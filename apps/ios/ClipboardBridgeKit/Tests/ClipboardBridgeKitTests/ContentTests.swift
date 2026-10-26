// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import ClipboardBridgeKit
import Foundation
import XCTest

/// Checks the content of images and files against Go's vectors (go test
/// ./internal/node -update) and between two nodes.
final class ContentTests: XCTestCase {
    struct Vectors: Decodable {
        struct Chunk: Decodable {
            var sha256: Data
            var offset: Int64
            var data: Data?
            var frame: Data
            var frame_len: Int
        }
        var frames: [MemberTests.AnyJSON]
        var chunks: [Chunk]
    }

    func vectors() throws -> Vectors {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/content.json")))
    }

    func testGoFrames() throws {
        var decoded: [Member.Message] = []
        for goFrame in try vectors().frames {
            let m = try Member.decode(body: goFrame.data)
            decoded.append(m)
            let encoded = try Member.encode(m)
            let mine = try JSONSerialization.jsonObject(with: encoded.dropFirst(4)) as! NSDictionary
            XCTAssertEqual(mine, goFrame.value as! NSDictionary)
        }
        let sum = Data(repeating: 7, count: 32)
        XCTAssertEqual(decoded, [
            .get(Member.Get(sha256: sum, offset: 0, length: Member.getWindow)),
            .get(Member.Get(sha256: sum, offset: 3 << 20, length: 12345)),
            .missing(Member.Get(sha256: sum, offset: 0, length: Member.getWindow)),
            .get(Member.Get(sha256: sum, offset: 0, length: 0)),
        ])
    }

    func testGoChunks() throws {
        for c in try vectors().chunks {
            let frame = c.frame + Data(count: c.frame_len - c.frame.count)
            let chunk = Member.Chunk(sha256: c.sha256, offset: c.offset, data: c.data ?? Data())
            XCTAssertEqual(try Member.encode(.chunk(chunk)), frame)
            let (n, binary) = try Member.header(frame.prefix(4))
            XCTAssertTrue(binary)
            XCTAssertEqual(n, frame.count - 4)
            XCTAssertEqual(try Member.decodeChunk(body: frame.dropFirst(4)), chunk)
        }
    }

    func testFrameLimits() throws {
        XCTAssertThrowsError(try Member.header(Data([0x80, 0x04, 0x40, 0x01])))
        XCTAssertEqual(try Member.header(Data([0x80, 0x04, 0x40, 0x00])).length, Member.maxChunkFrame)
        XCTAssertEqual(Member.maxChunkFrame, 278_528)
        XCTAssertThrowsError(try Member.decodeChunk(body: Data(count: 10)))
        var lying = try Member.encode(.chunk(Member.Chunk(sha256: Data(count: 32), offset: 0, data: Data(count: 3))))
            .subdata(in: 4..<(4 + Member.chunkHead + 3))
        lying[Member.chunkHead - 1] = 9
        XCTAssertThrowsError(try Member.decodeChunk(body: lying))
        XCTAssertThrowsError(try Member.encode(.chunk(Member.Chunk(sha256: Data(count: 32), offset: 0, data: Data(count: Member.chunkSize + 1)))))
    }

    func testNodesFetch() async throws {
        let store = MemoryContent()
        let events = Events()
        let idA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", idB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        let a = MemberNode(engine: SyncEngine(device: idA, clock: HybridClock()), name: "iPhone", content: store)
        let b = MemberNode(engine: SyncEngine(device: idB, clock: HybridClock()), name: "pi", role: .full,
                           onChange: { events.add($0) })
        let (pa, pb) = Pipe.pair()
        let ta = Task { try await a.serve(pa, peer: idB) }
        let tb = Task { try await b.serve(pb, peer: idA) }
        try await waitUntil {
            let (x, y) = (await a.peers, await b.peers)
            return x == 1 && y == 1
        }
        let bMedia = await b.mediaPeers, aMedia = await a.mediaPeers
        XCTAssertEqual(bMedia, [idA])
        XCTAssertEqual(aMedia, []) // b serves nothing

        // A picture of 5 MiB and a bit, more than the fetch asks for ahead.
        var rng = SystemRandomNumberGenerator()
        let png = Data((0..<(5 << 20 + 1234)).map { _ in UInt8.random(in: 0...255, using: &rng) })
        let e = await a.send(text: "", kind: .text, media: Content.manifest(store: store, data: [("image/png", png)]))
        XCTAssertEqual(e.kind, .media)
        try await waitUntil { events.all.contains { $0.id == e.id } }
        let got = events.all.first { $0.id == e.id }!
        let part = got.media!.parts[0]
        // Events keep flowing while the content does.
        let fetch = Task { try await Content.data(from: b, event: got, part: part) }
        await b.send(text: "meanwhile", kind: .text)
        try await waitUntil { await a.usable?.text == "meanwhile" }
        let fetched = try await fetch.value
        XCTAssertEqual(fetched, png)

        // A part the phone does not hold is missing; one over the limit is not fetched.
        do {
            try await b.fetch(from: idA, sha256: Data(repeating: 1, count: 32), size: 10) { _, _ in }
            XCTFail("fetched a part nobody has")
        } catch MemberNode.Failure.missing {}
        do {
            _ = try await Content.data(from: b, event: got, part: part, limit: 1 << 20)
            XCTFail("fetched a part over the limit")
        } catch Content.Failure.tooLarge {}
        // b serves nothing.
        do {
            try await a.fetch(from: idB, sha256: part.sha256!, size: part.size) { _, _ in }
            XCTFail("fetched from a member that serves nothing")
        } catch MemberNode.Failure.refused {}

        // A cancelled fetch cancels with the peer, and the next one gets it all.
        let slow = Task { try await b.fetch(from: idA, sha256: part.sha256!, size: part.size) { _, _ in Thread.sleep(forTimeInterval: 0.05) } }
        try await Task.sleep(nanoseconds: 100_000_000)
        slow.cancel()
        _ = await slow.result
        let again = try await Content.data(from: b, event: got, part: part)
        XCTAssertEqual(again, png)

        // A sink that fails ends the fetch with its error.
        struct Full: Error {}
        do {
            try await b.fetch(from: idA, sha256: part.sha256!, size: part.size) { _, _ in throw Full() }
            XCTFail("a failing sink did not end the fetch")
        } catch is Full {}
        let last = try await Content.data(from: b, event: got, part: part)
        XCTAssertEqual(last, png)

        await a.closeAll()
        try await ta.value
        try await tb.value
    }

    func testTooManyGets() async throws {
        // A store that reads slowly, so the gets wait.
        struct Slow: ContentStore {
            struct Source: ContentSource {
                var size: Int64 { 1 << 20 }
                func read(offset: Int64, length: Int) throws -> Data {
                    Thread.sleep(forTimeInterval: 2)
                    return Data(count: length)
                }
            }
            func open(sha256: Data) -> ContentSource? { Source() }
        }
        let sum = Data(repeating: 3, count: 32)
        let a = MemberNode(engine: SyncEngine(device: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", clock: HybridClock()), name: "iPhone", content: Slow())
        let (pa, pb) = Pipe.pair()
        let ta = Task { try await a.serve(pa) }
        // A peer that asks for more than 64 ranges at once is closed.
        try? await pb.write(Member.encode(.hello(.full, Member.Hello(wallMS: 0))))
        for i in 0..<80 { try? await pb.write(Member.encode(.get(Member.Get(sha256: sum, offset: Int64(i) * 1000, length: 1000)))) }
        do {
            try await ta.value
            XCTFail("the connection did not end with an error")
        } catch MemberNode.Failure.refused {}
    }

    func testMemoryContentKeepsTheNewest() {
        let store = MemoryContent(maxBytes: 10)
        let one = store.put(Data(repeating: 1, count: 6))
        let two = store.put(Data(repeating: 2, count: 6))
        XCTAssertNil(store.open(sha256: one))
        XCTAssertEqual(store.open(sha256: two)?.size, 6)
        // One part over the limit is still kept, alone.
        let big = store.put(Data(count: 20))
        XCTAssertNil(store.open(sha256: two))
        XCTAssertEqual(store.open(sha256: big)?.size, 20)
    }

    func waitUntil(_ cond: @escaping () async -> Bool) async throws {
        for _ in 0..<500 {
            if await cond() { return }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("timed out")
    }
}

final class Events: @unchecked Sendable {
    private let lock = NSLock()
    private var events: [Member.Event] = []
    func add(_ e: Member.Event) { lock.withLock { events.append(e) } }
    var all: [Member.Event] { lock.withLock { events } }
}
