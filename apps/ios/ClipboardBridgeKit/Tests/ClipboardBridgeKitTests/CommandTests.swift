// SPDX-License-Identifier: AGPL-3.0-only

@testable import ClipboardBridgeKit
import Foundation
import XCTest

/// Signed commands (docs/protocol.md, section 15) and the sync mode in the
/// hello.
final class CommandTests: XCTestCase {
    let now = Date()
    let pc = "00112233445566778899aabbccddeeff"

    func testModeCommand() throws {
        let root = SoftwareSigner()
        let ca = try GroupCertificates.groupCA(signer: root, now: now, pathLength: 1)
        let c = try Commands.mode(to: pc, mode: "own", group: GroupCertificates.tag(groupCA: ca),
                                  by: "0123456789abcdef0123456789abcdef", now: now, signer: root)
        let b = try JSONDecoder().decode(Commands.Body.self, from: c.body)
        XCTAssertEqual(b.type, "mode")
        XCTAssertEqual(b.to, pc)
        XCTAssertEqual(b.expires_ms - b.time_ms, Commands.lifetimeMS)
        XCTAssertEqual(Commands.id(of: c)?.count, 32)
        XCTAssertNil(c.chain)
        XCTAssertThrowsError(try Commands.mode(to: pc, mode: "everything", group: "tag", by: "by", now: now, signer: root))
    }

    /// A hub command carries the forwarder and the clients; a result
    /// carries the new hub's offer, which the old hub passes on.
    func testHubCommand() throws {
        let root = SoftwareSigner()
        let client = PhoneHub.Client(device: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", key: Data(repeating: 1, count: 32), psk: Data(repeating: 2, count: 32))
        let c = try Commands.hub(to: pc, forwarder: ("203.0.113.9:8764", "sha256:AAAA"), clients: [client], group: "tag", by: "by",
                                 now: now, signer: root)
        let b = try JSONDecoder().decode(Commands.Body.self, from: c.body)
        XCTAssertEqual(b.type, "hub")
        XCTAssertNil(b.mode)
        XCTAssertEqual(b.hub?.forwarder?.endpoint, "203.0.113.9:8764")
        XCTAssertEqual(b.hub?.clients, [client])
        XCTAssertThrowsError(try Commands.hub(to: pc, forwarder: nil, clients: [client], group: "tag", by: "by", now: now, signer: root))
        let m = try Member.decode(body: Data(
            #"{"t":"result","result":{"id":"ab","status":"done","tunnel":{"hub_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","endpoints":["203.0.113.9:8764"]}}}"#.utf8))
        guard case let .result(r) = m, let offer = r.tunnel else { return XCTFail("no result with an offer") }
        XCTAssertEqual(offer.endpoints, ["203.0.113.9:8764"])
        let hub = PhoneHub(publicKey: Data(repeating: 9, count: 32), clients: [client])
        let moved = try XCTUnwrap(hub.movedOffer(device: client.device, newHub: pc, offer: offer))
        XCTAssertEqual(moved.hub, pc)
        XCTAssertTrue(moved.moved)
        XCTAssertEqual(moved.psk, client.psk)
        XCTAssertNil(hub.movedOffer(device: pc, newHub: pc, offer: offer))
        XCTAssertEqual(try Member.decode(body: Data(Member.encode(.tunnel(moved)).dropFirst(4))), .tunnel(moved))
    }

    /// A command and its result through the frames, as Go sends and reads them.
    func testMessages() throws {
        let c = Member.Record(body: Data("{}".utf8), sig: Data([1, 2]), chain: [Data([3])])
        for m in [Member.Message.command(c), .result(Member.CommandResult(id: "ab", status: "refused", reason: "why"))] {
            XCTAssertEqual(try Member.decode(body: Data(Member.encode(m).dropFirst(4))), m)
        }
        let h = try Member.decode(body: Data(#"{"t":"hello","role":"full","hello":{"wall_ms":1,"mode":"receive"}}"#.utf8))
        guard case let .hello(_, hello) = h else { return XCTFail("not a hello") }
        XCTAssertEqual(hello.mode, "receive")
        let odd = try Member.decode(body: Data(#"{"t":"hello","role":"full","hello":{"wall_ms":1,"mode":"everything"}}"#.utf8))
        guard case let .hello(_, oddHello) = odd else { return XCTFail("not a hello") }
        XCTAssertNil(oddHello.mode)
    }

    /// A command goes to the named peer, and its result comes back; a phone
    /// refuses commands.
    func testCommandRoundTrip() async throws {
        let (da, db) = ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        let (pa, pb) = Pipe.pair()
        let a = MemberNode(engine: SyncEngine(device: da, clock: HybridClock()), name: "iPhone")
        let b = MemberNode(engine: SyncEngine(device: db, clock: HybridClock()), name: "Phone two")
        let ta = Task { try await a.serve(pa, peer: db) }
        let tb = Task { try await b.serve(pb, peer: da) }
        for _ in 0..<300 {
            if await a.peers == 1 { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        let c = try Commands.mode(to: db, mode: "own", group: "tag", by: da, now: now, signer: SoftwareSigner())
        let r = try await a.command(c, to: db)
        XCTAssertEqual(r.id, Commands.id(of: c))
        XCTAssertEqual(r.status, "refused")
        do {
            _ = try await a.command(c, to: "cccccccccccccccccccccccccccccccc")
            XCTFail("sent to a device that is not connected")
        } catch MemberNode.Failure.notConnected {}
        await a.closeAll()
        try await ta.value
        try await tb.value
    }

    /// Writes mode commands this kit signed, with the root key and with an
    /// admin CA's, for internal/group's TestSwiftCommand, when
    /// CBB_INTEROP_OUT names a directory.
    func testCommandsForGo() throws {
        guard let dir = ProcessInfo.processInfo.environment["CBB_INTEROP_OUT"] else { return }
        let root = SoftwareSigner(), admin = SoftwareSigner()
        let ca = try GroupCertificates.groupCA(signer: root, now: now, pathLength: 1)
        let tag = GroupCertificates.tag(groupCA: ca)
        let adminCA = try GroupCertificates.adminCA(device: "fedcba9876543210fedcba9876543210", publicKey: admin.publicKeyDER,
                                                    root: ca, rootSigner: root)
        let by = "0123456789abcdef0123456789abcdef"
        struct Out: Encodable {
            var group_ca: Data
            var to: String
            var commands: [Member.Record]
        }
        let out = Out(group_ca: ca, to: pc, commands: [
            try Commands.mode(to: pc, mode: "receive", group: tag, by: by, now: now, signer: root),
            try Commands.mode(to: pc, mode: "receive", group: tag, by: by, now: now, signer: admin, adminCA: adminCA),
            try Commands.hub(to: pc, forwarder: ("203.0.113.9:8764", "sha256:AAAA"),
                             clients: [PhoneHub.Client(device: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", key: Data(repeating: 1, count: 32),
                                                       psk: Data(repeating: 2, count: 32))],
                             group: tag, by: by, now: now, signer: root),
        ])
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        try (enc.encode(out) + Data("\n".utf8)).write(to: URL(fileURLWithPath: dir).appendingPathComponent("swift-command.json"))
    }
}
