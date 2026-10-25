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
        ])
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        try (enc.encode(out) + Data("\n".utf8)).write(to: URL(fileURLWithPath: dir).appendingPathComponent("swift-command.json"))
    }
}
