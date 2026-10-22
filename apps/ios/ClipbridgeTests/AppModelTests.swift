// SPDX-License-Identifier: AGPL-3.0-only

@testable import Clipbridge
import ClipbridgeKit
import SwiftUI
import XCTest

@MainActor
final class AppModelTests: XCTestCase {
    let qr = "clipbridge://join?code=246802&addr=192.168.1.20:8767&fp=qFnj7UvLCE_WNnna2IEmMaLbkA6tHcKf0VijTRzekKA"

    func testRead() {
        guard case let .joinCode(jc) = AppModel.read(scanned: qr) else { return XCTFail() }
        XCTAssertEqual(jc.code, "246802")
        XCTAssertEqual(jc.addrs, ["192.168.1.20:8767"])
        for text in ["", "https://example.com", "clipbridge://join?code=246802", "clipbridge://join?code=12&addr=a:1&fp=x"] {
            XCTAssertEqual(AppModel.read(scanned: text), .notClipbridge, text)
        }
    }

    /// A group that admits and syncs as told.
    @MainActor
    final class FakeGroup: GroupController {
        var hasGroup = false
        var computers: [AppModel.Computer] = []
        var admitted: [JoinCode] = []
        func admit(_ code: JoinCode) async throws {
            admitted.append(code)
            hasGroup = true
            computers = [.init(id: "a", name: "pi", online: true)]
        }
        func sync() async throws -> AppModel.SyncResult { .sent }
        func refresh() async {}
    }

    func testScanGoesHome() async {
        let g = FakeGroup()
        let m = AppModel(group: g)
        XCTAssertEqual(m.phase, .start)
        let bad = await m.scanned("not a code")
        XCTAssertFalse(bad)
        XCTAssertNotNil(m.message)
        let ok = await m.scanned(qr)
        XCTAssertTrue(ok)
        XCTAssertEqual(m.phase, .home)
        XCTAssertEqual(m.computers.map(\.name), ["pi"])
        XCTAssertNil(m.message)
        await m.sync()
        XCTAssertNotNil(m.message)
    }

    func testPendingGroup() async {
        let m = AppModel()
        XCTAssertEqual(m.phase, .start)
        let ok = await m.scanned(qr)
        XCTAssertFalse(ok)
        XCTAssertEqual(m.message, AppModel.describe(PendingGroup.Failure.notReady))
    }

    func testSplit() {
        XCTAssertEqual(LiveGroup.split("192.168.1.20:8767")?.0, "192.168.1.20")
        XCTAssertEqual(LiveGroup.split("192.168.1.20:8767")?.1, 8767)
        XCTAssertEqual(LiveGroup.split("[fd00::5]:8767")?.0, "fd00::5")
        XCTAssertNil(LiveGroup.split("host"))
        XCTAssertNil(LiveGroup.split(":80"))
    }

    func testDescribe() {
        XCTAssertNotEqual(AppModel.describe(PairingMember.Failure.refused(.wrongCode)), AppModel.describe(PairingMember.Failure.refused(.busy)))
        XCTAssertEqual(AppModel.describe(LiveGroup.Failure.unreachable), AppModel.describe(TLSTransport.Failure.closed))
    }

    func testThemes() {
        XCTAssertEqual(ThemeChoice.system.palette(for: .dark), Tokens.terminal)
        XCTAssertEqual(ThemeChoice.system.palette(for: .light), Tokens.light)
        XCTAssertEqual(ThemeChoice.amber.palette(for: .light), Tokens.amber)
        XCTAssertEqual(Set(ThemeChoice.allCases.map { $0.palette(for: .dark).dark }), [true, false])
    }
}
