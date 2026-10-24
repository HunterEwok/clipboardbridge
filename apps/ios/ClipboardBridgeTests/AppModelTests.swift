// SPDX-License-Identifier: AGPL-3.0-only

@testable import ClipboardBridge
import ClipboardBridgeKit
import SwiftUI
import XCTest

@MainActor
final class AppModelTests: XCTestCase {
    let qr = "clipboardbridge://join?code=246802&addr=192.168.1.20:8767&fp=qFnj7UvLCE_WNnna2IEmMaLbkA6tHcKf0VijTRzekKA"

    func testRead() {
        guard case let .joinCode(jc) = AppModel.read(scanned: qr) else { return XCTFail() }
        XCTAssertEqual(jc.code, "246802")
        XCTAssertEqual(jc.addrs, ["192.168.1.20:8767"])
        for text in ["", "https://example.com", "clipboardbridge://join?code=246802", "clipboardbridge://join?code=12&addr=a:1&fp=x"] {
            XCTAssertEqual(AppModel.read(scanned: text), .notClipboardBridge, text)
        }
    }

    /// The text cbb pair prints under its QR code, as Go's
    /// phone.JoinQR writes it (percent-encoded, an IPv6 address too), reads
    /// as pasted from a terminal, spaces and newline included.
    func testReadGoJoinText() {
        let text = "clipboardbridge://join?code=246802&addr=192.168.1.20%3A8767&addr=%5Bfd00%3A%3A5%5D%3A8767&fp=qFnj7UvLCE_WNnna2IEmMaLbkA6tHcKf0VijTRzekKA"
        for pasted in [text, " " + text + "\n"] {
            guard case let .joinCode(jc) = AppModel.read(scanned: pasted) else { return XCTFail(pasted) }
            XCTAssertEqual(jc.code, "246802")
            XCTAssertEqual(jc.addrs, ["192.168.1.20:8767", "[fd00::5]:8767"])
            XCTAssertEqual(jc.fingerprint, "qFnj7UvLCE_WNnna2IEmMaLbkA6tHcKf0VijTRzekKA")
        }
    }

    func testTheMoreTellingFailure() {
        let handshake = TLSTransport.Failure.notReady("handshake failed")
        func isHandshake(_ e: Error) -> Bool {
            if case TLSTransport.Failure.notReady("handshake failed") = e { return true }
            return false
        }
        XCTAssertTrue(isHandshake(LiveGroup.telling(nil, handshake)))
        XCTAssertTrue(isHandshake(LiveGroup.telling(handshake, TLSTransport.Failure.timedOut)), "a later timeout hides nothing")
        XCTAssertTrue(isHandshake(LiveGroup.telling(TLSTransport.Failure.timedOut, handshake)), "an address that answered says more")
    }

    func testSyncFromShortcut() async {
        let g = FakeGroup()
        g.hasGroup = true
        g.computers = [.init(id: "a", name: "pi", online: true)]
        let m = AppModel(group: g, defaults: freshDefaults())
        let said = await m.syncFromShortcut(wait: .seconds(1))
        XCTAssertEqual(said, String(localized: "Sent to the computers.", bundle: .app))
    }

    func testSyncFromShortcutWithoutAGroupDoesNotWait() async {
        let m = AppModel(group: PendingGroup(), defaults: freshDefaults())
        let started = ContinuousClock.now
        let said = await m.syncFromShortcut(wait: .seconds(5))
        XCTAssertFalse(said.isEmpty)
        XCTAssertLessThan(ContinuousClock.now - started, .seconds(2))
    }

    func testIPv4AddressesFirst() {
        XCTAssertEqual(LiveGroup.ordered(["[fd00::5]:8767", "192.168.1.20:8767", "[fe80::1]:8767", "10.0.0.2:8767"]),
                       ["192.168.1.20:8767", "10.0.0.2:8767", "[fd00::5]:8767", "[fe80::1]:8767"])
    }

    /// A group that admits and syncs as told.
    @MainActor
    final class FakeGroup: GroupController {
        var hasGroup = false
        var isAdmin = true
        var prepared = 0
        func prepare() throws { prepared += 1 }
        var joinCode = JoinCode(code: "135790", addrs: ["192.168.1.30:50000"], fingerprint: "fp")
        var shown: [JoinCode] = []
        func join(show: @escaping @MainActor (JoinCode) -> Void) async throws {
            show(joinCode)
            shown.append(joinCode)
            hasGroup = true
            isAdmin = false
        }
        var computers: [AppModel.Computer] = []
        var admitted: [JoinCode] = []
        func admit(_ code: JoinCode) async throws {
            admitted.append(code)
            hasGroup = true
            computers = [.init(id: "a", name: "pi", online: true)]
        }
        func sync() async throws -> AppModel.SyncResult { .sent }
        func refresh() async {}
        var devices: [AppModel.Computer] { computers + [.init(id: "me", name: "iPhone", online: true, role: "phone", isSelf: true)] }
        func remove(_ id: String) async throws { computers.removeAll { $0.id == id } }
        func makeAdmin(_ id: String) async throws {
            guard let i = computers.firstIndex(where: { $0.id == id && $0.canMakeAdmin }) else { throw PhoneGroup.Failure.notRoot }
            (computers[i].admin, computers[i].canMakeAdmin) = (true, false)
        }
    }

    func testMakeAdmin() async {
        let g = FakeGroup()
        g.computers = [.init(id: "a", name: "pi", online: true, canMakeAdmin: true), .init(id: "b", name: "deck", online: true)]
        let m = AppModel(group: g)
        await m.makeAdmin("a")
        XCTAssertEqual(m.devices.first { $0.id == "a" }?.admin, true)
        XCTAssertEqual(m.devices.first { $0.id == "a" }?.canMakeAdmin, false)
        XCTAssertNotNil(m.message)
        m.message = nil
        await m.makeAdmin("b")
        XCTAssertEqual(m.devices.first { $0.id == "b" }?.admin, false)
        XCTAssertNotNil(m.message)
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
        XCTAssertEqual(m.devices.count, 2)
        await m.remove("a")
        XCTAssertEqual(m.devices.map(\.id), ["me"])
        XCTAssertTrue(m.computers.isEmpty)
    }

    func testJoin() async {
        let g = FakeGroup()
        let m = AppModel(group: g)
        m.startJoining()
        XCTAssertEqual(m.phase, .joining)
        await m.join()
        XCTAssertEqual(g.shown, [g.joinCode])
        XCTAssertEqual(m.phase, .home)
        XCTAssertNil(m.joinCode)
        XCTAssertFalse(m.isAdmin)

        let pending = AppModel()
        pending.startJoining()
        await pending.join()
        XCTAssertEqual(pending.phase, .joining, "the screen stays, with the error")
        XCTAssertNotNil(pending.message)
        pending.cancelJoin()
        XCTAssertEqual(pending.phase, .start)
        XCTAssertNil(pending.message)
    }

    func testJoinQRText() {
        let jc = JoinCode(code: "246802", addrs: ["192.168.1.20:8767", JoinCode.address(host: "fd00::5", port: 8767)], fingerprint: "abc_-")
        XCTAssertEqual(JoinCode(qr: jc.qrText), jc)
        XCTAssertEqual(AppModel.read(scanned: jc.qrText), .joinCode(jc))
        XCTAssertTrue(JoinCode(code: JoinCode.newCode(), addrs: [], fingerprint: "").codeIsValid)
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
        XCTAssertNotEqual(AppModel.describe(PairingMember.Failure.refused(.wrongCode), details: false),
                          AppModel.describe(PairingMember.Failure.refused(.busy), details: false))
        XCTAssertEqual(AppModel.describe(LiveGroup.Failure.unreachable, details: false), AppModel.describe(TLSTransport.Failure.closed, details: false))
        XCTAssertTrue(AppModel.describe(TLSTransport.Failure.closed, details: true).contains("closed"))
    }

    func testThemes() {
        XCTAssertEqual(ThemeChoice.system.palette(for: .dark), Tokens.terminal)
        XCTAssertEqual(ThemeChoice.system.palette(for: .light), Tokens.light)
        XCTAssertEqual(ThemeChoice.amber.palette(for: .light), Tokens.amber)
        XCTAssertEqual(Set(ThemeChoice.allCases.map { $0.palette(for: .dark).dark }), [true, false])
    }

    /// A fresh defaults domain per test, removed after it.
    private func freshDefaults() -> UserDefaults {
        let name = "clipboardbridge-tests-\(UUID().uuidString)"
        addTeardownBlock { UserDefaults().removePersistentDomain(forName: name) }
        return UserDefaults(suiteName: name)!
    }

    func testWelcomeOnce() {
        let defaults = freshDefaults()
        let g = FakeGroup()
        let m = AppModel(group: g, defaults: defaults)
        m.prepare()
        XCTAssertTrue(m.welcome)
        XCTAssertEqual(g.prepared, 1)
        m.dismissWelcome()
        XCTAssertFalse(m.welcome)
        let again = AppModel(group: g, defaults: defaults)
        again.prepare()
        XCTAssertFalse(again.welcome, "the note shows only at the first launch")
        XCTAssertEqual(g.prepared, 1)
    }

    func testNoWelcomeWithAGroup() {
        let g = FakeGroup()
        g.hasGroup = true
        let m = AppModel(group: g, defaults: freshDefaults())
        m.prepare()
        XCTAssertFalse(m.welcome)
        XCTAssertEqual(g.prepared, 0)
    }

    func testJoiningEndsTheWelcome() {
        let defaults = freshDefaults()
        let m = AppModel(group: FakeGroup(), defaults: defaults)
        m.prepare()
        m.startJoining()
        XCTAssertFalse(m.welcome)
        XCTAssertTrue(defaults.bool(forKey: AppModel.welcomedKey))
    }

    func testLanguageOfferedOnStart() {
        let ours = ["Base", "en", "ru"]
        XCTAssertFalse(LanguageChoice.offeredOnStart(preferred: ["en-GB", "de"], localizations: ours))
        XCTAssertFalse(LanguageChoice.offeredOnStart(preferred: ["ru-RU"], localizations: ours))
        XCTAssertTrue(LanguageChoice.offeredOnStart(preferred: ["de-DE", "en"], localizations: ours),
                      "German is not translated, so the app shows English and offers the choice")
        XCTAssertTrue(LanguageChoice.offeredOnStart(preferred: ["pt_BR"], localizations: ours))
        XCTAssertFalse(LanguageChoice.offeredOnStart(preferred: [], localizations: ours))
    }

    func testLanguageChoice() {
        let defaults = freshDefaults()
        XCTAssertEqual(LanguageChoice.current(defaults), .system)
        defaults.set("ru", forKey: LanguageChoice.key)
        XCTAssertEqual(LanguageChoice.current(defaults), .ru)
        defaults.set("xx", forKey: LanguageChoice.key)
        XCTAssertEqual(LanguageChoice.current(defaults), .system)
        XCTAssertNil(LanguageChoice.system.locale)
        XCTAssertEqual(LanguageChoice.ru.locale?.identifier, "ru")
        XCTAssertEqual(String(localized: "Theme", bundle: LanguageChoice.ru.bundle), "\u{0422}\u{0435}\u{043C}\u{0430}")
        XCTAssertEqual(String(localized: "Theme", bundle: LanguageChoice.en.bundle), "Theme")
    }
}
