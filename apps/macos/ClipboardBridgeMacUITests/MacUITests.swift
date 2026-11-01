// SPDX-License-Identifier: AGPL-3.0-only

import XCTest

/// The Mac app's window driven as a person would (docs/testbench-catalogue.md,
/// A4, A9, U12), with its control socket pointed where no service answers
/// (CBB_SOCKET): the stopped service explained in one line, the error
/// underneath only with error details on, the Settings window's switch, and
/// Russian. A running service and the admin prompts are the bench's.
final class MacUITests: XCTestCase {
    static let plain = "The Clipboard Bridge service is not running on this Mac. Install it, or start it with sudo launchctl kickstart system/io.github.hunterewok.clipboardbridge."

    override func setUp() {
        continueAfterFailure = false
    }

    private func launch(_ extra: [String] = [], language: String = "en") -> XCUIApplication {
        let app = XCUIApplication()
        app.launchEnvironment["CBB_SOCKET"] = NSTemporaryDirectory() + "cbb-ui-no-service.sock"
        app.launchArguments = ["-AppleLanguages", "(\(language))"] + extra
        app.launch()
        return app
    }

    /// A4, U12: with details off the window says only what to do; with them
    /// on, the error underneath follows after a blank line.
    func testStoppedService() {
        var app = launch(["-ShowErrorDetails", "NO"])
        XCTAssertTrue(app.staticTexts["The service does not answer"].waitForExistence(timeout: 30))
        XCTAssertTrue(app.staticTexts[Self.plain].waitForExistence(timeout: 10), "with details off the notice is not the plain message")
        app.terminate()

        app = launch(["-ShowErrorDetails", "YES"])
        let detailed = app.staticTexts.matching(NSPredicate(format: "value BEGINSWITH %@ OR label BEGINSWITH %@", Self.plain + "\n\n", Self.plain + "\n\n")).firstMatch
        XCTAssertTrue(detailed.waitForExistence(timeout: 30), "with details on the notice has no error underneath")
        XCTAssertFalse(app.staticTexts[Self.plain].exists, "with details on the plain message shows alone")
        app.terminate()
    }

    /// U12: the Settings window's switch shows the setting the app runs with.
    func testSettingsSwitch() {
        for (arg, want) in [("NO", false), ("YES", true)] {
            let app = launch(["-ShowErrorDetails", arg])
            XCTAssertTrue(app.staticTexts["The service does not answer"].waitForExistence(timeout: 30))
            app.typeKey(",", modifierFlags: .command)
            let toggle = app.checkBoxes["Show error details"].exists ? app.checkBoxes["Show error details"] : app.switches["Show error details"]
            XCTAssertTrue(toggle.waitForExistence(timeout: 10), "Settings has no error details switch")
            let on = (toggle.value as? Int ?? Int(toggle.value as? String ?? "") ?? -1) == 1
            XCTAssertEqual(on, want, "ShowErrorDetails \(arg) gives the switch \(String(describing: toggle.value))")
            app.terminate()
        }
    }

    /// A9: in Russian the notice is Russian.
    func testRussian() {
        let app = launch(language: "ru")
        XCTAssertTrue(app.staticTexts[ru("The service does not answer")].waitForExistence(timeout: 30))
        app.terminate()
    }

    /// The app's Russian text for an English one, from its string catalog,
    /// which this target compiles too; a missing translation fails.
    private func ru(_ english: String, file: StaticString = #filePath, line: UInt = #line) -> String {
        guard let path = Bundle(for: Self.self).path(forResource: "ru", ofType: "lproj"), let bundle = Bundle(path: path) else {
            XCTFail("the test bundle has no Russian strings", file: file, line: line)
            return english
        }
        let text = bundle.localizedString(forKey: english, value: nil, table: "Localizable")
        if text == english { XCTFail("no Russian for \(english)", file: file, line: line) }
        return text
    }
}
