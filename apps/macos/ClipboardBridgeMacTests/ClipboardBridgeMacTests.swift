// SPDX-License-Identifier: AGPL-3.0-only

import XCTest
@testable import CBB

final class ClipboardBridgeMacTests: XCTestCase {
    /// A message goes out as the Go service reads it: a JSON line with the
    /// payload's length, then the payload.
    func testEncode() throws {
        let data = try Control.encode(.init(op: "copy"), payload: Data("hi".utf8))
        let text = String(decoding: data, as: UTF8.self)
        XCTAssertEqual(text, "{\"len\":2,\"op\":\"copy\"}\nhi")
    }

    /// An answer is read only once all of it has come, and its devices
    /// keep what the service leaves out as false.
    func testDecode() throws {
        let line = #"{"op":"reply","len":3,"devices":[{"id":"ab12","name":"deck","role":"full","os":"linux","online":true,"self":true,"os_version":"Ubuntu 24.04","last_seen_ms":5},{"id":"cd34"}]}"#
        let whole = Data((line + "\nxyz").utf8)
        XCTAssertNil(try Control.decode(whole.prefix(10)))
        XCTAssertNil(try Control.decode(whole.dropLast()))
        let (header, body, used) = try XCTUnwrap(try Control.decode(whole + Data("more".utf8)))
        XCTAssertEqual(body, Data("xyz".utf8))
        XCTAssertEqual(used, whole.count)
        let devices = try XCTUnwrap(header.devices)
        XCTAssertEqual(devices[0].osVersion, "Ubuntu 24.04")
        XCTAssertTrue(devices[0].online && devices[0].isSelf)
        XCTAssertEqual(devices[0].lastSeenMS, 5)
        XCTAssertEqual(devices[1].name, "cd34")
        XCTAssertFalse(devices[1].admin || devices[1].online)
        XCTAssertEqual(devices[1].kind, .desktop)
        XCTAssertEqual(devices[0].systemWithVersion, "Ubuntu 24.04")
    }

    func testBadHeader() {
        XCTAssertThrowsError(try Control.decode(Data("not json\n".utf8)))
        XCTAssertThrowsError(try Control.decode(Data(repeating: 0x41, count: Control.maxHeader + 1)))
    }

    /// Every argument reaches cbb as one word, whatever a name holds.
    func testShellCommand() {
        let line = Admin.shellCommand("/usr/local/bin/cbb", ["rename", "ab12", "Bob's \"Mac\" $(x)"], answer: false, details: true)
        XCTAssertEqual(line, #"CBB_DEBUG=1 '/usr/local/bin/cbb' 'rename' 'ab12' 'Bob'\''s "Mac" $(x)'"#)
        XCTAssertEqual(Admin.shellCommand("/usr/local/bin/cbb", ["global", "on"], answer: true, details: false), "echo yes | '/usr/local/bin/cbb' 'global' 'on'")
        XCTAssertEqual(Admin.appleScript(shell: #"a "b" \c"#), #"do shell script "a \"b\" \\c" with administrator privileges"#)
    }

    func testAdminFailure() {
        XCTAssertEqual(Admin.failure("0:80: execution error: User canceled. (-128)"), .cancelled)
        XCTAssertEqual(
            Admin.failure("0:120: execution error: cbb: no device named nope in the group (1)"),
            .failed("no device named nope in the group", detail: "0:120: execution error: cbb: no device named nope in the group (1)")
        )
    }

    func testKind() {
        var phone = Control.Device(id: "1", name: "phone", role: "phone", os: "ios")
        XCTAssertEqual(phone.kind, .phone)
        phone.form = "tablet"
        XCTAssertEqual(phone.kind, .tablet)
        XCTAssertEqual(Control.Device(id: "2", name: "mac", os: "macos").kind, .laptop)
        XCTAssertEqual(Control.Device(id: "3", name: "pi", role: "lite").kind, .board)
    }

    func testOrbitSpots() {
        let spots = OrbitView.spots(count: 8, radii: [10, 20], center: .zero)
        XCTAssertEqual(spots.count, 8)
        XCTAssertEqual(spots[0].x, 0, accuracy: 1e-9)
        XCTAssertEqual(spots[0].y, -10, accuracy: 1e-9)
    }
}
