// SPDX-License-Identifier: AGPL-3.0-only

@testable import ClipboardBridgeKit
import Foundation
import XCTest

/// testdata/interop/strict.json, from the Go tests: the kit takes exactly
/// the record bodies, commands and manifests the Go member does.
final class StrictTests: XCTestCase {
    struct Vectors: Decodable {
        struct Case: Decodable {
            var name: String
            var body: Data
            var valid: Bool
        }

        var records, commands, manifests: [Case]
    }

    func vectors() throws -> Vectors {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        let v = try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/strict.json")))
        XCTAssertFalse(v.records.isEmpty || v.commands.isEmpty || v.manifests.isEmpty)
        return v
    }

    func testRecords() throws {
        for c in try vectors().records {
            XCTAssertEqual(Records.Body.decode(c.body) != nil, c.valid, "record \(c.name)")
        }
    }

    func testCommands() throws {
        for c in try vectors().commands {
            XCTAssertEqual((try? Commands.parse(c.body)) != nil, c.valid, "command \(c.name)")
        }
    }

    func testManifests() throws {
        for c in try vectors().manifests {
            // The frames' decoder, Member.decode, runs the same scan first.
            let m = Strict.integersOnly(c.body) ? try? JSONDecoder().decode(Media.Manifest.self, from: c.body) : nil
            XCTAssertEqual(m?.isValid ?? false, c.valid, "manifest \(c.name)")
        }
    }
}
