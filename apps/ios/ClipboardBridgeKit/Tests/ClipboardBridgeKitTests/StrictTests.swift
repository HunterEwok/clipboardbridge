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

    /// testdata/interop/strict-generated.json, from the tables of
    /// docs/protocol.md: the kit takes exactly the bodies the tables take,
    /// and says which row it reads otherwise.
    func testGenerated() throws {
        struct Case: Decodable {
            var name, rule: String
            var valid: Bool
            var body: Data
            var pad_at, pad: Int?

            var full: Data {
                guard let pad, let pad_at else { return body }
                return body.prefix(pad_at) + Data(repeating: UInt8(ascii: "a"), count: pad) + body.dropFirst(pad_at)
            }
        }
        struct Vectors: Decodable { var records, commands, manifests: [Case] }
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        let v = try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/strict-generated.json")))
        var wrong: [String] = []
        let kinds: [(String, [Case], (Data) -> Bool)] = [
            ("records", v.records, { (b: Data) in Records.Body.decode(b) != nil }),
            ("commands", v.commands, { (b: Data) in (try? Commands.parse(b)) != nil }),
            ("manifests", v.manifests, { (b: Data) in
                (Strict.integersOnly(b) ? try? JSONDecoder().decode(Media.Manifest.self, from: b) : nil)?.isValid ?? false
            }),
        ]
        for (kind, cases, take) in kinds {
            XCTAssertFalse(cases.isEmpty, "no \(kind)")
            for c in cases where take(c.full) != c.valid {
                wrong.append("\(kind) \(c.name) (\(c.rule)): valid \(c.valid)")
            }
        }
        XCTAssert(wrong.isEmpty, "\(wrong.count) vectors read otherwise:\n" + wrong.joined(separator: "\n"))
    }

    /// testdata/interop/strict-mutants-*.json: valid bodies changed byte by
    /// byte, each with the verdict of the tables of docs/protocol.md.
    func testMutants() throws {
        struct Case: Decodable {
            var name, rule: String
            var valid: Bool
            var body: Data
            var pad_at, pad: Int?

            var full: Data {
                guard let pad, let pad_at else { return body }
                return body.prefix(pad_at) + Data(repeating: UInt8(ascii: "a"), count: pad) + body.dropFirst(pad_at)
            }
        }
        struct Vectors: Decodable { var records, commands: [Case]? }
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        var wrong: [String] = []
        var n = 0
        for i in 1... {
            let file = url.appendingPathComponent("testdata/interop/strict-mutants-\(i).json")
            guard FileManager.default.fileExists(atPath: file.path) else { break }
            let v = try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: file))
            for c in v.records ?? [] {
                n += 1
                if (Records.Body.decode(c.full) != nil) != c.valid { wrong.append("records \(c.name) (\(c.rule)): valid \(c.valid)") }
            }
            for c in v.commands ?? [] {
                n += 1
                if ((try? Commands.parse(c.full)) != nil) != c.valid { wrong.append("commands \(c.name) (\(c.rule)): valid \(c.valid)") }
            }
        }
        XCTAssert(n > 0, "no mutant vectors")
        XCTAssert(wrong.isEmpty, "\(wrong.count) vectors read otherwise:\n" + wrong.joined(separator: "\n"))
    }

    /// strict-files.json: the server credentials and release files, as Go's
    /// TestStrictGeneratedFiles writes them.
    func testGeneratedFiles() throws {
        struct Case: Decodable {
            var name, rule, kind: String
            var valid: Bool
            var body: Data
            var pad_at, pad: Int?

            var full: Data {
                guard let pad, let pad_at else { return body }
                return body.prefix(pad_at) + Data(repeating: UInt8(ascii: "a"), count: pad) + body.dropFirst(pad_at)
            }
        }
        struct Vectors: Decodable { var credentials, releases: [Case] }
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        let v = try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/strict-files.json")))
        XCTAssertFalse(v.credentials.isEmpty)
        XCTAssertFalse(v.releases.isEmpty)
        var wrong: [String] = []
        for c in v.credentials where ((try? ServerCredentials.Body.parse(c.full)) != nil) != c.valid {
            wrong.append("credentials \(c.name) (\(c.rule)): valid \(c.valid)")
        }
        for c in v.releases {
            let b = c.full
            var taken = b.count <= Releases.maxBody
            if taken {
                switch c.kind {
                case "keys": taken = (try? Releases.decodeKeys(b)) != nil
                case "release": taken = (try? Releases.decodeRelease(b)) != nil
                case "channel": taken = (try? Releases.decodeChannel(b)) != nil
                case "attest-status": taken = (try? Releases.decodeStatus(b)) != nil
                default: XCTFail("unknown kind \(c.kind)")
                }
            }
            if taken != c.valid { wrong.append("releases \(c.name) (\(c.rule)): valid \(c.valid)") }
        }
        XCTAssert(wrong.isEmpty, "\(wrong.count) vectors read otherwise:\n" + wrong.joined(separator: "\n"))
    }
}
