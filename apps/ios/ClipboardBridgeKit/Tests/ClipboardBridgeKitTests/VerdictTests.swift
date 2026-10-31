// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import ClipboardBridgeKit
import Crypto
import Foundation
import XCTest

/// The kit's verdicts on a corpus of tools/difffuzz (docs/differential.md):
/// one line per case, which the comparison checks against the other
/// implementations' lines. It runs on the corpus that CBB_VERDICTS names and
/// writes to CBB_VERDICTS_OUT; without them, on a corpus of its own.
final class VerdictTests: XCTestCase {
    struct Case: Decodable {
        var kind: String
        var body: Data?
        var ca: Data?
        var records: [Member.Record]?
        var keys: [Data]?
    }

    func hex(_ d: Data?) -> String { (d ?? Data()).map { String(format: "%02x", $0) }.joined() }
    func hex(_ s: String?) -> String { hex(Data((s ?? "").utf8)) }
    func hashes(_ l: [Data]?) -> String { (l ?? []).map { hex($0) }.joined(separator: ".") }
    func bit(_ b: Bool) -> String { b ? "1" : "0" }
    func sha(_ d: Data) -> Data { Data(SHA256.hash(data: d)) }

    func taken(_ pairs: [(String, String)]) -> String { "taken" + pairs.map { " \($0.0)=\($0.1)" }.joined() }

    /// A reader refuses with its own error; any other is a verdict of its
    /// own, which no other reader gives.
    func refused(_ f: () throws -> String) -> String {
        do { return try f() } catch is Commands.Refused { return "refused" } catch is ServerCredentials.Refused {
            return "refused"
        } catch is Releases.Refused { return "refused" } catch { return "threw \(type(of: error))" }
    }

    func verdict(_ c: Case) -> String {
        let body = c.body ?? Data()
        switch c.kind {
        case "record":
            guard let b = Records.Body.decode(body) else { return "refused" }
            return taken([
                ("type", hex(b.type)), ("group", hex(b.group)), ("time_ms", String(b.time_ms)), ("by", hex(b.by)),
                ("device", hex(b.device)), ("name", hex(b.name)), ("role", hex(b.role)), ("os", hex(b.os)),
                ("store", hex(b.store)), ("key", hex(b.key)), ("admin", hex(b.admin)), ("keys", hashes(b.keys)),
                ("keep", hashes(b.keep)), ("root", hex(b.root)), ("records", hashes(b.records)),
            ])
        case "command":
            return refused {
                let b = try Commands.parse(body)
                return taken([
                    ("type", hex(b.type)), ("group", hex(b.group)), ("by", hex(b.by)), ("to", hex(b.to)), ("id", hex(b.id)),
                    ("time_ms", String(b.time_ms)), ("expires_ms", String(b.expires_ms)), ("mode", hex(b.mode)),
                    ("enter", bit(b.enter ?? false)), ("kind", hex(b.kind)), ("text", hex(sha(Data((b.text ?? "").utf8)))),
                    ("action", hex(b.action)),
                ])
            }
        case "credential":
            return refused {
                let b = try ServerCredentials.Body.parse(body)
                return taken([
                    ("type", hex(b.type)), ("group", hex(b.group)), ("version", String(b.version)),
                    ("expires_ms", String(b.expires_ms)), ("tag", hex(b.tag)), ("key", hex(b.key)), ("hubs", hashes(b.hubs)),
                    ("admins", hashes(b.admins)), ("members", hashes(b.members)),
                ])
            }
        case "manifest":
            // The frames' decoder, Member.decode, runs the same scan first.
            let m = Strict.integersOnly(body) ? try? JSONDecoder().decode(Media.Manifest.self, from: body) : nil
            return m?.isValid ?? false ? "taken" : "refused"
        case "keys", "release", "channel", "attest-status":
            return refused {
                guard body.count <= Releases.maxBody else { return "refused" }
                switch c.kind {
                case "keys": _ = try Releases.decodeKeys(body)
                case "release": _ = try Releases.decodeRelease(body)
                case "channel": _ = try Releases.decodeChannel(body)
                default: _ = try Releases.decodeStatus(body)
                }
                return "taken"
            }
        case "set":
            return set(c)
        default:
            XCTFail("unknown kind \(c.kind)")
            return ""
        }
    }

    func set(_ c: Case) -> String {
        // The kits refuse legacy groups (docs/protocol.md, section 2): a
        // group CA of path length 0 that a root record hands to a root, as
        // cbb upgrade does.
        let legacy = (try? ParsedCertificate(der: c.ca ?? Data()))?.pathLength == 0
        if legacy, (c.records ?? []).contains(where: { Records.Body.decode($0.body)?.type == "root" }) { return "skip" }
        var set = RecordSet()
        let fresh = set.addAll(c.records ?? [], groupCA: c.ca ?? Data())
        let roots = set.roots.map { hex(sha($0)) }.joined(separator: ".")
        let devices = set.devices.map {
            [hex($0.id), hex($0.name), hex($0.role), hex($0.store), bit($0.admin), hex($0.adminKey), bit($0.frozen)].joined(separator: ":")
        }.joined(separator: ".")
        let keys = c.keys ?? []
        let revoked = keys.map { bit(set.revoked.contains($0)) }.joined()
        let frozen = keys.map { bit(set.isFrozen($0)) }.joined()
        return "set taken=\(fresh.count) roots=\(roots) devices=\(devices) revoked=\(revoked) frozen=\(frozen) digest=\(set.digest ?? "")"
    }

    func testVerdicts() throws {
        let env = ProcessInfo.processInfo.environment
        let input = env["CBB_VERDICTS"].flatMap { $0.isEmpty ? nil : $0 }
        let text = try input.map { try String(contentsOfFile: $0, encoding: .utf8) }
            ?? "{\"kind\":\"record\",\"body\":\"e30=\"}\n{\"kind\":\"keys\",\"body\":\"e30=\"}\n"
        var out = ""
        for line in text.split(separator: "\n") where !line.isEmpty {
            out += verdict(try JSONDecoder().decode(Case.self, from: Data(line.utf8))) + "\n"
        }
        if input != nil {
            try out.write(toFile: env["CBB_VERDICTS_OUT"]!, atomically: true, encoding: .utf8)
        } else {
            XCTAssertEqual(out, "refused\nrefused\n")
        }
    }
}
