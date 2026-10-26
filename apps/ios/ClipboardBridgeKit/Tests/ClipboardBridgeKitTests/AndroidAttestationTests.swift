// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import ClipboardBridgeKit
import Foundation
import XCTest

final class AndroidAttestationTests: XCTestCase {
    /// Reads testdata/interop/go-attest.json, from Go's TestAttestVectors.
    func testGoAttest() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct Challenge: Decodable {
            var group_tag: String
            var member_key: Data?
            var salt: Data
            var challenge: Data
        }
        struct C: Decodable {
            var name: String
            var chain: [Data]
            var spki: Data
            var challenge: Data
            var roots: [Data]?
            var strict: Bool?
            var revoked: [String]?
            var ok: Bool
            var store: String?
            var kind: String?
            var rkp: Bool?
            var serials: [String]?
        }
        struct V: Decodable {
            var google_roots: [Data]
            var challenges: [Challenge]
            var vectors: [C]
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/go-attest.json")))
        XCTAssertEqual(v.google_roots, AndroidAttestation.googleRoots)
        for c in v.challenges {
            XCTAssertEqual(try Attestation.challenge(groupTag: c.group_tag, memberKey: c.member_key ?? Data(), salt: c.salt), c.challenge, c.group_tag)
        }
        XCTAssertEqual(v.vectors.count, 23)
        for c in v.vectors {
            let policy = AndroidAttestation.Policy(strict: c.strict ?? false, revoked: Set(c.revoked ?? []), roots: c.roots)
            let got = Result { try AndroidAttestation.check(chain: c.chain, spki: c.spki, challenge: c.challenge, policy: policy) }
            switch got {
            case let .success(r):
                XCTAssertTrue(c.ok, c.name)
                XCTAssertEqual(r.store, c.store, c.name)
                XCTAssertEqual(r.kind, c.kind ?? "", c.name)
                XCTAssertEqual(r.rkp, c.rkp ?? false, c.name)
                XCTAssertEqual(r.serials, c.serials, c.name)
                XCTAssertEqual(r.store == Records.proven, r.why.isEmpty, c.name)
            case let .failure(e):
                XCTAssertFalse(c.ok, "\(c.name): \(e)")
                XCTAssertTrue(e is AndroidAttestation.Invalid, "\(c.name): \(e)")
            }
        }
        XCTAssertThrowsError(try Attestation.challenge(groupTag: "", memberKey: Data(), salt: Data(count: 15)))
    }
}
