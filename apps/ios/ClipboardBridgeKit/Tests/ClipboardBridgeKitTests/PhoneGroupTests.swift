// SPDX-License-Identifier: AGPL-3.0-only

@testable import ClipboardBridgeKit
import Foundation
import XCTest

final class PhoneGroupTests: XCTestCase {
    func testCreateSaveLoad() throws {
        let now = Date()
        let ca = SoftwareSigner()
        let g = try PhoneGroup.create(caSigner: ca, memberKey: SoftwareSigner().publicKeyDER, now: now)
        XCTAssertEqual(try GroupCertificates.verifyMember(g.memberCert, groupCA: g.groupCA, now: now), g.device)
        let root = try ParsedCertificate(der: g.groupCA)
        XCTAssertTrue(root.isCA)
        XCTAssertTrue(try CertificateInfo(der: g.groupCA).commonName?.hasPrefix("clipboardbridge group root ") == true)
        XCTAssertEqual(g.tag.count, 16)

        let url = FileManager.default.temporaryDirectory.appendingPathComponent("cb-\(SyncEngine.newID())/group.json")
        XCTAssertNil(try PhoneGroup.load(from: url))
        var saved = g
        saved.computers.append(.init(device: SyncEngine.newID(), name: "pi", os: "linux", cert: Data([1]), admitted: now))
        try saved.save(to: url)
        XCTAssertEqual(try PhoneGroup.load(from: url), saved)
    }
}
