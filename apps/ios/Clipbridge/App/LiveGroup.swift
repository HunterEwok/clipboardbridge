// SPDX-License-Identifier: AGPL-3.0-only

import ClipbridgeKit
import CryptoKit
import Foundation
import Security
import UIKit
import UniformTypeIdentifiers

/// The phone's own group (docs/protocol.md, section 9): its root CA key in
/// the Secure Enclave (a keychain key where there is none, as in the
/// simulator), its member key in the keychain, the group in
/// Application Support. While there is a group it finds the computers,
/// keeps a connection to each, and syncs with them.
@MainActor
final class LiveGroup: GroupController {
    enum Failure: Error { case unreachable, notConfirmed }

    static let caLabel = "io.github.hunterewok.clipbridge.group-root"
    static let memberLabel = "io.github.hunterewok.clipbridge.member"
    /// How recent a computer's copy must be for the button to fetch it
    /// first, as for the shortcut (internal/phone/sync.go).
    static let recentCopyMS: Int64 = 45_000

    let file: URL
    private(set) var state: PhoneGroup?
    private var node: MemberNode?
    private var browser: BonjourBrowser?
    private var dialer: MemberDialer?
    private var online: Set<String> = []

    static var defaultFile: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("clipbridge/group.json")
    }

    init(file: URL = LiveGroup.defaultFile) {
        self.file = file
        state = try? PhoneGroup.load(from: file)
        try? startSync()
    }

    var hasGroup: Bool { state != nil }

    var computers: [AppModel.Computer] {
        (state?.computers ?? []).map { .init(id: $0.device, name: $0.name, online: online.contains($0.device)) }
    }

    func refresh() async {
        online = await node?.connected ?? []
    }

    // MARK: Keys

    private func key(label: String, secureEnclave: Bool) throws -> SecKey {
        if let k = try KeychainIdentity.loadKey(label: label) { return k }
        return try KeychainIdentity.makeKey(label: label, secureEnclave: secureEnclave)
    }

    private func caSigner() throws -> SecKeySigner {
        try SecKeySigner(key(label: Self.caLabel, secureEnclave: SecureEnclave.isAvailable))
    }

    private func memberSigner() throws -> SecKeySigner {
        try SecKeySigner(key(label: Self.memberLabel, secureEnclave: false))
    }

    private func identity(_ g: PhoneGroup, _ member: SecKeySigner) throws -> SecIdentity {
        KeychainIdentity.removeCertificates(label: Self.memberLabel)
        return try KeychainIdentity.identity(certificate: g.memberCert, key: member.key, label: Self.memberLabel, storeKey: false)
    }

    // MARK: Admitting

    func admit(_ code: JoinCode) async throws {
        let ca = try caSigner()
        let member = try memberSigner()
        var g = try state ?? PhoneGroup.create(caSigner: ca, memberKey: member.publicKeyDER, now: Date())
        let id = try identity(g, member)
        var lastError: Error = Failure.unreachable
        for addr in code.addrs {
            guard let (host, port) = Self.split(addr) else { continue }
            let tls = TLSTransport(host: host, port: port, alpn: Pairing.alpn, identity: id) { leaf in
                Pairing.fingerprint(cert: leaf) == code.fingerprint
            }
            do {
                try await tls.start()
                defer { tls.close() }
                guard let leaf = tls.peerCertificate,
                      let sid = tls.exportKeyingMaterial(label: Pairing.exporterLabel, length: 32) else { throw Failure.unreachable }
                let admitted = try await g.admit(over: tls, code: code.code, joinerCert: leaf, sessionID: sid, caSigner: ca, now: Date())
                try g.save(to: file)
                state = g
                try startSync()
                guard admitted.confirmed else { throw Failure.notConfirmed }
                return
            } catch let e as PairingMember.Failure {
                throw e // the computer answered: a wrong code is not worth another address
            } catch {
                tls.close()
                lastError = error
            }
        }
        throw lastError
    }

    /// host and port of "host:port" or "[IPv6]:port".
    nonisolated static func split(_ addr: String) -> (String, UInt16)? {
        guard let i = addr.lastIndex(of: ":"), let port = UInt16(addr[addr.index(after: i)...]) else { return nil }
        var host = String(addr[..<i])
        if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        return host.isEmpty ? nil : (host, port)
    }

    // MARK: Syncing

    /// Starts finding and dialing the computers, once there is a group.
    private func startSync() throws {
        guard let g = state, node == nil else { return }
        let id = try identity(g, memberSigner())
        let node = MemberNode(engine: SyncEngine(device: g.device, clock: HybridClock()), name: UIDevice.current.name)
        let relay = Relay()
        let browser = BonjourBrowser { found in relay.update(found) }
        let dialer = MemberDialer(node: node, group: g.tag, dial: browser.dialer(identity: id, groupCA: g.groupCA))
        relay.dialer = dialer
        browser.start()
        (self.node, self.browser, self.dialer) = (node, browser, dialer)
    }

    /// Passes what the browser finds to the dialer.
    final class Relay: @unchecked Sendable {
        private let lock = NSLock()
        private var _dialer: MemberDialer?
        var dialer: MemberDialer? {
            get { lock.withLock { _dialer } }
            set { lock.withLock { _dialer = newValue } }
        }
        func update(_ found: Set<FoundMember>) {
            guard let d = dialer else { return }
            Task { await d.update(found) }
        }
    }

    /// The one button, by the rule of the shortcut: a computer's copy of a
    /// moment ago comes to the phone; otherwise a new text on the phone goes
    /// to the computers; otherwise the computers' latest text comes.
    func sync() async throws -> AppModel.SyncResult {
        guard let node, let g = state else { throw PendingGroup.Failure.noComputers }
        online = await node.connected
        let board = UIPasteboard.general.hasStrings ? UIPasteboard.general.string : nil
        let cur = await node.current
        let usable = await node.usable
        if let cur, let u = usable, cur.origin != g.device, cur.via == .copy, cur.ageMS < Self.recentCopyMS, u.text != board {
            write(u.text, kind: u.kind)
            return .fetched
        }
        if let t = board, !t.isEmpty, t != usable?.text {
            guard !online.isEmpty else { throw PendingGroup.Failure.noComputers }
            await node.send(text: t, kind: .text)
            return .sent
        }
        if let u = usable, u.text != board {
            write(u.text, kind: u.kind)
            return .fetched
        }
        if online.isEmpty { throw PendingGroup.Failure.noComputers }
        return .nothingNew
    }

    /// Puts a text into the phone's clipboard; a secret stays on this phone
    /// only and for its remaining minute.
    private func write(_ text: String, kind: Member.Kind) {
        if kind == .secret {
            UIPasteboard.general.setItems([[UTType.plainText.identifier: text]],
                                          options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(SyncEngine.secretTTL)])
        } else {
            UIPasteboard.general.string = text
        }
    }
}
