// SPDX-License-Identifier: AGPL-3.0-only

import ClipbridgeKit
import CryptoKit
import Foundation
import LocalAuthentication
import Security
import UIKit
import UniformTypeIdentifiers

/// The phone's own group (docs/protocol.md, section 9): its root CA key in
/// the Secure Enclave, signing only after Face ID or the passcode (a
/// keychain key where there is no Secure Enclave, as in the simulator), its
/// member key in the keychain, the group in Application Support. While there is a group it finds the computers,
/// keeps a connection to each, and syncs with them.
@MainActor
final class LiveGroup: GroupController {
    enum Failure: Error { case unreachable, notConfirmed }

    nonisolated static let caLabel = "io.github.hunterewok.clipbridge.group-root"
    /// How long one Face ID check covers the root key's signatures for the
    /// actions that follow it.
    static let authorizedFor: TimeInterval = 300
    static let memberLabel = "io.github.hunterewok.clipbridge.member"
    /// How recent a computer's copy must be for the button to fetch it
    /// first, as for the shortcut (internal/phone/sync.go).
    static let recentCopyMS: Int64 = 45_000

    let file: URL
    private(set) var state: PhoneGroup?
    private var node: MemberNode?
    private var browser: BonjourBrowser?
    private var dialer: MemberDialer?
    private var relay: Relay?
    private var recordBox: RecordBox?
    private var renewer: Renewer?
    private var online: Set<String> = []
    /// The last authentication context the user passed for the root key.
    private var authorized: (context: LAContext, at: Date)?

    nonisolated static var defaultFile: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("clipbridge/group.json")
    }

    init(file: URL = LiveGroup.defaultFile) {
        self.file = file
        state = try? PhoneGroup.load(from: file)
        try? startSync()
        Task { await renewOwnCertificate() }
    }

    /// Renews this phone's own member certificate when it is due, which
    /// asks for Face ID, and then connects again with it.
    private func renewOwnCertificate() async {
        guard var g = state, GroupCertificates.isDue(g.memberCert, groupCA: g.groupCA, now: Date()),
              let ca = try? await caSigner(reason: String(localized: "Renew this phone's certificate")),
              (try? g.renewOwnCertificate(caSigner: ca, now: Date())) == true else { return }
        try? g.save(to: file)
        state = g
        await restartSync()
    }

    var hasGroup: Bool { state != nil }

    var computers: [AppModel.Computer] {
        devices.filter { !$0.isSelf }
    }

    var devices: [AppModel.Computer] {
        guard let g = state else { return [] }
        return g.devices.map {
            .init(id: $0.id, name: $0.name, online: $0.id == g.device || online.contains($0.id), role: $0.role, isSelf: $0.id == g.device)
        }
    }

    func refresh() async {
        online = await node?.connected ?? []
    }

    // MARK: Keys

    private func key(label: String, secureEnclave: Bool) throws -> SecKey {
        if let k = try KeychainIdentity.loadKey(label: label) { return k }
        return try KeychainIdentity.makeKey(label: label, secureEnclave: secureEnclave)
    }

    /// The root key's signer for an action the user asked for. In the
    /// Secure Enclave the key signs only after Face ID, Touch ID or the
    /// passcode: asked once, and good for the signatures of the next few
    /// minutes. A key made before the app asked is asked for too.
    private func caSigner(reason: String) async throws -> SecKeySigner {
        guard SecureEnclave.isAvailable else { return try SecKeySigner(key(label: Self.caLabel, secureEnclave: false)) }
        let context: LAContext
        if let a = authorized, Date().timeIntervalSince(a.at) < Self.authorizedFor {
            context = a.context
        } else {
            context = LAContext()
            try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
            authorized = (context, Date())
            renewer?.context = context
        }
        if try KeychainIdentity.loadKey(label: Self.caLabel) == nil {
            _ = try KeychainIdentity.makeKey(label: Self.caLabel, secureEnclave: true, userPresence: true)
        }
        guard let k = try KeychainIdentity.loadKey(label: Self.caLabel, context: context) else { throw KeychainIdentity.Failure.noIdentity }
        return try SecKeySigner(k)
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
        let ca = try await caSigner(reason: String(localized: "Add a computer to your group"))
        let member = try memberSigner()
        var g = try state ?? PhoneGroup.create(caSigner: ca, memberKey: member.publicKeyDER, name: UIDevice.current.name, now: Date())
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
                groupChanged()
                await node?.sendRecords(g.records.records)
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

    // MARK: Removing

    /// Removes a device from the group: a revocation signed with the root
    /// key, sent to every connected computer, which refuse the device from
    /// then on. The phone stops dialing it.
    func remove(_ id: String) async throws {
        guard state != nil else { return }
        let ca = try await caSigner(reason: String(localized: "Remove a device from your group"))
        guard var g = state else { return }
        let r = try g.revoke(device: id, caSigner: ca, now: Date())
        try g.save(to: file)
        state = g
        groupChanged()
        await node?.sendRecords([r])
        await node?.close(peer: id)
    }

    /// Passes a changed group to the parts that run with it.
    private func groupChanged() {
        guard let g = state else { return }
        recordBox?.replace(g.records)
        relay?.allowed = Set(g.devices.map(\.id))
    }

    /// Takes in records a computer sent.
    private func adopt(_ set: RecordSet) {
        guard var g = state else { return }
        for r in set.records { g.records.add(r, groupCA: g.groupCA) }
        guard g != state else { return }
        try? g.save(to: file)
        state = g
        relay?.allowed = Set(g.devices.map(\.id))
    }

    // MARK: Syncing

    /// Starts finding and dialing the computers, once there is a group.
    private func startSync() throws {
        guard let g = state, node == nil else { return }
        let id = try identity(g, memberSigner())
        let box = RecordBox(groupCA: g.groupCA, set: g.records)
        box.onAdd = { [weak self] set in Task { @MainActor in self?.adopt(set) } }
        // The phone holds the group's key, so it renews the computers'
        // certificates when they connect and are due (docs/protocol.md,
        // section 2).
        let renewer = Renewer(group: g, secureEnclave: SecureEnclave.isAvailable)
        renewer.context = authorized?.context
        let node = MemberNode(engine: SyncEngine(device: g.device, clock: HybridClock()), name: UIDevice.current.name,
                              records: box, renew: { renewer.renew($0) })
        let relay = Relay()
        relay.allowed = Set(g.devices.map(\.id))
        let browser = BonjourBrowser { found in relay.update(found) }
        let dialer = MemberDialer(node: node, group: g.tag, dial: browser.dialer(identity: id, groupCA: g.groupCA))
        relay.dialer = dialer
        browser.start()
        (self.node, self.browser, self.dialer, self.relay, self.recordBox, self.renewer) = (node, browser, dialer, relay, box, renewer)
    }

    /// Stops syncing and starts again, with a renewed certificate.
    private func restartSync() async {
        await dialer?.stop()
        browser?.stop()
        await node?.closeAll()
        (node, browser, dialer, relay, recordBox, renewer) = (nil, nil, nil, nil, nil, nil)
        try? startSync()
    }

    /// Issues renewed member certificates with the root key, without
    /// asking: in the Secure Enclave only while the context of the user's
    /// last Face ID check in this run lasts, so a computer that is due and
    /// connects before that gets its renewal on a later connection.
    final class Renewer: @unchecked Sendable {
        let group: PhoneGroup
        let secureEnclave: Bool
        private let lock = NSLock()
        private var _context: LAContext?
        var context: LAContext? {
            get { lock.withLock { _context } }
            set { lock.withLock { _context = newValue } }
        }

        init(group: PhoneGroup, secureEnclave: Bool) { (self.group, self.secureEnclave) = (group, secureEnclave) }

        /// A renewal for a peer's chain, leaf first, when it is due and this
        /// phone may renew it.
        func renew(_ chain: [Data]) -> Data? {
            guard group.isAdmin, let cert = chain.first, GroupCertificates.isDue(cert, groupCA: group.groupCA, now: Date()) else { return nil }
            var ctx = context
            if secureEnclave && ctx == nil {
                let quiet = LAContext()
                quiet.interactionNotAllowed = true // a key that needs the user fails instead of asking
                ctx = quiet
            }
            guard let k = try? KeychainIdentity.loadKey(label: LiveGroup.caLabel, context: ctx), let signer = try? SecKeySigner(k) else { return nil }
            return group.renewal(chain: chain, caSigner: signer, now: Date())
        }
    }

    /// The group's records for the node, which exchanges them with the
    /// computers.
    final class RecordBox: RecordStore, @unchecked Sendable {
        private let lock = NSLock()
        private var set: RecordSet
        let groupCA: Data
        var onAdd: (@Sendable (RecordSet) -> Void)?

        init(groupCA: Data, set: RecordSet) { (self.groupCA, self.set) = (groupCA, set) }

        var digest: String? { lock.withLock { set.digest } }
        var all: [Member.Record] { lock.withLock { set.records } }

        func add(_ rs: [Member.Record]) -> [Member.Record] {
            let (fresh, now): ([Member.Record], RecordSet) = lock.withLock {
                (rs.filter { set.add($0, groupCA: groupCA) }, set)
            }
            if !fresh.isEmpty { onAdd?(now) }
            return fresh
        }

        func replace(_ new: RecordSet) { lock.withLock { set = new } }
    }

    /// Passes what the browser finds to the dialer, only the devices that
    /// are in the group's list: a removed computer is not dialed.
    final class Relay: @unchecked Sendable {
        private let lock = NSLock()
        private var _dialer: MemberDialer?
        private var _allowed: Set<String> = []
        private var last: Set<FoundMember> = []
        var dialer: MemberDialer? {
            get { lock.withLock { _dialer } }
            set { lock.withLock { _dialer = newValue } }
        }
        var allowed: Set<String> {
            get { lock.withLock { _allowed } }
            set {
                lock.withLock { _allowed = newValue }
                update(lock.withLock { last })
            }
        }
        func update(_ found: Set<FoundMember>) {
            let (d, members): (MemberDialer?, Set<FoundMember>) = lock.withLock {
                last = found
                return (_dialer, found.filter { _allowed.contains($0.device) })
            }
            guard let d else { return }
            Task { await d.update(members) }
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
