// SPDX-License-Identifier: AGPL-3.0-only

import ClipboardBridgeKit
import CryptoKit
import Foundation
import LocalAuthentication
import Network
import os
import Security
import UIKit
import UniformTypeIdentifiers

private let awayLog = Logger(subsystem: "io.github.hunterewok.clipboardbridge", category: "away")

/// The phone's own group (docs/protocol.md, section 9): its root CA key in
/// the Secure Enclave, signing only after Face ID or the passcode (a
/// keychain key where there is no Secure Enclave, as in the simulator), its
/// member key in the keychain, the group in Application Support. While there is a group it finds the computers,
/// keeps a connection to each, and syncs with them.
@MainActor
final class LiveGroup: GroupController {
    enum Failure: Error { case unreachable, notConfirmed, noNetwork, timedOut, tooManyWrongCodes, notAdmin }

    /// The clipboard holds something the app could not read as text: the
    /// paste was not allowed, or it is not text. The button leaves it as it
    /// is rather than put an older text over it.
    struct ClipboardUnreadable: Error {
        let items: Int
        let hasStrings: Bool
        let types: [String]
        let changeCount: Int
    }

    nonisolated static let caLabel = "io.github.hunterewok.clipboardbridge.group-root"
    /// The admin key of a phone that joined another phone's group.
    nonisolated static let adminLabel = "io.github.hunterewok.clipboardbridge.admin"
    /// How long the join QR code is good for, and how many wrong codes it
    /// takes, as for cbb pair (docs/protocol.md, section 6).
    static let joinWindow: TimeInterval = 300
    /// How long admitting a device may take once its connection is up:
    /// a computer that stops answering mid-pairing fails then.
    static let pairingDeadline: Duration = .seconds(30)
    static let joinAttempts = 3
    /// How long one Face ID check covers the root key's signatures for the
    /// actions that follow it.
    static let authorizedFor: TimeInterval = 300
    static let memberLabel = Shared.memberLabel
    /// Whether the root and admin keys live in the Secure Enclave behind
    /// Face ID. The simulator reports a Secure Enclave but cannot make a key
    /// that needs user presence, so there they are keychain keys.
    nonisolated static var secureEnclave: Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        return SecureEnclave.isAvailable
        #endif
    }
    /// How recent a computer's copy must be for the button to fetch it
    /// first, as for the shortcut (internal/phone/sync.go).
    static let recentCopyMS: Int64 = 45_000
    /// How long the button waits for a computer to connect before it says
    /// none is.
    static let connectWait: Duration = .seconds(5)

    let file: URL
    private(set) var state: PhoneGroup?
    private var node: MemberNode?
    private var browser: BonjourBrowser?
    private var dialer: MemberDialer?
    private var relay: Relay?
    private var recordBox: RecordBox?
    private var renewer: Renewer?
    private var admins: AdminBox?
    private var away: AwayFromHome?
    private var online: Set<String> = []
    /// The admin keys the connected computers offer, by device ID.
    private var offers: [String: Data] = [:]
    /// The last authentication context the user passed for the root key.
    private var authorized: (context: LAContext, at: Date)?

    /// In the app group's container, where the share extension reads it.
    nonisolated static var defaultFile: URL { Shared.groupFile }

    init(file: URL = LiveGroup.defaultFile) {
        self.file = file
        state = try? PhoneGroup.load(from: file)
        try? startSync()
        Task { await renewOwnCertificate() }
    }

    /// Renews this phone's own member certificate when it is due, which
    /// asks for Face ID, and then connects again with it.
    private func renewOwnCertificate() async {
        guard var g = state, GroupCertificates.isDue(g.memberCert, groupCA: g.adminCA ?? g.currentRoot, now: Date()),
              let ca = try? await caSigner(reason: String(localized: "Renew this phone's certificate", bundle: .app)),
              (try? g.renewOwnCertificate(caSigner: ca, now: Date())) == true else { return }
        try? g.save(to: file)
        state = g
        await restartSync()
    }

    var hasGroup: Bool { state != nil }

    /// Whether this phone may add and remove devices: it made the group, or
    /// the phone that did made it an admin. A phone without a group makes
    /// one when it adds a computer.
    var isAdmin: Bool { state?.isAdmin ?? true }

    /// The label of the key this phone signs with: the root key, or the
    /// admin key of a phone that joined.
    nonisolated static func signingLabel(_ g: PhoneGroup?) -> String { g?.isRoot == false ? adminLabel : caLabel }

    var computers: [AppModel.Computer] {
        devices.filter { !$0.isSelf }
    }

    var devices: [AppModel.Computer] {
        guard let g = state else { return [] }
        let root = g.records.rootDevice
        return g.devices.map {
            .init(id: $0.id, name: $0.name, online: $0.id == g.device || online.contains($0.id), role: $0.role, os: $0.os,
                  isSelf: $0.id == g.device,
                  admin: $0.admin || $0.id == root, isRoot: $0.id == root,
                  canMakeAdmin: g.isRoot && !$0.admin && !$0.frozen && $0.role == "full" && offers[$0.id] != nil, frozen: $0.frozen)
        }
    }

    func refresh() async {
        online = await node?.connected ?? []
        offers = await node?.offeredAdminKeys ?? [:]
    }

    // MARK: Keys

    private func key(label: String, secureEnclave: Bool) throws -> SecKey {
        if let k = try KeychainIdentity.loadKey(label: label) { return k }
        return try KeychainIdentity.makeKey(label: label, secureEnclave: secureEnclave)
    }

    /// The signer of this phone's root or admin key for an action the user
    /// asked for. In the Secure Enclave the key signs only after Face ID,
    /// Touch ID or the passcode: asked once, and good for the signatures of
    /// the next few minutes. A key made before the app asked is asked for
    /// too. A phone that is no admin has no such key.
    private func caSigner(reason: String) async throws -> SecKeySigner {
        guard isAdmin else { throw Failure.notAdmin }
        return try await signer(label: Self.signingLabel(state), reason: reason)
    }

    /// The signer of the key under label, after Face ID as caSigner asks.
    private func signer(label: String, reason: String) async throws -> SecKeySigner {
        guard Self.secureEnclave else { return try SecKeySigner(key(label: label, secureEnclave: false)) }
        let context: LAContext
        if let a = authorized, Date().timeIntervalSince(a.at) < Self.authorizedFor {
            context = a.context
        } else {
            context = LAContext()
            try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
            authorized = (context, Date())
            renewer?.context = context
        }
        if try KeychainIdentity.loadKey(label: label) == nil {
            _ = try KeychainIdentity.makeKey(label: label, secureEnclave: true, userPresence: true)
        }
        guard let k = try KeychainIdentity.loadKey(label: label, context: context) else { throw KeychainIdentity.Failure.noIdentity }
        return try SecKeySigner(k)
    }

    func prepare() throws {
        _ = try memberSigner()
    }

    private func memberSigner() throws -> SecKeySigner {
        try SecKeySigner(key(label: Self.memberLabel, secureEnclave: false))
    }

    private func identity(_ g: PhoneGroup, _ member: SecKeySigner) throws -> SecIdentity {
        try identity(certificate: g.memberCert, member)
    }

    private func identity(certificate: Data, _ member: SecKeySigner) throws -> SecIdentity {
        KeychainIdentity.removeCertificates(label: Self.memberLabel)
        return try KeychainIdentity.identity(certificate: certificate, key: member.key, label: Self.memberLabel, storeKey: false)
    }

    /// The certificates this phone sends after its own in TLS: the admin CA
    /// that issued it, if one did.
    private static func chain(_ g: PhoneGroup) -> [Data] { g.memberIssuer.map { [$0] } ?? [] }

    // MARK: Admitting

    func admit(_ code: JoinCode) async throws {
        let ca = try await caSigner(reason: String(localized: "Add a computer to your group", bundle: .app))
        let member = try memberSigner()
        var g = try state ?? PhoneGroup.create(caSigner: ca, memberKey: member.publicKeyDER, name: UIDevice.current.name, now: Date())
        let id = try identity(g, member)
        var failure: Error?
        for addr in Self.ordered(code.addrs) {
            try Task.checkCancellation()
            guard let (host, port) = Self.split(addr) else { continue }
            let tls = TLSTransport(host: host, port: port, alpn: Pairing.alpn, identity: id, chain: Self.chain(g)) { leaf in
                Pairing.fingerprint(cert: leaf) == code.fingerprint
            }
            // Closing the connection ends a pairing that takes too long or
            // that the user cancelled: the pending read fails.
            let deadline = Task {
                try await Task.sleep(for: Self.pairingDeadline)
                tls.close()
            }
            defer { deadline.cancel() }
            do {
                let admitted = try await withTaskCancellationHandler {
                    try await tls.start()
                    defer { tls.close() }
                    guard let leaf = tls.peerCertificate,
                          let sid = tls.exportKeyingMaterial(label: Pairing.exporterLabel, length: 32) else { throw Failure.unreachable }
                    // The address that answered goes first, for dialing when mDNS does not find the computer.
                    return try await g.admit(over: tls, code: code.code, joinerCert: leaf, sessionID: sid, caSigner: ca,
                                             addrs: [addr] + code.addrs.filter { $0 != addr }, now: Date())
                } onCancel: {
                    tls.close()
                }
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
                if Task.isCancelled { throw CancellationError() }
                failure = Self.telling(failure, error)
            }
        }
        throw failure ?? Failure.unreachable
    }

    /// Of two failures on different addresses, the one that says more: an
    /// address that answered, as with a failed handshake, over one that
    /// did not.
    nonisolated static func telling(_ earlier: Error?, _ later: Error) -> Error {
        guard let earlier else { return later }
        if case TLSTransport.Failure.timedOut = earlier, !isTimeout(later) { return later }
        return earlier
    }

    nonisolated private static func isTimeout(_ e: Error) -> Bool {
        if case TLSTransport.Failure.timedOut = e { return true }
        return false
    }

    /// The addresses to try, IPv4 first: a home network reaches those most
    /// surely, and each that fails costs its timeout.
    nonisolated static func ordered(_ addrs: [String]) -> [String] { JoinCode.ordered(addrs) }

    /// host and port of "host:port" or "[IPv6]:port".
    nonisolated static func split(_ addr: String) -> (String, UInt16)? { JoinCode.split(addr) }

    // MARK: Joining

    /// Joins another phone's group (docs/protocol.md, section 6, "The
    /// joiner listens"): makes this phone's admin key, listens, hands show
    /// the QR code to put on screen, and waits up to five minutes for an
    /// admin phone to scan it and admit this one. Three wrong codes end it,
    /// as does cancelling the task.
    func join(show: @escaping @MainActor (JoinCode) -> Void) async throws {
        guard state == nil else { return }
        let member = try memberSigner()
        // The admin key, in the Secure Enclave behind Face ID like the root
        // key; reading its public key asks for nothing.
        let se = Self.secureEnclave
        let admin = try SecKeySigner(KeychainIdentity.loadKey(label: Self.adminLabel)
            ?? KeychainIdentity.makeKey(label: Self.adminLabel, secureEnclave: se, userPresence: se))
        let device = SyncEngine.newID()
        let cert = try GroupCertificates.selfSigned(device: device, signer: member)
        let id = try identity(certificate: cert, member)
        let listener = try TLSListener(alpn: Pairing.alpn, identity: id) { !$0.isEmpty }
        let port = try await listener.start()
        let addrs = LocalAddresses.current().map { JoinCode.address(host: $0, port: port) }
        guard !addrs.isEmpty else {
            listener.stop()
            throw Failure.noNetwork
        }
        let code = JoinCode(code: JoinCode.newCode(), addrs: addrs, fingerprint: Pairing.fingerprint(cert: cert))
        show(code)
        let info = Pairing.Info(name: PhoneGroup.validName(UIDevice.current.name), os: "ios", adminKey: admin.publicKeyDER)
        let file = file
        let timer = Task {
            try await Task.sleep(for: .seconds(Self.joinWindow))
            listener.stop()
        }
        defer {
            timer.cancel()
            listener.stop()
        }
        var wrong = 0
        let joined: PairingJoiner.Joined? = try await withTaskCancellationHandler {
            while let t = await listener.next() {
                do {
                    try await t.start()
                    defer { t.close() }
                    guard let leaf = t.peerCertificate, let sid = t.exportKeyingMaterial(label: Pairing.exporterLabel, length: 32) else { continue }
                    return try await PairingJoiner.accept(over: t, code: code.code, info: info, memberCert: leaf, joinerCert: cert,
                                                          sessionID: sid, now: Date()) { try PhoneGroup.joined($0).save(to: file) }
                } catch PairingJoiner.Failure.refused(.wrongCode) {
                    wrong += 1
                    if wrong >= Self.joinAttempts { throw Failure.tooManyWrongCodes }
                } catch {
                    continue // another device, or a dropped connection: the code is not spent
                }
            }
            return nil
        } onCancel: {
            listener.stop()
        }
        guard let joined else {
            if Task.isCancelled { throw CancellationError() }
            throw Failure.timedOut
        }
        state = PhoneGroup.joined(joined)
        try startSync()
    }

    // MARK: Removing

    /// Removes a device from the group: a revocation signed with this
    /// phone's root or admin key, sent to every connected computer, which
    /// refuse the device from then on. The phone stops dialing it.
    func remove(_ id: String) async throws {
        guard let current = state else { return }
        if !current.isRoot, id == current.records.rootDevice {
            try await takeOver(from: id)
            return
        }
        let ca = try await caSigner(reason: String(localized: "Remove a device from your group", bundle: .app))
        guard var g = state else { return }
        let r = try g.revoke(device: id, caSigner: ca, now: Date())
        try g.save(to: file)
        state = g
        groupChanged()
        await node?.sendRecords([r])
        await node?.close(peer: id)
    }

    /// Unfreezes an admin computer that another admin froze
    /// (docs/protocol.md, section 10, rule 4): a thaw record signed with this
    /// phone's root or admin key, after Face ID, sent to every connected
    /// computer.
    func unfreeze(_ id: String) async throws {
        let ca = try await caSigner(reason: String(localized: "Unfreeze an admin computer", bundle: .app))
        guard var g = state else { return }
        let r = try g.thaw(device: id, caSigner: ca, now: Date())
        try g.save(to: file)
        state = g
        groupChanged()
        await node?.sendRecords([r])
    }

    /// Gives a device another name (docs/protocol.md, section 10): a device
    /// record like its newest one with that name, signed with this phone's
    /// root or admin key after Face ID, sent to every connected computer.
    func rename(_ id: String, to name: String) async throws {
        guard state?.isAdmin == true else { throw PhoneGroup.Failure.notAdmin }
        let ca = try await caSigner(reason: String(localized: "Rename a device", bundle: .app))
        guard var g = state else { return }
        let r = try g.rename(device: id, to: name, caSigner: ca, now: Date())
        try g.save(to: file)
        state = g
        groupChanged()
        await node?.sendRecords([r])
    }

    /// Makes a computer an admin (docs/protocol.md, section 10, "A computer
    /// as admin"): the root key, after Face ID, certifies the admin key the
    /// computer offers; the computer gets its admin CA and every member the
    /// new record.
    func makeAdmin(_ id: String) async throws {
        guard state?.isRoot == true, let key = offers[id] else { throw Failure.notAdmin }
        let root = try await caSigner(reason: String(localized: "Make a computer an admin", bundle: .app))
        guard var g = state else { return }
        let (ca, r) = try g.makeAdmin(device: id, adminKey: key, rootSigner: root, now: Date())
        try g.save(to: file)
        state = g
        groupChanged()
        await node?.sendRecords([r])
        await node?.send(adminCA: ca, to: id)
    }

    /// Removes the phone that holds the group's root, when it is lost: this
    /// admin phone makes a new root key in the Secure Enclave, behind Face
    /// ID, and takes the group over (docs/protocol.md, section 10, "Handing
    /// the group over"). From then on it signs with that key.
    private func takeOver(from id: String) async throws {
        let reason = String(localized: "Take the group over from the lost phone", bundle: .app)
        let admin = try await signer(label: Self.adminLabel, reason: reason)
        // A root key left from a group this phone made before goes.
        KeychainIdentity.removeKey(label: Self.caLabel)
        let se = Self.secureEnclave
        _ = try KeychainIdentity.makeKey(label: Self.caLabel, secureEnclave: se, userPresence: se)
        let root = try await signer(label: Self.caLabel, reason: reason)
        guard var g = state else { return }
        let rs = try g.takeOver(from: id, adminSigner: admin, rootSigner: root, now: Date())
        try g.save(to: file)
        state = g
        groupChanged()
        await node?.sendRecords(rs)
        await node?.close(peer: id)
        await restartSync()
    }

    /// Passes a changed group to the parts that run with it.
    private func groupChanged() {
        guard let g = state else { return }
        recordBox?.replace(g.records)
        admins?.group = g
        relay?.allowed = Self.allowed(g)
        relay?.addresses = g.addresses
    }

    /// The devices the phone dials: those in the list. A phone that joined
    /// has no records until a computer sends them, so it dials every member
    /// of the group until then; TLS still checks each against the group CA.
    nonisolated static func allowed(_ g: PhoneGroup) -> Set<String>? {
        g.records.records.isEmpty ? nil : Set(g.devices.map(\.id))
    }

    /// Takes in records a computer sent, and the roots they lead to: a
    /// new root, after another admin phone took the group over, means
    /// connecting again with it trusted.
    private func adopt(_ set: RecordSet) {
        guard var g = state else { return }
        let roots = g.roots
        g.add(set.records)
        guard g != state else { return }
        try? g.save(to: file)
        state = g
        relay?.allowed = Self.allowed(g)
        if g.roots != roots { Task { await restartSync() } }
    }

    // MARK: Syncing

    /// Starts finding and dialing the computers, once there is a group.
    private func startSync() throws {
        guard let g = state, node == nil else { return }
        let id = try identity(g, memberSigner())
        let box = RecordBox(groupCA: g.groupCA, set: g.records)
        box.onAdd = { [weak self] set in Task { @MainActor in self?.adopt(set) } }
        // An admin phone renews the computers' certificates when they
        // connect and are due (docs/protocol.md, section 2).
        let renewer = Renewer(group: g, secureEnclave: Self.secureEnclave)
        renewer.context = authorized?.context
        // The root sends a computer it made an admin its admin CA again
        // when the computer still offers the key.
        let admins = AdminBox(group: g)
        // Sync away from home: the hellos offer the tunnel key while it is
        // on, and the hub's answer goes to AwayFromHome.
        let awayState = AwayKeychain.load()
        let awayRef = Ref<AwayFromHome>()
        let node = MemberNode(engine: SyncEngine(device: g.device, clock: HybridClock()), name: UIDevice.current.name, os: "ios",
                              records: box, renew: { renewer.renew($0) }, adminCA: { admins.group.computerAdminCA(for: $0) },
                              tunnelKey: awayState.flatMap { try? GoTunnels().publicKey($0.key) },
                              onTunnel: { from, offer in Task { await awayRef.value?.keep(from: from, offer: offer) } })
        let relay = Relay(group: g.tag)
        relay.allowed = Self.allowed(g)
        // Through the tunnel the phone dials the hub's member port with the
        // same TLS as at home, and only while the hub is not found here.
        let chain = Self.chain(g), roots = g.trusted
        let away = AwayFromHome(
            device: g.device, tunnels: GoTunnels(), state: awayState, save: { try AwayKeychain.save($0) },
            atHome: { relay.has($0) },
            dial: { port, hub in
                let t = TLSTransport(endpoint: .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port) ?? .any),
                                     alpn: Member.alpn, identity: id, chain: chain) { peer in
                    (try? GroupCertificates.verifyMember(chain: peer, roots: roots, now: Date())) == hub
                }
                try await t.start()
                return t
            },
            serve: { t, hub in try await node.serve(t, peer: hub) },
            mayHost: { box.mayHost($0) },
            log: { what, error in awayLog.error("\(what, privacy: .public): \(String(reflecting: error), privacy: .public)") })
        awayRef.value = away
        Task { await away.start() }
        let browser = BonjourBrowser { found in relay.update(found) }
        let dialer = MemberDialer(node: node, group: g.tag,
                                  dial: browser.dialer(identity: id, chain: Self.chain(g), roots: g.trusted) { relay.addresses[$0] ?? [] })
        relay.dialer = dialer
        // The computers at known addresses are dialed even while browsing finds nothing.
        relay.addresses = g.addresses
        browser.start()
        (self.node, self.browser, self.dialer, self.relay, self.recordBox, self.renewer, self.admins, self.away) =
            (node, browser, dialer, relay, box, renewer, admins, away)
    }

    /// Stops syncing and starts again, with a renewed certificate.
    private func restartSync() async {
        await away?.stop()
        await dialer?.stop()
        browser?.stop()
        await node?.closeAll()
        (node, browser, dialer, relay, recordBox, renewer, admins, away) = (nil, nil, nil, nil, nil, nil, nil, nil)
        try? startSync()
    }

    /// Sync away from home as Settings shows it; nil without a group.
    func awayStatus() async -> (on: Bool, status: AwayFromHome.Status, error: Error?)? {
        guard let away else { return nil }
        return (await away.isOn, await away.status, await away.lastError)
    }

    /// Turns sync away from home on or off, then connects again, so the
    /// hellos offer the new key and the hub answers it.
    func setAwayFromHome(_ on: Bool) async throws {
        guard let away else { return }
        if on { try await away.turnOn() } else { try await away.turnOff() }
        await restartSync()
    }

    /// A value set after the closures that read it are made.
    final class Ref<T: AnyObject>: @unchecked Sendable {
        private let lock = NSLock()
        private var _value: T?
        var value: T? {
            get { lock.withLock { _value } }
            set { lock.withLock { _value = newValue } }
        }
    }

    /// Issues renewed member certificates with the root or admin key, without
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
        func renew(_ chain: [Data]) -> MemberNode.Renewal? {
            guard group.isAdmin, let cert = chain.first,
                  GroupCertificates.isDue(cert, groupCA: group.adminCA ?? group.currentRoot, now: Date()) else { return nil }
            var ctx = context
            if secureEnclave && ctx == nil {
                let quiet = LAContext()
                quiet.interactionNotAllowed = true // a key that needs the user fails instead of asking
                ctx = quiet
            }
            guard let k = try? KeychainIdentity.loadKey(label: LiveGroup.signingLabel(group), context: ctx),
                  let signer = try? SecKeySigner(k) else { return nil }
            return group.renewal(chain: chain, caSigner: signer, now: Date())
        }
    }

    /// The group as the node's adminCA closure reads it, off the main actor.
    final class AdminBox: @unchecked Sendable {
        private let lock = NSLock()
        private var _group: PhoneGroup
        var group: PhoneGroup {
            get { lock.withLock { _group } }
            set { lock.withLock { _group = newValue } }
        }
        init(group: PhoneGroup) { _group = group }
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
                (set.addAll(rs, groupCA: groupCA), set)
            }
            if !fresh.isEmpty { onAdd?(now) }
            return fresh
        }

        func replace(_ new: RecordSet) { lock.withLock { set = new } }

        /// Whether device may be the hub for sync away from home.
        func mayHost(_ device: String) -> Bool { lock.withLock { set.mayHost(device) } }
    }

    /// Passes what the browser finds to the dialer, with the computers it
    /// does not find at the addresses they had when admitted, only the
    /// devices that are in the group's list: a removed computer is not
    /// dialed.
    final class Relay: @unchecked Sendable {
        private let lock = NSLock()
        private var _dialer: MemberDialer?
        private var _allowed: Set<String>? = []
        private var _addresses: [String: [String]] = [:]
        private var last: Set<FoundMember> = []
        /// The group tag of the members at known addresses.
        let group: String

        init(group: String) { self.group = group }
        var dialer: MemberDialer? {
            get { lock.withLock { _dialer } }
            set { lock.withLock { _dialer = newValue } }
        }
        /// The device IDs to dial; nil dials every member found.
        var allowed: Set<String>? {
            get { lock.withLock { _allowed } }
            set {
                lock.withLock { _allowed = newValue }
                update(lock.withLock { last })
            }
        }
        /// The known addresses of the computers, by device ID.
        var addresses: [String: [String]] {
            get { lock.withLock { _addresses } }
            set {
                lock.withLock { _addresses = newValue }
                update(lock.withLock { last })
            }
        }
        /// Whether the browser finds device on the home network now.
        func has(_ device: String) -> Bool { lock.withLock { last.contains { $0.device == device } } }

        func update(_ found: Set<FoundMember>) {
            let (d, members): (MemberDialer?, Set<FoundMember>) = lock.withLock {
                last = found
                let all = Discovery.withKnown(found, known: Set(_addresses.keys), group: group)
                return (_dialer, _allowed.map { a in all.filter { a.contains($0.device) } } ?? all)
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
        let pb = UIPasteboard.general
        let board = pb.hasStrings ? pb.string : nil
        if board == nil, pb.numberOfItems > 0 {
            throw ClipboardUnreadable(items: pb.numberOfItems, hasStrings: pb.hasStrings, types: pb.types, changeCount: pb.changeCount)
        }
        let cur = await node.current
        let usable = await node.usable
        if let cur, let u = usable, cur.origin != g.device, cur.via == .copy, cur.ageMS < Self.recentCopyMS, u.text != board {
            write(u.text, kind: u.kind)
            return .fetched
        }
        if let t = board, !t.isEmpty, t != usable?.text {
            guard await connected(node) else { throw PendingGroup.Failure.noComputers }
            await node.send(text: t, kind: .text)
            return .sent
        }
        if let u = usable, u.text != board {
            write(u.text, kind: u.kind)
            return .fetched
        }
        if !(await connected(node)) { throw PendingGroup.Failure.noComputers }
        return .nothingNew
    }

    /// Whether a computer is connected, waiting up to connectWait for one:
    /// back from the background, the connections iOS dropped take a moment
    /// to come back. Keeps online, and so the dots, in step.
    private func connected(_ node: MemberNode) async -> Bool {
        let deadline = ContinuousClock.now + Self.connectWait
        while true {
            online = await node.connected
            if !online.isEmpty || ContinuousClock.now >= deadline { return !online.isEmpty }
            try? await Task.sleep(for: .milliseconds(250))
        }
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
