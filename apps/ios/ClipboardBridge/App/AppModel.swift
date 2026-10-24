// SPDX-License-Identifier: AGPL-3.0-only

import ClipboardBridgeKit
import Foundation
import os
import SwiftUI

private let log = Logger(subsystem: "io.github.hunterewok.clipboardbridge", category: "app")

/// The group as the app sees it: whether there is one, its computers,
/// admitting a device and joining another phone's group. LiveGroup is the
/// real one; PendingGroup stands in for previews.
@MainActor
protocol GroupController: AnyObject {
    var hasGroup: Bool { get }
    /// Whether this phone may add and remove devices.
    var isAdmin: Bool { get }
    var computers: [AppModel.Computer] { get }
    /// Every device of the group, this phone included.
    var devices: [AppModel.Computer] { get }
    /// Makes this phone's own key, which proves it to the other devices,
    /// unless it has one.
    func prepare() throws
    /// Removes a device from the group.
    func remove(_ id: String) async throws
    /// Makes a computer an admin; only the root phone does.
    func makeAdmin(_ id: String) async throws
    /// Unfreezes an admin computer that another admin froze.
    func unfreeze(_ id: String) async throws
    /// Admits the device whose QR code the user scanned.
    func admit(_ code: JoinCode) async throws
    /// Joins another phone's group: listens, hands show the QR code for the
    /// other phone to scan, and returns once this phone is in the group.
    func join(show: @escaping @MainActor (JoinCode) -> Void) async throws
    /// Sends what this phone holds, or fetches the computers' recent copy.
    func sync() async throws -> AppModel.SyncResult
    /// Updates which computers are online.
    func refresh() async
    /// Sync away from home: whether it is on, where it stands and its last
    /// failure; nil without a group.
    func awayStatus() async -> (on: Bool, status: AwayFromHome.Status, error: Error?)?
    /// Turns sync away from home on or off.
    func setAwayFromHome(_ on: Bool) async throws
}

extension GroupController {
    func unfreeze(_ id: String) async throws {}
    func awayStatus() async -> (on: Bool, status: AwayFromHome.Status, error: Error?)? { nil }
    func setAwayFromHome(_ on: Bool) async throws {}
}

/// What the app shows and does; the views only read it and call it.
@MainActor
final class AppModel: ObservableObject {
    /// The one model of the running app, which the Shortcuts action uses
    /// too.
    static let shared = AppModel(group: LiveGroup())

    enum Phase: Equatable { case start, joining, home }

    /// A device of the group: a computer, or this phone.
    struct Computer: Identifiable, Equatable {
        let id: String
        var name: String
        var online: Bool
        /// "full", "phone", "lite" or "shortcut".
        var role = "full"
        /// Its operating system; nil when its record does not tell.
        var os: String?
        var isSelf = false
        /// An admin phone: it may add and remove devices.
        var admin = false
        /// The phone that holds the group's root.
        var isRoot = false
        /// A computer this phone, the root, can make an admin: it offers an
        /// admin key.
        var canMakeAdmin = false
        /// An admin computer another admin froze: the root or an admin phone
        /// unfreezes or removes it.
        var frozen = false
    }

    enum SyncResult: Equatable { case sent, fetched, nothingNew }

    enum ScanResult: Equatable {
        case joinCode(JoinCode)
        case notClipboardBridge
    }

    @Published private(set) var phase: Phase
    @Published private(set) var computers: [Computer] = []
    @Published private(set) var devices: [Computer] = []
    /// One line about the last action, in plain words.
    @Published var message: String?
    @Published private(set) var busy = false
    /// The QR code this phone shows while it waits to join a group.
    @Published private(set) var joinCode: JoinCode?
    @Published private(set) var isAdmin = true
    /// The one-time note on the Start screen that this phone is ready.
    @Published private(set) var welcome = false

    /// Sync away from home as Settings shows it: nil without a group.
    struct Away: Equatable {
        var on: Bool
        var status: AwayFromHome.Status
        /// The last failure while it is still trying, in words.
        var error: String?
    }

    @Published private(set) var away: Away?
    /// What turning it on or off said, when it failed.
    @Published private(set) var awayNote: String?

    let group: GroupController
    private let defaults: UserDefaults
    static let welcomedKey = "welcomed"

    /// nil means PendingGroup, made here because a default argument is
    /// evaluated outside the main actor.
    init(group: GroupController? = nil, defaults: UserDefaults = .standard) {
        let group = group ?? PendingGroup()
        self.group = group
        self.defaults = defaults
        phase = group.hasGroup ? .home : .start
        computers = group.computers
        devices = group.devices
        isAdmin = group.isAdmin
    }

    /// Reads what the camera saw, or what the user typed: the text of the QR
    /// code of cbb pair.
    nonisolated static func read(scanned text: String) -> ScanResult {
        guard let jc = JoinCode(qr: text), jc.codeIsValid, !jc.addrs.isEmpty, !jc.fingerprint.isEmpty else { return .notClipboardBridge }
        return .joinCode(jc)
    }

    /// Admits a scanned computer; on success the app goes Home.
    func scanned(_ text: String) async -> Bool {
        guard case let .joinCode(jc) = Self.read(scanned: text) else {
            message = String(localized: "Not a clipboardbridge QR code.", bundle: .app)
            return false
        }
        busy = true
        defer { busy = false }
        do {
            try await group.admit(jc)
            computers = group.computers
            devices = group.devices
            phase = .home
            message = nil
            return true
        } catch is CancellationError {
            return false
        } catch {
            message = Self.describe(error)
            return false
        }
    }

    /// At the first launch: makes this phone's own key and says so once,
    /// with what to do next.
    func prepare() {
        guard phase == .start, !defaults.bool(forKey: Self.welcomedKey) else { return }
        do {
            try group.prepare()
            welcome = true
        } catch {
            message = Self.describe(error)
        }
    }

    /// Hides the note for good.
    func dismissWelcome() {
        welcome = false
        defaults.set(true, forKey: Self.welcomedKey)
    }

    /// Opens the screen that joins another phone's group.
    func startJoining() {
        dismissWelcome()
        message = nil
        phase = .joining
    }

    /// Joins another phone's group: shows this phone's QR code until an
    /// admin phone scans it, then goes Home. The join screen runs it as its
    /// task, so leaving the screen cancels it and stops listening.
    func join() async {
        do {
            try await group.join { [weak self] code in self?.joinCode = code }
            computers = group.computers
            devices = group.devices
            isAdmin = group.isAdmin
            phase = .home
        } catch is CancellationError {
        } catch {
            message = Self.describe(error)
        }
        joinCode = nil
    }

    /// Leaves the join screen without joining.
    func cancelJoin() {
        joinCode = nil
        message = nil
        phase = .start
    }

    /// The one big button.
    func sync() async {
        busy = true
        defer { busy = false }
        do {
            switch try await group.sync() {
            case .sent: message = String(localized: "Sent to the computers.", bundle: .app)
            case .fetched: message = String(localized: "Fetched from the computers.", bundle: .app)
            case .nothingNew: message = String(localized: "Nothing new to send or fetch.", bundle: .app)
            }
        } catch {
            message = Self.describe(error)
        }
        computers = group.computers
    }

    /// The sync the Shortcuts action runs, with the app perhaps just
    /// started for it: the Home button's, after waiting up to wait for a
    /// computer to connect. Returns what it says.
    func syncFromShortcut(wait: Duration = .seconds(5)) async -> String {
        let deadline = ContinuousClock.now + wait
        while group.hasGroup, ContinuousClock.now < deadline {
            await refresh()
            if computers.contains(where: \.online) { break }
            try? await Task.sleep(for: .milliseconds(250))
        }
        await sync()
        return message ?? ""
    }

    /// Updates which computers are online.
    func refresh() async {
        await group.refresh()
        computers = group.computers
        devices = group.devices
        await refreshAway()
    }

    private func refreshAway() async {
        guard let a = await group.awayStatus() else {
            away = nil
            return
        }
        // The last failure only while it is still trying; once connected or
        // at home it is old news. AwayFromHome logs each failure itself.
        let failing = a.status == .connecting ? a.error : nil
        away = Away(on: a.on, status: a.status, error: failing.map {
            Self.describe($0, summary: String(localized: "The hub does not answer through the tunnel.", bundle: .app), log: false)
        })
    }

    /// Turns sync away from home on or off; the hub's answer comes on the
    /// next connection at home.
    func setAway(_ on: Bool) async {
        do {
            try await group.setAwayFromHome(on)
            awayNote = nil
        } catch {
            awayNote = Self.describe(error)
        }
        await refreshAway()
    }

    /// Removes a device from the group.
    func remove(_ id: String) async {
        do {
            try await group.remove(id)
            message = String(localized: "Removed. The other devices refuse it from now on.", bundle: .app)
        } catch {
            message = Self.describe(error)
        }
        computers = group.computers
        devices = group.devices
        isAdmin = group.isAdmin
    }

    /// Unfreezes an admin computer that another admin froze.
    func unfreeze(_ id: String) async {
        do {
            try await group.unfreeze(id)
            message = String(localized: "It is an admin again.", bundle: .app)
        } catch {
            message = Self.describe(error)
        }
        devices = group.devices
    }

    /// Makes a computer an admin.
    func makeAdmin(_ id: String) async {
        do {
            try await group.makeAdmin(id)
            message = String(localized: "It is an admin now: it adds and removes devices with cbb pair and cbb revoke.", bundle: .app)
        } catch {
            message = Self.describe(error)
        }
        devices = group.devices
    }

    /// Whether a message names the error underneath, to find out what
    /// failed: on in debug builds, off in release ones, and either way the
    /// ShowErrorDetails default when it is set (in Xcode, the launch
    /// argument -ShowErrorDetails YES or NO).
    nonisolated static var showsErrorDetails: Bool {
        if let set = UserDefaults.standard.object(forKey: "ShowErrorDetails") as? Bool { return set }
        #if DEBUG
        return true
        #else
        return false
        #endif
    }

    /// The message for an error, with the error itself below it when
    /// details is set. The error is logged either way.
    static func describe(_ error: Error, details: Bool = showsErrorDetails, summary given: String? = nil, log logs: Bool = true) -> String {
        let text = given ?? summary(error), detail = String(reflecting: error)
        if logs { log.error("\(text, privacy: .public) \(detail, privacy: .public)") }
        return details ? text + "\n\n" + detail : text
    }

    private static func summary(_ error: Error) -> String {
        if let f = error as? PendingGroup.Failure {
            return f == .notReady ? String(localized: "Adding a computer is not ready yet.", bundle: .app) : String(localized: "No computers connected.", bundle: .app)
        }
        if let f = error as? PairingMember.Failure {
            if case .refused(.wrongCode) = f {
                return String(localized: "The code did not match. Run cbb pair on the computer again and scan the new code.", bundle: .app)
            }
            return String(localized: "The computer refused. Run cbb pair on it again.", bundle: .app)
        }
        if let f = error as? LiveGroup.Failure, f == .notConfirmed {
            return String(localized: "The computer joined but did not confirm it. Check cbb status on it.", bundle: .app)
        }
        if let f = error as? LiveGroup.Failure {
            switch f {
            case .noNetwork: return String(localized: "Connect this phone to your home Wi-Fi, then try again.", bundle: .app)
            case .timedOut: return String(localized: "No phone scanned the code in five minutes. Try again.", bundle: .app)
            case .tooManyWrongCodes: return String(localized: "Too many wrong codes. Try again with a new code.", bundle: .app)
            case .notAdmin: return String(localized: "Only an admin phone can do this.", bundle: .app)
            default: break
            }
        }
        if let f = error as? PhoneGroup.Failure, f == .cannotRemoveRoot {
            return String(localized: "The phone that made the group cannot be removed yet.", bundle: .app)
        }
        if error is PairingJoiner.Failure {
            return String(localized: "The other phone's group could not be joined. Try again.", bundle: .app)
        }
        if error is LiveGroup.Failure || error is TLSTransport.Failure {
            return String(localized: "Could not reach the computer. Is it on the same network as this phone, and does its firewall let clipboardbridge in?", bundle: .app)
        }
        return String(localized: "Something went wrong. Try again.", bundle: .app)
    }
}

/// Stands in for the group in previews and tests: no group, no computers.
@MainActor
final class PendingGroup: GroupController {
    enum Failure: Error { case notReady, noComputers }
    var hasGroup: Bool { false }
    var isAdmin: Bool { true }
    var computers: [AppModel.Computer] { [] }
    var devices: [AppModel.Computer] { [] }
    func prepare() throws {}
    func remove(_ id: String) async throws {}
    func makeAdmin(_ id: String) async throws {}
    func admit(_ code: JoinCode) async throws { throw Failure.notReady }
    func join(show: @escaping @MainActor (JoinCode) -> Void) async throws { throw Failure.notReady }
    func sync() async throws -> AppModel.SyncResult { throw Failure.noComputers }
    func refresh() async {}
}
