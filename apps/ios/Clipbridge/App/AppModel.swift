// SPDX-License-Identifier: AGPL-3.0-only

import ClipbridgeKit
import Foundation
import os
import SwiftUI

private let log = Logger(subsystem: "io.github.hunterewok.clipbridge", category: "app")

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
    /// Removes a device from the group.
    func remove(_ id: String) async throws
    /// Makes a computer an admin; only the root phone does.
    func makeAdmin(_ id: String) async throws
    /// Admits the device whose QR code the user scanned.
    func admit(_ code: JoinCode) async throws
    /// Joins another phone's group: listens, hands show the QR code for the
    /// other phone to scan, and returns once this phone is in the group.
    func join(show: @escaping @MainActor (JoinCode) -> Void) async throws
    /// Sends what this phone holds, or fetches the computers' recent copy.
    func sync() async throws -> AppModel.SyncResult
    /// Updates which computers are online.
    func refresh() async
}

/// What the app shows and does; the views only read it and call it.
@MainActor
final class AppModel: ObservableObject {
    enum Phase: Equatable { case start, joining, home }

    /// A device of the group: a computer, or this phone.
    struct Computer: Identifiable, Equatable {
        let id: String
        var name: String
        var online: Bool
        var role = "linux"
        var isSelf = false
        /// An admin phone: it may add and remove devices.
        var admin = false
        /// The phone that holds the group's root.
        var isRoot = false
        /// A computer this phone, the root, can make an admin: it offers an
        /// admin key.
        var canMakeAdmin = false
    }

    enum SyncResult: Equatable { case sent, fetched, nothingNew }

    enum ScanResult: Equatable {
        case joinCode(JoinCode)
        case notClipbridge
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

    let group: GroupController

    /// nil means PendingGroup, made here because a default argument is
    /// evaluated outside the main actor.
    init(group: GroupController? = nil) {
        let group = group ?? PendingGroup()
        self.group = group
        phase = group.hasGroup ? .home : .start
        computers = group.computers
        devices = group.devices
        isAdmin = group.isAdmin
    }

    /// Reads what the camera saw, or what the user typed: the text of the QR
    /// code of clipbridge join.
    nonisolated static func read(scanned text: String) -> ScanResult {
        guard let jc = JoinCode(qr: text), jc.codeIsValid, !jc.addrs.isEmpty, !jc.fingerprint.isEmpty else { return .notClipbridge }
        return .joinCode(jc)
    }

    /// Admits a scanned computer; on success the app goes Home.
    func scanned(_ text: String) async -> Bool {
        guard case let .joinCode(jc) = Self.read(scanned: text) else {
            message = String(localized: "Not a clipbridge QR code.")
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
        } catch {
            message = Self.describe(error)
            return false
        }
    }

    /// Opens the screen that joins another phone's group.
    func startJoining() {
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
            case .sent: message = String(localized: "Sent to the computers.")
            case .fetched: message = String(localized: "Fetched from the computers.")
            case .nothingNew: message = String(localized: "Nothing new to send or fetch.")
            }
        } catch {
            message = Self.describe(error)
        }
        computers = group.computers
    }

    /// Updates which computers are online.
    func refresh() async {
        await group.refresh()
        computers = group.computers
        devices = group.devices
    }

    /// Removes a device from the group.
    func remove(_ id: String) async {
        do {
            try await group.remove(id)
            message = String(localized: "Removed. The other devices refuse it from now on.")
        } catch {
            message = Self.describe(error)
        }
        computers = group.computers
        devices = group.devices
        isAdmin = group.isAdmin
    }

    /// Makes a computer an admin.
    func makeAdmin(_ id: String) async {
        do {
            try await group.makeAdmin(id)
            message = String(localized: "It is an admin now: it adds and removes devices with clipbridge pair and clipbridge revoke.")
        } catch {
            message = Self.describe(error)
        }
        devices = group.devices
    }

    static func describe(_ error: Error) -> String {
        if let f = error as? PendingGroup.Failure {
            return f == .notReady ? String(localized: "Adding a computer is not ready yet.") : String(localized: "No computers connected.")
        }
        if let f = error as? PairingMember.Failure {
            if case .refused(.wrongCode) = f {
                return String(localized: "The code did not match. Run clipbridge join on the computer again and scan the new code.")
            }
            return String(localized: "The computer refused. Run clipbridge join on it again.")
        }
        if let f = error as? LiveGroup.Failure, f == .notConfirmed {
            return String(localized: "The computer joined but did not confirm it. Check clipbridge status on it.")
        }
        if let f = error as? LiveGroup.Failure {
            switch f {
            case .noNetwork: return String(localized: "Connect this phone to your home Wi-Fi, then try again.")
            case .timedOut: return String(localized: "No phone scanned the code in five minutes. Try again.")
            case .tooManyWrongCodes: return String(localized: "Too many wrong codes. Try again with a new code.")
            case .notAdmin: return String(localized: "Only an admin phone can do this.")
            default: break
            }
        }
        if let f = error as? PhoneGroup.Failure, f == .cannotRemoveRoot {
            return String(localized: "The phone that made the group cannot be removed yet.")
        }
        if error is PairingJoiner.Failure {
            return String(localized: "The other phone's group could not be joined. Try again.")
        }
        if error is LiveGroup.Failure || error is TLSTransport.Failure {
            return String(localized: "Could not reach the computer. Is it on the same network as this phone?")
        }
        // Any other error is unexpected: name it, so that a report says
        // what failed.
        let detail = String(reflecting: error)
        log.error("unexpected error: \(detail, privacy: .public)")
        return String(localized: "Something went wrong (\(detail)). Try again.")
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
    func remove(_ id: String) async throws {}
    func makeAdmin(_ id: String) async throws {}
    func admit(_ code: JoinCode) async throws { throw Failure.notReady }
    func join(show: @escaping @MainActor (JoinCode) -> Void) async throws { throw Failure.notReady }
    func sync() async throws -> AppModel.SyncResult { throw Failure.noComputers }
    func refresh() async {}
}
