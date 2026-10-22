// SPDX-License-Identifier: AGPL-3.0-only

import ClipbridgeKit
import Foundation
import SwiftUI

/// The group as the app sees it: whether there is one, its computers, and
/// admitting a computer. LiveGroup is the real one; PendingGroup stands in
/// for previews.
@MainActor
protocol GroupController: AnyObject {
    var hasGroup: Bool { get }
    var computers: [AppModel.Computer] { get }
    /// Admits the computer whose QR code the user scanned.
    func admit(_ code: JoinCode) async throws
    /// Sends what this phone holds, or fetches the computers' recent copy.
    func sync() async throws -> AppModel.SyncResult
    /// Updates which computers are online.
    func refresh() async
}

/// What the app shows and does; the views only read it and call it.
@MainActor
final class AppModel: ObservableObject {
    enum Phase: Equatable { case start, home }

    struct Computer: Identifiable, Equatable {
        let id: String
        var name: String
        var online: Bool
    }

    enum SyncResult: Equatable { case sent, fetched, nothingNew }

    enum ScanResult: Equatable {
        case joinCode(JoinCode)
        case notClipbridge
    }

    @Published private(set) var phase: Phase
    @Published private(set) var computers: [Computer] = []
    /// One line about the last action, in plain words.
    @Published var message: String?
    @Published private(set) var busy = false

    let group: GroupController

    /// nil means PendingGroup, made here because a default argument is
    /// evaluated outside the main actor.
    init(group: GroupController? = nil) {
        let group = group ?? PendingGroup()
        self.group = group
        phase = group.hasGroup ? .home : .start
        computers = group.computers
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
            phase = .home
            message = nil
            return true
        } catch {
            message = Self.describe(error)
            return false
        }
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
        if error is LiveGroup.Failure || error is TLSTransport.Failure {
            return String(localized: "Could not reach the computer. Is it on the same network as this phone?")
        }
        return String(localized: "Something went wrong. Try again.")
    }
}

/// Stands in for the group in previews and tests: no group, no computers.
@MainActor
final class PendingGroup: GroupController {
    enum Failure: Error { case notReady, noComputers }
    var hasGroup: Bool { false }
    var computers: [AppModel.Computer] { [] }
    func admit(_ code: JoinCode) async throws { throw Failure.notReady }
    func sync() async throws -> AppModel.SyncResult { throw Failure.noComputers }
    func refresh() async {}
}
