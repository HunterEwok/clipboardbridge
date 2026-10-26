// SPDX-License-Identifier: AGPL-3.0-only

import AppKit
import os
import SwiftUI

private let log = Logger(subsystem: "io.github.hunterewok.clipboardbridge.mac", category: "app")

/// What the app knows of the service on this Mac: its status and the
/// group's devices, read from the control socket every few seconds. The
/// clipboard itself syncs without the app, through the pasteboard agent.
@MainActor
final class MacModel: ObservableObject {
    @Published private(set) var status: Control.Status?
    @Published private(set) var devices: [Control.Device] = []
    /// Why the service cannot be reached; nil while it answers.
    @Published private(set) var problem: String?
    /// The outcome of the last action, for a line under it.
    @Published var message: String?
    @Published private(set) var busy = false

    private let client = ControlClient()
    private var timer: Timer?

    var inGroup: Bool { status?.group?.isEmpty == false && status?.removed != true }
    var this: Control.Device? { devices.first { $0.isSelf } }
    var others: [Control.Device] { devices.filter { !$0.isSelf } }
    var isAdmin: Bool { this?.admin == true }
    var isRoot: Bool { this?.root == true }
    var awayOn: Bool { status?.away != nil }

    /// The menu bar's symbol: linked while another device is online.
    var symbol: String {
        if problem != nil || !inGroup { return "clipboard" }
        return others.contains { $0.online } ? "link.circle.fill" : "link.circle"
    }

    func start() {
        guard timer == nil else { return }
        Task { await refresh() }
        timer = Timer.scheduledTimer(withTimeInterval: 4, repeats: true) { [weak self] _ in
            Task { await self?.refresh() }
        }
    }

    func refresh() async {
        do {
            let (answer, _) = try await client.request(.init(op: "status"))
            status = answer.status
            if inGroup {
                devices = try await client.request(.init(op: "devices")).0.devices ?? []
            } else {
                devices = []
            }
            problem = nil
        } catch {
            problem = Self.describe(error)
        }
    }

    /// Sends what the pasteboard holds to the group, as a copy on this Mac.
    func send() async {
        guard let text = NSPasteboard.general.string(forType: .string), !text.isEmpty else {
            message = String(localized: "The clipboard holds no text.")
            return
        }
        await act {
            _ = try await self.client.request(.init(op: "copy"), payload: Data(text.utf8))
            return String(localized: "Sent to the group.")
        }
    }

    /// Puts the group's latest text into the pasteboard.
    func fetch() async {
        await act {
            let (_, body) = try await self.client.request(.init(op: "paste"))
            guard !body.isEmpty else { return String(localized: "The group has no text yet.") }
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(String(decoding: body, as: UTF8.self), forType: .string)
            return String(localized: "Fetched from the group.")
        }
    }

    func rename(_ id: String, to name: String) async {
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else { return }
        await admin(["rename", id, name], done: String(localized: "Renamed."))
    }

    func remove(_ id: String) async { await admin(["revoke", id], done: String(localized: "Removed from the group.")) }
    /// The dialog that asks first warns that the computer's key is a file,
    /// which -allow-file-key consents to.
    func makeAdmin(_ id: String) async { await admin(["admin", "-allow-file-key", id], done: String(localized: "It is an admin now.")) }
    func freeze(_ id: String) async { await admin(["freeze", id], done: String(localized: "Frozen.")) }
    func unfreeze(_ id: String) async { await admin(["unfreeze", id], done: String(localized: "Unfrozen.")) }

    /// Sets the sync mode: this Mac's with id nil, or on an admin another
    /// device's, which cbb sends it as a signed command.
    func setMode(_ mode: SyncMode, on id: String? = nil) async {
        let arguments = id.map { ["mode", "-on", $0, mode.rawValue] } ?? ["mode", mode.rawValue]
        await admin(arguments, done: String(localized: "The sync mode is set."))
    }

    /// Turns sync away from home on or off; on needs the user's yes to the
    /// warning the app showed, which cbb asks for.
    func setAway(_ on: Bool) async {
        await admin(["global", on ? "on" : "off"], answer: on, done: on ? String(localized: "Sync away from home is on.") : String(localized: "Sync away from home is off."))
    }

    private func admin(_ arguments: [String], answer: Bool = false, done: String) async {
        let details = Self.showsErrorDetails
        await act {
            _ = try await Admin.run(arguments, answer: answer, details: details)
            return done
        }
    }

    private func act(_ work: @escaping () async throws -> String) async {
        busy = true
        defer { busy = false }
        do {
            message = try await work()
        } catch Admin.Failure.cancelled {
            message = nil
        } catch {
            message = Self.describe(error)
        }
        await refresh()
    }

    /// Whether a message names the error underneath, to find out what
    /// failed: on in debug builds, off in release ones, and either way the
    /// ShowErrorDetails default when it is set (Settings, or
    /// defaults write io.github.hunterewok.clipboardbridge.mac ShowErrorDetails -bool YES).
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
    nonisolated static func describe(_ error: Error, details: Bool = showsErrorDetails) -> String {
        let (text, detail) = summary(error)
        log.error("\(text, privacy: .public) \(detail, privacy: .public)")
        return details ? text + "\n\n" + detail : text
    }

    nonisolated static func summary(_ error: Error) -> (String, String) {
        switch error {
        case Control.Failure.notRunning(let why):
            return (String(localized: "The Clipboard Bridge service is not running on this Mac. Install it, or start it with sudo launchctl kickstart system/io.github.hunterewok.clipboardbridge."), why)
        case Control.Failure.denied:
            return (String(localized: "No permission to use the service: add your user to the _clipboardbridge group and log in again."), "EACCES")
        case Control.Failure.refused(let text, let detail):
            return (text, detail ?? String(reflecting: error))
        case Admin.Failure.noCommand:
            return (String(localized: "cbb is not installed in /usr/local/bin or /opt/homebrew/bin."), String(reflecting: error))
        case Admin.Failure.failed(let text, let detail):
            return (text, detail)
        default:
            return (String(localized: "The service answered something unexpected."), String(reflecting: error))
        }
    }
}
