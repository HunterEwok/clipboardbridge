// SPDX-License-Identifier: AGPL-3.0-only

import Foundation
import os
import WatchConnectivity

private let log = Logger(subsystem: "io.github.hunterewok.clipboardbridge.watch", category: "watch")

/// The group as the phone last told it, and the away switch, which asks
/// the phone.
@MainActor
final class WatchModel: NSObject, ObservableObject {
    @Published private(set) var state = WatchState()
    /// Whether the phone answers now; the state may be old without it.
    @Published private(set) var reachable = false
    @Published private(set) var switching = false
    /// What the last switch said, when it failed.
    @Published private(set) var note: String?

    override init() {
        super.init()
        guard WCSession.isSupported() else { return }
        WCSession.default.delegate = self
        WCSession.default.activate()
    }

    /// Turns the phone's sync away from home on or off, as its Settings do.
    func setAway(_ on: Bool) {
        let session = WCSession.default
        guard session.isReachable else {
            note = String(localized: "Open Clipboard Bridge on the iPhone, then try again.")
            return
        }
        switching = true
        note = nil
        session.sendMessage([WatchState.awayKey: on], replyHandler: { reply in
            let s = WatchState(reply)
            Task { @MainActor in
                if let s { self.state = s }
                self.switching = false
            }
        }, errorHandler: { error in
            log.error("away not switched: \(String(reflecting: error), privacy: .public)")
            Task { @MainActor in
                self.switching = false
                self.note = String(localized: "The iPhone did not answer. Try again.")
            }
        })
    }

    private func take(_ context: [String: Any]) {
        if let s = WatchState(context) { state = s }
    }
}

extension WatchModel: WCSessionDelegate {
    nonisolated func session(_ session: WCSession, activationDidCompleteWith state: WCSessionActivationState, error: Error?) {
        if let error { log.error("watch session: \(String(reflecting: error), privacy: .public)") }
        let context = session.receivedApplicationContext, reachable = session.isReachable
        nonisolated(unsafe) let c = context
        Task { @MainActor in
            self.take(c)
            self.reachable = reachable
        }
    }

    nonisolated func session(_ session: WCSession, didReceiveApplicationContext context: [String: Any]) {
        nonisolated(unsafe) let c = context
        Task { @MainActor in self.take(c) }
    }

    nonisolated func sessionReachabilityDidChange(_ session: WCSession) {
        let reachable = session.isReachable
        Task { @MainActor in self.reachable = reachable }
    }
}
