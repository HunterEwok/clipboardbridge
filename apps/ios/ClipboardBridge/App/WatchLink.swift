// SPDX-License-Identifier: AGPL-3.0-only

import Foundation
import os
import WatchConnectivity

private let log = Logger(subsystem: "io.github.hunterewok.clipboardbridge", category: "watch")

/// The phone's side of the Apple Watch app: it hands the watch the group as
/// the app sees it, and turns sync away from home on or off when the watch
/// asks (docs/apps.md, Apple Watch).
@MainActor
final class WatchLink: NSObject {
    static let shared = WatchLink()

    private var session: WCSession? { WCSession.isSupported() ? WCSession.default : nil }
    private var last: WatchState?

    /// Starts the session once; a phone without a paired watch has nothing
    /// to send to.
    func start() {
        guard let session, session.delegate == nil else { return }
        session.delegate = self
        session.activate()
    }

    /// Sends the state when it changed and a watch app is there to read it.
    func update(_ model: AppModel) {
        start()
        let state = Self.state(model)
        guard state != last, let session, session.activationState == .activated, session.isWatchAppInstalled else { return }
        do {
            try session.updateApplicationContext(state.data)
            last = state
        } catch {
            log.error("watch not updated: \(String(reflecting: error), privacy: .public)")
        }
    }

    func eventsChanged() {
        update(AppModel.shared)
    }

    static func state(_ model: AppModel) -> WatchState {
        var s = WatchState()
        s.hasGroup = model.phase == .home
        s.devices = model.devices.filter { !$0.isSelf }.map {
            WatchState.Device(id: $0.id, name: $0.name, symbol: $0.kind.symbol, online: $0.online)
        }
        s.away = model.away.map { a in
            guard a.on else { return .off }
            switch a.status {
            case .atHome: return .atHome
            case .connecting: return .connecting
            case .connected: return .connected
            case .off, .waitingForHub: return .waiting
            }
        }
        s.events = Notifier.shared.recent
        s.color = UserDefaults.standard.string(forKey: AccentChoice.key) ?? Tokens.colors[0].name
        return s
    }
}

extension WatchLink: WCSessionDelegate {
    nonisolated func session(_ session: WCSession, activationDidCompleteWith state: WCSessionActivationState, error: Error?) {
        if let error { log.error("watch session: \(String(reflecting: error), privacy: .public)") }
        Task { @MainActor in self.update(AppModel.shared) }
    }

    nonisolated func sessionDidBecomeInactive(_ session: WCSession) {}

    /// After the user switches to another watch.
    nonisolated func sessionDidDeactivate(_ session: WCSession) {
        session.activate()
    }

    /// The watch's away switch: the same as the one in Settings.
    nonisolated func session(_ session: WCSession, didReceiveMessage message: [String: Any], replyHandler: @escaping ([String: Any]) -> Void) {
        guard let on = message[WatchState.awayKey] as? Bool else { return replyHandler([:]) }
        nonisolated(unsafe) let reply = replyHandler
        Task { @MainActor in
            let model = AppModel.shared
            await model.setAway(on)
            reply(Self.state(model).data)
        }
    }
}
