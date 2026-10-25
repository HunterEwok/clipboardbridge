// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// What the phone tells its watch, through WatchConnectivity: the watch has
/// no network of its own for an ordinary app, so it shows the group as the
/// phone sees it (docs/apps.md, Apple Watch). Never the clipboard.
struct WatchState: Codable, Equatable {
    struct Device: Codable, Equatable, Identifiable {
        var id: String
        var name: String
        /// An SF Symbol for its kind.
        var symbol: String
        var online: Bool
    }

    /// Where sync away from home stands, as the phone's Settings say it.
    enum Away: String, Codable {
        case off, atHome, connecting, connected, waiting
    }

    var hasGroup = false
    var devices: [Device] = []
    /// nil without a group.
    var away: Away?
    /// The latest events, newest first.
    var events: [String] = []
    /// The phone's colour, by its name in Tokens.colors.
    var color = "terminal"

    static let key = "state"
    /// The message that turns the phone's sync away from home on or off.
    static let awayKey = "away"

    var data: [String: Any] {
        (try? JSONEncoder().encode(self)).map { [Self.key: $0] } ?? [:]
    }

    init() {}

    init?(_ data: [String: Any]) {
        guard let d = data[Self.key] as? Data, let s = try? JSONDecoder().decode(Self.self, from: d) else { return nil }
        self = s
    }
}
