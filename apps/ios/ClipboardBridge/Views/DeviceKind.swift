// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// What a device is, for its icon: SF Symbols, which Apple licenses for
/// apps on its platforms.
enum DeviceKind: String, CaseIterable {
    case laptop, desktop, phone, tablet, tv, board, server, router, console, watch, retro, other

    var symbol: String {
        switch self {
        case .laptop: "laptopcomputer"
        case .desktop: "desktopcomputer"
        case .phone: "iphone"
        case .tablet: "ipad"
        case .tv: "tv"
        case .board: "cpu"
        case .server: "server.rack"
        case .router: "wifi.router"
        case .console: "gamecontroller"
        case .watch: "applewatch"
        case .retro: "keyboard"
        case .other: "shippingbox"
        }
    }

    var title: LocalizedStringKey {
        switch self {
        case .laptop: "Laptop"
        case .desktop: "Computer"
        case .phone: "Phone"
        case .tablet: "Tablet"
        case .tv: "TV"
        case .board: "Board"
        case .server: "Server"
        case .router: "Router"
        case .console: "Game console"
        case .watch: "Watch"
        case .retro: "Retro computer"
        case .other: "Device"
        }
    }
}

extension AppModel.Computer {
    /// Its kind as its role and system tell: a Mac is taken for a laptop,
    /// another computer for a desktop, until devices say what they are.
    var kind: DeviceKind {
        switch (role, os) {
        case ("phone", _), ("shortcut", _): .phone
        case ("lite", _): .board
        case (_, "macos"): .laptop
        case (_, "ios"), (_, "android"): .phone
        default: .desktop
        }
    }

    /// The name of its operating system, the same in every language; nil
    /// when the records do not tell, or for firmware.
    var system: String? {
        switch os {
        case "linux": "Linux"
        case "windows": "Windows"
        case "macos": "macOS"
        case "ios": "iOS"
        case "android": "Android"
        default: nil
        }
    }

    /// Its place in the group, in a word; nil for a plain member.
    var standing: LocalizedStringKey? {
        if isSelf { return admin ? "This phone · admin" : "This phone" }
        if frozen { return "frozen" }
        if isRoot { return "root" }
        if admin { return "admin" }
        return nil
    }
}

/// A device's icon on a soft square, bright while it is online.
struct DeviceIcon: View {
    let device: AppModel.Computer
    var size: CGFloat = 44
    @Environment(\.palette) private var palette

    var body: some View {
        Image(systemName: device.kind.symbol)
            .font(.system(size: size * 0.48, weight: .medium))
            .frame(width: size, height: size)
            .foregroundStyle(device.online ? palette.accent : palette.textDim)
            .background(device.online ? palette.soft : palette.line, in: RoundedRectangle(cornerRadius: size * 0.3, style: .continuous))
            .accessibilityHidden(true)
    }
}

/// The live dot: the accent while online, dim while not.
struct OnlineDot: View {
    let online: Bool
    @Environment(\.palette) private var palette

    var body: some View {
        Circle().fill(online ? palette.accent : palette.textDim).frame(width: 8, height: 8)
            .accessibilityHidden(true)
    }
}
