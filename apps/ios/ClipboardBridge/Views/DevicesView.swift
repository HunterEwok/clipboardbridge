// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// The whole group: every device with its role, whether it is online, the
/// admin phones marked; on an admin phone a device can be removed
/// (docs/apps.md, Devices).
struct DevicesView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette
    @State private var removing: AppModel.Computer?
    @State private var promoting: AppModel.Computer?

    var body: some View {
        List {
            if model.devices.isEmpty {
                Text("No computers connected.").foregroundStyle(palette.textDim)
            }
            ForEach(model.devices) { d in
                HStack(spacing: Tokens.spacingMedium) {
                    Image(systemName: icon(d)).foregroundStyle(d.online ? palette.accent : palette.textDim)
                    VStack(alignment: .leading) {
                        Text(d.name).font(.system(.body, design: .monospaced))
                        if let system = Self.system(d.os) {
                            Text(verbatim: system).font(.caption).foregroundStyle(palette.textDim)
                        }
                        if d.isSelf {
                            (d.admin ? Text("This phone · admin") : Text("This phone")).font(.caption).foregroundStyle(palette.textDim)
                        } else if d.admin {
                            Text("admin").font(.caption).foregroundStyle(palette.textDim)
                        }
                    }
                    Spacer()
                    (d.online ? Text("online") : Text("offline"))
                        .font(.caption)
                        .foregroundStyle(d.online ? palette.accent : palette.textDim)
                }
                .accessibilityElement(children: .combine)
                .swipeActions {
                    if canRemove(d) {
                        Button(role: .destructive) { removing = d } label: { Text("Remove") }
                    }
                    if d.canMakeAdmin {
                        Button { promoting = d } label: { Text("Make it an admin") }
                    }
                }
                .contextMenu {
                    if d.canMakeAdmin {
                        Button { promoting = d } label: { Text("Make it an admin") }
                    }
                    if canRemove(d) {
                        Button(role: .destructive) { removing = d } label: { Text("Remove") }
                    }
                }
                .listRowBackground(palette.surface)
            }
            if !model.isAdmin {
                Text("Only an admin phone can add or remove devices.").foregroundStyle(palette.textDim).listRowBackground(Color.clear)
            } else if model.devices.filter({ $0.admin }).count == 1 {
                Text("Lost a phone? Make a second phone an admin: on it, tap I already use clipboardbridge on another phone, then scan its code here with +.")
                    .foregroundStyle(palette.textDim).listRowBackground(Color.clear)
            }
            if let message = model.message {
                Text(message).foregroundStyle(palette.textDim).listRowBackground(Color.clear)
            }
        }
        .scrollContentBackground(.hidden)
        .background(GridBackground())
        .navigationTitle(Text("Devices"))
        .confirmationDialog(Text("Remove \(removing?.name ?? "")?"), isPresented: Binding(
            get: { removing != nil }, set: { if !$0 { removing = nil } }
        ), titleVisibility: .visible) {
            Button(role: .destructive) {
                if let d = removing { Task { await model.remove(d.id) } }
                removing = nil
            } label: { Text("Remove") }
        } message: {
            if removing?.isRoot == true {
                Text("It made the group. This phone takes the group over with a new key, and the other devices follow it.")
            } else {
                Text("It will no longer sync with your devices. To add it again, scan its QR code again.")
            }
        }
        .confirmationDialog(Text("Make \(promoting?.name ?? "") an admin?"), isPresented: Binding(
            get: { promoting != nil }, set: { if !$0 { promoting = nil } }
        ), titleVisibility: .visible) {
            Button {
                if let d = promoting { Task { await model.makeAdmin(d.id) } }
                promoting = nil
            } label: { Text("Make it an admin") }
        } message: {
            Text("It can then add and remove devices with cbb pair and cbb revoke. Its key is a file on the computer, so do this only for a computer you keep safe.")
        }
    }

    /// An admin phone removes any device but itself; removing the phone
    /// that holds the group's root hands the group to this phone.
    private func canRemove(_ d: AppModel.Computer) -> Bool { model.isAdmin && !d.isSelf }

    private func icon(_ d: AppModel.Computer) -> String {
        switch (d.role, d.os) {
        case ("phone", _), ("shortcut", _): "iphone"
        case ("lite", _): "cpu"
        case (_, "macos"): "laptopcomputer"
        default: "desktopcomputer"
        }
    }

    /// The name of a device's operating system, the same in every language;
    /// nil when the records do not tell, or for firmware.
    static func system(_ os: String?) -> String? {
        switch os {
        case "linux": "Linux"
        case "windows": "Windows"
        case "macos": "macOS"
        case "ios": "iOS"
        case "android": "Android"
        default: nil
        }
    }
}
