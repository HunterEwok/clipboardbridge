// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// The whole group: every device with its role, whether it is online, this
/// phone marked as the admin; a device can be removed (docs/apps.md,
/// Devices).
struct DevicesView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette
    @State private var removing: AppModel.Computer?

    var body: some View {
        List {
            if model.devices.isEmpty {
                Text("No computers connected.").foregroundStyle(palette.textDim)
            }
            ForEach(model.devices) { d in
                HStack(spacing: Tokens.spacingMedium) {
                    Image(systemName: icon(d.role)).foregroundStyle(d.online ? palette.accent : palette.textDim)
                    VStack(alignment: .leading) {
                        Text(d.name).font(.system(.body, design: .monospaced))
                        if d.isSelf {
                            Text("This phone · admin").font(.caption).foregroundStyle(palette.textDim)
                        }
                    }
                    Spacer()
                    (d.online ? Text("online") : Text("offline"))
                        .font(.caption)
                        .foregroundStyle(d.online ? palette.accent : palette.textDim)
                }
                .accessibilityElement(children: .combine)
                .swipeActions {
                    if !d.isSelf {
                        Button(role: .destructive) { removing = d } label: { Text("Remove") }
                    }
                }
                .contextMenu {
                    if !d.isSelf {
                        Button(role: .destructive) { removing = d } label: { Text("Remove") }
                    }
                }
                .listRowBackground(palette.surface)
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
            Text("It will no longer sync with your devices. To add it again, scan its QR code again.")
        }
    }

    private func icon(_ role: String) -> String {
        switch role {
        case "mac": "laptopcomputer"
        case "phone", "iphone": "iphone"
        default: "desktopcomputer"
        }
    }
}
