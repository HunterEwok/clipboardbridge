// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// One device: a summary of what it is and where it stands, then what an
/// admin phone may do with it (docs/apps.md, Devices).
struct DeviceDetailView: View {
    let id: AppModel.Computer.ID
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette
    @Environment(\.dismiss) private var dismiss
    @State private var removing = false
    @State private var promoting = false
    @State private var thawing = false
    @State private var renaming = false
    @State private var newName = ""

    private var device: AppModel.Computer? { model.devices.first { $0.id == id } }

    var body: some View {
        ScrollView {
            if let d = device {
                VStack(alignment: .leading, spacing: Tokens.spacingLarge) {
                    header(d)
                    summary(d)
                    actions(d)
                    if let message = model.message {
                        Text(message).foregroundStyle(palette.textDim)
                    }
                }
                .padding(Tokens.spacingLarge)
            }
        }
        .background(AppBackground())
        .navigationTitle(Text(verbatim: device?.name ?? ""))
        .navigationBarTitleDisplayMode(.inline)
        .onChange(of: device == nil) { _, gone in
            // Removed here or by another admin: back to the devices.
            if gone { dismiss() }
        }
        .confirmationDialog(Text("Remove \(device?.name ?? "")?"), isPresented: $removing, titleVisibility: .visible) {
            Button(role: .destructive) {
                Task { await model.remove(id) }
            } label: { Text("Remove") }
        } message: {
            if device?.isRoot == true {
                Text("It made the group. This phone takes the group over with a new key, and the other devices follow it.")
            } else {
                Text("It will no longer sync with your devices. To add it again, scan its QR code again.")
            }
        }
        .confirmationDialog(Text("Make \(device?.name ?? "") an admin?"), isPresented: $promoting, titleVisibility: .visible) {
            Button {
                Task { await model.makeAdmin(id) }
            } label: { Text("Make it an admin") }
        } message: {
            Text("It can then add and remove devices with cbb pair and cbb revoke. Its key is a file on the computer, so do this only for a computer you keep safe.")
        }
        .alert(Text("Rename \(device?.name ?? "")"), isPresented: $renaming) {
            TextField(text: $newName) { Text("Name") }
            Button {
                Task { await model.rename(id, to: newName) }
            } label: { Text("Rename") }
            Button(role: .cancel) {} label: { Text("Cancel") }
        } message: {
            Text("Every device of the group shows the new name.")
        }
        .confirmationDialog(Text("Unfreeze \(device?.name ?? "")?"), isPresented: $thawing, titleVisibility: .visible) {
            Button {
                Task { await model.unfreeze(id) }
            } label: { Text("Unfreeze") }
        } message: {
            Text("Another admin froze this computer, as one does with a stolen one: it changes nothing and the others refuse it. Unfreeze it only if it is in safe hands; otherwise remove it.")
        }
    }

    private func header(_ d: AppModel.Computer) -> some View {
        HStack(spacing: Tokens.spacingMedium) {
            DeviceIcon(device: d, size: 64)
            VStack(alignment: .leading, spacing: 4) {
                Text(d.name).font(.system(.title2, design: .monospaced).weight(.bold)).lineLimit(2)
                HStack(spacing: 6) {
                    OnlineDot(online: d.online)
                    (d.online ? Text("online") : Text("offline"))
                        .foregroundStyle(d.online ? palette.accent : palette.textDim)
                }
                .font(.subheadline)
            }
        }
        .accessibilityElement(children: .combine)
    }

    /// What the group knows of it, a row each.
    private func summary(_ d: AppModel.Computer) -> some View {
        VStack(spacing: 0) {
            row(Text("Type"), Text(d.kind.title))
            if let system = d.system {
                Divider().overlay(palette.line)
                row(Text("Operating system"), Text(verbatim: system))
            }
            Divider().overlay(palette.line)
            row(Text("Role"), roleText(d))
            if let standing = d.standing {
                Divider().overlay(palette.line)
                row(Text("In the group"), Text(standing))
            }
        }
        .glassTile(cornerRadius: Tokens.radiusCard)
    }

    private func row(_ label: Text, _ value: Text) -> some View {
        HStack {
            label.foregroundStyle(palette.textDim)
            Spacer()
            value.multilineTextAlignment(.trailing)
        }
        .padding(.horizontal, Tokens.spacingMedium)
        .frame(minHeight: 44)
        .accessibilityElement(children: .combine)
    }

    private func roleText(_ d: AppModel.Computer) -> Text {
        switch d.role {
        case "phone": Text("Phone app")
        case "lite": Text("Lite member")
        case "shortcut": Text("Shortcut")
        default: Text("Full member")
        }
    }

    /// The actions an admin phone has for it; none on a phone that is no
    /// admin.
    @ViewBuilder private func actions(_ d: AppModel.Computer) -> some View {
        if model.isAdmin {
            VStack(spacing: 0) {
                action(Text("Rename"), "pencil") {
                    newName = d.name
                    renaming = true
                }
                if d.frozen {
                    Divider().overlay(palette.line)
                    action(Text("Unfreeze"), "snowflake") { thawing = true }
                }
                if d.canMakeAdmin {
                    Divider().overlay(palette.line)
                    action(Text("Make it an admin"), "person.badge.key") { promoting = true }
                }
                if !d.isSelf {
                    Divider().overlay(palette.line)
                    action(Text("Remove"), "trash", destructive: true) { removing = true }
                }
            }
            .glassTile(cornerRadius: Tokens.radiusCard)
        } else {
            Text("Only an admin phone can add or remove devices.").font(.footnote).foregroundStyle(palette.textDim)
        }
    }

    private func action(_ title: Text, _ symbol: String, destructive: Bool = false, perform: @escaping () -> Void) -> some View {
        Button(action: perform) {
            HStack(spacing: Tokens.spacingMedium) {
                Image(systemName: symbol).frame(width: 24).accessibilityHidden(true)
                title
                Spacer()
            }
            .foregroundStyle(destructive ? palette.danger : palette.accent)
            .padding(.horizontal, Tokens.spacingMedium)
            .frame(minHeight: 48)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}
