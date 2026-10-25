// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// Tiles or a list, as the menu sets it.
enum DeviceLayout: String {
    static let key = "deviceLayout"

    case tiles, list
}

/// The one page: the big button, the result in one line, and every device
/// of the group as tiles or a list; a device opens its details.
struct HomeView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette
    @AppStorage(DeviceLayout.key) private var layout = DeviceLayout.tiles
    @State private var adding = false
    @State private var settings = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: Tokens.spacingLarge) {
                    summary
                    Button {
                        Task { await model.sync() }
                    } label: {
                        Text("Send or fetch")
                    }
                    .buttonStyle(AccentButtonStyle())
                    .disabled(model.busy)
                    .sensoryFeedback(.success, trigger: model.message)

                    if let message = model.message {
                        Text(message).foregroundStyle(palette.textDim)
                    }
                    DeviceCollection(devices: model.devices, layout: layout)
                    hint
                }
                .padding(Tokens.spacingLarge)
            }
            .background(AppBackground())
            .navigationTitle(Text("Clipboard Bridge"))
            .navigationDestination(for: AppModel.Computer.ID.self) { DeviceDetailView(id: $0) }
            .navigationDestination(isPresented: $settings) { SettingsView() }
            .toolbar {
                ToolbarItem(placement: .topBarLeading) { menu }
                ToolbarItem(placement: .topBarTrailing) {
                    if model.isAdmin {
                        Button { adding = true } label: {
                            Image(systemName: "plus").accessibilityLabel(Text("Add a device"))
                        }
                    }
                }
            }
            .sheet(isPresented: $adding) { AddDeviceView() }
            .task {
                // The live dots: which devices are connected now.
                while !Task.isCancelled {
                    await model.refresh()
                    try? await Task.sleep(for: .seconds(2))
                }
            }
        }
    }

    /// How many devices are online, of how many.
    private var summary: some View {
        let online = model.devices.filter(\.online).count
        return Text("\(online) of \(model.devices.count) online")
            .font(.subheadline)
            .foregroundStyle(palette.textDim)
    }

    private var menu: some View {
        Menu {
            Picker(selection: $layout) {
                Label { Text("Tiles") } icon: { Image(systemName: "square.grid.2x2") }.tag(DeviceLayout.tiles)
                Label { Text("List") } icon: { Image(systemName: "list.bullet") }.tag(DeviceLayout.list)
            } label: {
                Text("View")
            }
            .pickerStyle(.inline)
            Button { settings = true } label: {
                Label { Text("Settings") } icon: { Image(systemName: "gearshape") }
            }
        } label: {
            Image(systemName: "ellipsis").accessibilityLabel(Text("Menu"))
        }
    }

    @ViewBuilder private var hint: some View {
        if !model.isAdmin {
            Text("Only an admin phone can add or remove devices.").font(.footnote).foregroundStyle(palette.textDim)
        } else if model.devices.filter({ $0.admin }).count == 1 {
            Text("Lost a phone? Make a second phone an admin: on it, tap I already use Clipboard Bridge on another phone, then scan its code here with +.")
                .font(.footnote).foregroundStyle(palette.textDim)
        }
    }
}

/// The devices as tiles or as a list; each one opens its details.
struct DeviceCollection: View {
    let devices: [AppModel.Computer]
    let layout: DeviceLayout
    @Environment(\.palette) private var palette

    var body: some View {
        if devices.isEmpty {
            Text("No computers connected.").foregroundStyle(palette.textDim)
        } else if layout == .tiles {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), spacing: Tokens.spacingMedium)], spacing: Tokens.spacingMedium) {
                ForEach(devices) { d in
                    NavigationLink(value: d.id) { DeviceTile(device: d) }.buttonStyle(.plain)
                }
            }
        } else {
            VStack(spacing: Tokens.spacingSmall) {
                ForEach(devices) { d in
                    NavigationLink(value: d.id) { DeviceRow(device: d) }.buttonStyle(.plain)
                }
            }
        }
    }
}

/// A device as a tile: its icon and live dot, its name, its system and
/// where it stands.
struct DeviceTile: View {
    let device: AppModel.Computer

    var body: some View {
        VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
            HStack(alignment: .top) {
                DeviceIcon(device: device)
                Spacer()
                OnlineDot(online: device.online)
            }
            Text(device.name)
                .font(.system(.headline, design: .monospaced))
                .lineLimit(1)
            DeviceSubtitle(device: device)
        }
        .padding(Tokens.spacingMedium)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassTile()
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityValue(device.online ? Text("online") : Text("offline"))
    }
}

/// A device as a row of the list.
struct DeviceRow: View {
    let device: AppModel.Computer
    @Environment(\.palette) private var palette

    var body: some View {
        HStack(spacing: Tokens.spacingMedium) {
            DeviceIcon(device: device, size: 36)
            VStack(alignment: .leading, spacing: 2) {
                Text(device.name).font(.system(.body, design: .monospaced).weight(.semibold)).lineLimit(1)
                DeviceSubtitle(device: device)
            }
            Spacer()
            OnlineDot(online: device.online)
            Image(systemName: "chevron.right").font(.footnote.weight(.semibold)).foregroundStyle(palette.textDim)
        }
        .padding(.horizontal, Tokens.spacingMedium)
        .frame(minHeight: 60)
        .glassTile(cornerRadius: Tokens.radiusCard)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityValue(device.online ? Text("online") : Text("offline"))
    }
}

/// The system (or kind) of a device, then where it stands.
struct DeviceSubtitle: View {
    let device: AppModel.Computer
    @Environment(\.palette) private var palette

    var body: some View {
        HStack(spacing: 4) {
            if let system = device.system {
                Text(verbatim: system)
            } else {
                Text(device.kind.title)
            }
            if let standing = device.standing {
                Text(verbatim: "·")
                Text(standing)
            }
        }
        .font(.caption)
        .foregroundStyle(palette.textDim)
        .lineLimit(1)
    }
}
