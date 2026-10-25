// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// Tiles or a list, as the menu sets it; on a big screen also the orbit.
enum DeviceLayout: String {
    static let key = "deviceLayout"
    /// The choice on a big screen, which starts with the orbit.
    static let wideKey = "deviceLayoutWide"

    case tiles, list, orbit
}

/// The one page: the big button, the result in one line, and every device
/// of the group as tiles or a list; a device opens its details. On a big
/// screen (an iPad, a foldable iPhone's inner screen) the devices may stand
/// on orbits around this phone, and the details open beside them.
struct HomeView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette
    @Environment(\.horizontalSizeClass) private var sizeClass
    @AppStorage(DeviceLayout.key) private var layout = DeviceLayout.tiles
    @AppStorage(DeviceLayout.wideKey) private var wideLayout = DeviceLayout.orbit
    @State private var adding = false
    @State private var settings = false
    /// The device whose details stand beside the devices on a big screen.
    @State private var selected: AppModel.Computer.ID?

    private var wide: Bool { sizeClass == .regular }

    var body: some View {
        NavigationStack {
            Group {
                if wide { wideBody } else { compactBody }
            }
            .background(AppBackground())
            .navigationTitle(Text("Clipboard Bridge"))
            .navigationDestination(for: AppModel.Computer.ID.self) { DeviceDetailView(id: $0) }
            .navigationDestination(isPresented: $settings) { SettingsView() }
            .toolbar {
                ToolbarItem(placement: .topBarLeading) { menu }
                // On a big screen the toolbar holds the sync button, which a
                // foldable iPhone puts in the strip at its right edge.
                if wide {
                    ToolbarItem(placement: .primaryAction) {
                        Button {
                            Task { await model.sync() }
                        } label: {
                            Label { Text("Send or fetch") } icon: { Image(systemName: "arrow.up.arrow.down") }
                        }
                        .disabled(model.busy)
                    }
                }
                ToolbarItem(placement: .primaryAction) {
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

    /// The phone's page.
    private var compactBody: some View {
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
                DeviceCollection(devices: model.devices, layout: layout == .orbit ? .tiles : layout)
                hint
            }
            .padding(Tokens.spacingLarge)
        }
    }

    /// The big screen's page: the devices, and the chosen one's details
    /// beside them.
    private var wideBody: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: Tokens.spacingMedium) {
                summary
                if let message = model.message {
                    Text(message).foregroundStyle(palette.textDim)
                }
                if wideLayout == .orbit {
                    OrbitView(devices: model.devices, selected: selected, busy: model.busy,
                              select: { selected = $0 }, sync: { Task { await model.sync() } })
                } else {
                    ScrollView {
                        DeviceCollection(devices: model.devices, layout: wideLayout, select: { selected = $0 })
                    }
                }
                hint
            }
            .padding(Tokens.spacingLarge)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            if let id = selected {
                Divider().overlay(palette.line)
                DeviceDetailView(id: id, close: { selected = nil })
                    .frame(width: 400)
                    .transition(.move(edge: .trailing))
            }
        }
        .animation(.smooth, value: selected)
        .sensoryFeedback(.success, trigger: model.message)
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
            Picker(selection: wide ? $wideLayout : $layout) {
                if wide {
                    Label { Text("Orbit") } icon: { Image(systemName: "circle.circle") }.tag(DeviceLayout.orbit)
                }
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

/// The devices as tiles or as a list; each one opens its details: on the
/// next page, or beside them through select on a big screen.
struct DeviceCollection: View {
    let devices: [AppModel.Computer]
    let layout: DeviceLayout
    var select: ((AppModel.Computer.ID) -> Void)?
    @Environment(\.palette) private var palette

    var body: some View {
        if devices.isEmpty {
            Text("No computers connected.").foregroundStyle(palette.textDim)
        } else if layout == .list {
            VStack(spacing: Tokens.spacingSmall) {
                ForEach(devices) { d in open(d) { DeviceRow(device: d) } }
            }
        } else {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), spacing: Tokens.spacingMedium)], spacing: Tokens.spacingMedium) {
                ForEach(devices) { d in open(d) { DeviceTile(device: d) } }
            }
        }
    }

    @ViewBuilder private func open<Content: View>(_ d: AppModel.Computer, @ViewBuilder label: () -> Content) -> some View {
        if let select {
            Button { select(d.id) } label: { label() }.buttonStyle(.plain)
        } else {
            NavigationLink(value: d.id) { label() }.buttonStyle(.plain)
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
