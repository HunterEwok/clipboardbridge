// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// Colour and appearance, language, sync away from home, notifications,
/// about.
struct SettingsView: View {
    @AppStorage(AccentChoice.key) private var color = Tokens.colors[0].name
    @AppStorage(Appearance.key) private var appearance = Appearance.system
    @AppStorage(LanguageChoice.key) private var language = LanguageChoice.system
    @Environment(\.palette) private var palette
    @EnvironmentObject private var model: AppModel
    @State private var switching = false
    @State private var forwarderAddress = ""
    @State private var forwarderKey = ""
    /// Taps on the version; seven show the error details switch, as
    /// Android's build number shows its developer options.
    @State private var versionTaps = 0
    @AppStorage("ShowErrorDetails") private var errorDetails = AppModel.showsErrorDetails
    @AppStorage("ShowErrorDetailsSwitch") private var detailsSwitch = false

    private var version: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? ""
    }

    var body: some View {
        Form {
            Section {
                Picker(selection: $appearance) {
                    ForEach(Appearance.allCases) { Text($0.title).tag($0) }
                } label: {
                    Text("Theme")
                }
                .pickerStyle(.segmented)
                ColorSwatches(selection: $color)
            } header: {
                Text("Colour")
            }
            .listRowBackground(palette.surface)
            Picker(selection: $language) {
                ForEach(LanguageChoice.allCases) { Text(verbatim: $0.title).tag($0) }
            } label: {
                Text("Language")
            }
            .listRowBackground(palette.surface)
            if let hub = model.hub {
                hubSection(hub)
            }
            if let away = model.away, model.hub?.on != true {
                awaySection(away)
            }
            NotificationSettings()
            Section {
                LabeledContent {
                    Text(version).font(.system(.body, design: .monospaced))
                } label: {
                    Text("Version")
                }
                .contentShape(Rectangle())
                .onTapGesture {
                    versionTaps += 1
                    if versionTaps >= 7 { detailsSwitch = true }
                }
                if detailsSwitch {
                    Toggle(isOn: $errorDetails) {
                        Text("Show error details")
                    }
                    // The share extension reads it from the app group.
                    .onChange(of: errorDetails, initial: true) { _, on in Shared.defaults.set(on, forKey: "ShowErrorDetails") }
                }
                Link(destination: URL(string: "https://github.com/HunterEwok/clipboardbridge")!) {
                    Text("Source code and license (AGPL-3.0)")
                }
            } header: {
                Text("About")
            } footer: {
                if detailsSwitch {
                    Text("Error messages show the error underneath them, to find out what failed. Tap the version seven times to see this switch.")
                }
            }
            .listRowBackground(palette.surface)
        }
        .scrollContentBackground(.hidden)
        .background(AppBackground())
        .navigationTitle(Text("Settings"))
        .task {
            // Where sync away from home stands, as it changes.
            while !Task.isCancelled {
                await model.refresh()
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    /// The phone as the group's hub: the switch, where it stands, the
    /// forwarder and the home networks.
    private func hubSection(_ hub: AppModel.Hub) -> some View {
        Section {
            Toggle(isOn: Binding(get: { hub.on }, set: { on in
                switching = true
                Task {
                    await model.setHub(on)
                    switching = false
                }
            })) {
                Text("This phone is the group's hub")
            }
            .disabled(switching)
            hubStatus(hub)
                .foregroundStyle(hub.status == .registered ? palette.accent : palette.textDim)
            // The registration's error underneath, when details are on.
            if let error = hub.error, AppModel.showsErrorDetails {
                Text(verbatim: error).font(.caption).foregroundStyle(palette.textDim)
            }
            if hub.on {
                Text(hub.home ? "On a home network: devices here connect to this phone."
                     : "This network is not one of the hub's home networks: devices here do not see this phone.")
                    .font(.footnote)
                    .foregroundStyle(palette.textDim)
                if !hub.home {
                    Button { Task { await model.addHomeNetwork() } } label: { Text("This is my home network") }
                }
                TextField(text: $forwarderAddress) { Text("Forwarder address, such as 198.51.100.9:8764") }
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.numbersAndPunctuation)
                TextField(text: $forwarderKey) { Text("Forwarder key, sha256:…") }
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .font(.system(.body, design: .monospaced))
                Button {
                    switching = true
                    Task {
                        await model.setForwarder(address: forwarderAddress, pin: forwarderKey)
                        switching = false
                    }
                } label: {
                    Text("Save the forwarder")
                }
                .disabled(switching || (forwarderAddress == (hub.forwarder?.endpoint ?? "") && forwarderKey == (hub.forwarder?.pin ?? "")))
            }
            if let note = model.hubNote {
                Text(verbatim: note).font(.caption).foregroundStyle(palette.danger)
            }
        } header: {
            Text("This phone as the hub")
        } footer: {
            Text("While the app is open, this phone is the hub of a group without a computer: the other phones, TVs and lite members on the home network connect to it, and with a forwarder they reach it from afar too. The forwarder only passes encrypted packets; it learns the group's tag, this phone's tunnel key and the addresses, never what is copied. A computer that is always on is the better hub; until then this phone does it.")
        }
        .listRowBackground(palette.surface)
        .onAppear {
            forwarderAddress = hub.forwarder?.endpoint ?? ""
            forwarderKey = hub.forwarder?.pin ?? ""
        }
    }

    private func hubStatus(_ hub: AppModel.Hub) -> Text {
        switch hub.status {
        case .off: return Text("Off: this phone is no hub.")
        case .paused: return Text("Waiting for the app: the hub works while the app is open.")
        case .homeOnly: return Text("The hub at home only: add a forwarder for sync away from home.")
        case .registering: return Text("Registering with the forwarder…")
        case .registered: return Text("Registered with the forwarder: devices away from home reach this phone.")
        case .failed: return Text("The forwarder does not take this phone. Check its address and key.")
        }
    }

    /// Sync away from home: the switch, where it stands, and what it does.
    private func awaySection(_ away: AppModel.Away) -> some View {
        Section {
            Toggle(isOn: Binding(get: { away.on }, set: { on in
                switching = true
                Task {
                    await model.setAway(on)
                    switching = false
                }
            })) {
                Text("Sync away from home")
            }
            .disabled(switching)
            awayStatus(away)
                .foregroundStyle(away.on && away.status == .connected ? palette.accent : palette.textDim)
            if let error = away.error {
                Text(verbatim: error).font(.caption).foregroundStyle(palette.danger)
            }
            if let note = model.awayNote {
                Text(verbatim: note).font(.caption).foregroundStyle(palette.danger)
            }
        } header: {
            Text("Away from home")
        } footer: {
            Text("When the phone is not on the home network, it syncs through the WireGuard tunnel of your own hub, a computer of the group set up with cbb global hub; its port is reachable from the internet, but only through WireGuard with the group's keys. The hub answers this phone the next time it connects at home. Nothing goes anywhere else, and without the tunnel there is no connection. Turning it off forgets this phone's tunnel key.")
        }
        .listRowBackground(palette.surface)
    }

    private func awayStatus(_ away: AppModel.Away) -> Text {
        guard away.on else { return Text("Off") }
        switch away.status {
        case .atHome: return Text("At home: syncing directly.")
        case .connecting: return Text("Connecting to the hub through the tunnel…")
        case .connected: return Text("Connected to the hub through the tunnel.")
        case .off, .waitingForHub: return Text("Waiting for the hub: open the app at home once, near a computer of the group.")
        }
    }
}

/// The ten colours as round swatches, the chosen one ringed and ticked.
struct ColorSwatches: View {
    @Binding var selection: String
    @Environment(\.palette) private var palette

    var body: some View {
        LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: Tokens.spacingSmall), count: 5), spacing: Tokens.spacingMedium) {
            ForEach(Tokens.colors, id: \.name) { pair in
                let swatch = palette.dark ? pair.dark : pair.light
                let chosen = pair.name == selection
                Button { selection = pair.name } label: {
                    VStack(spacing: 6) {
                        Circle()
                            .fill(swatch.accent)
                            .frame(width: 36, height: 36)
                            .overlay {
                                if chosen {
                                    Image(systemName: "checkmark").font(.footnote.weight(.bold)).foregroundStyle(swatch.onAccent)
                                }
                            }
                            .padding(3)
                            .overlay(Circle().stroke(chosen ? swatch.accent : .clear, lineWidth: 2))
                        Text(AccentChoice.title(pair.name)).font(.caption2).lineLimit(1).minimumScaleFactor(0.8)
                            .foregroundStyle(chosen ? palette.text : palette.textDim)
                    }
                    .frame(maxWidth: .infinity, minHeight: 44)
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(chosen ? .isSelected : [])
            }
        }
        .padding(.vertical, Tokens.spacingSmall)
    }
}

/// A switch for each kind of the group's events (GroupEvent.Kind).
struct NotificationSettings: View {
    @Environment(\.palette) private var palette

    var body: some View {
        Section {
            ForEach(GroupEvent.Kind.allCases) { NotifyToggle(kind: $0) }
        } header: {
            Text("Notifications")
        } footer: {
            Text("The app notifies of these while it runs, and a paired Apple Watch shows them too. It hears of an event when it next syncs with the group.")
        }
        .listRowBackground(palette.surface)
    }
}

private struct NotifyToggle: View {
    let kind: GroupEvent.Kind
    @AppStorage private var on: Bool

    init(kind: GroupEvent.Kind) {
        self.kind = kind
        _on = AppStorage(wrappedValue: true, kind.key)
    }

    var body: some View {
        Toggle(isOn: $on) { title }
    }

    private var title: Text {
        switch kind {
        case .devices: Text("A device joined or was removed")
        case .admins: Text("A device became an admin")
        case .frozen: Text("A device was frozen or unfrozen")
        case .takeover: Text("The group was taken over")
        case .hub: Text("The hub does not answer away from home")
        }
    }
}
