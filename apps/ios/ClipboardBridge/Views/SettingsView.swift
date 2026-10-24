// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// Theme, language, sync away from home, about.
struct SettingsView: View {
    @AppStorage("theme") private var theme = ThemeChoice.system
    @AppStorage(LanguageChoice.key) private var language = LanguageChoice.system
    @Environment(\.palette) private var palette
    @EnvironmentObject private var model: AppModel
    @State private var switching = false
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
            Picker(selection: $theme) {
                ForEach(ThemeChoice.allCases) { Text($0.title).tag($0) }
            } label: {
                Text("Theme")
            }
            .listRowBackground(palette.surface)
            Picker(selection: $language) {
                ForEach(LanguageChoice.allCases) { Text(verbatim: $0.title).tag($0) }
            } label: {
                Text("Language")
            }
            .listRowBackground(palette.surface)
            if let away = model.away {
                awaySection(away)
            }
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
        .background(GridBackground())
        .navigationTitle(Text("Settings"))
        .task {
            // Where sync away from home stands, as it changes.
            while !Task.isCancelled {
                await model.refresh()
                try? await Task.sleep(for: .seconds(2))
            }
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
