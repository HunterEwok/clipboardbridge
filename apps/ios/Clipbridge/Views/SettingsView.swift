// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// Theme, language, about. Nothing else.
struct SettingsView: View {
    @AppStorage("theme") private var theme = ThemeChoice.system
    @Environment(\.palette) private var palette
    @Environment(\.openURL) private var openURL

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
            Button {
                // The language follows the system, with the per-app choice
                // in the system's Settings.
                if let url = URL(string: UIApplication.openSettingsURLString) { openURL(url) }
            } label: {
                LabeledContent {
                    Text("Change in the system settings").foregroundStyle(palette.textDim)
                } label: {
                    Text("Language")
                }
            }
            .listRowBackground(palette.surface)
            Section {
                LabeledContent {
                    Text(version).font(.system(.body, design: .monospaced))
                } label: {
                    Text("Version")
                }
                Link(destination: URL(string: "https://github.com/HunterEwok/clipbridge")!) {
                    Text("Source code and license (AGPL-3.0)")
                }
            } header: {
                Text("About")
            }
            .listRowBackground(palette.surface)
        }
        .scrollContentBackground(.hidden)
        .background(GridBackground())
        .navigationTitle(Text("Settings"))
    }
}
