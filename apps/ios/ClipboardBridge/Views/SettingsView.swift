// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// Theme, language, about. Nothing else.
struct SettingsView: View {
    @AppStorage("theme") private var theme = ThemeChoice.system
    @AppStorage(LanguageChoice.key) private var language = LanguageChoice.system
    @Environment(\.palette) private var palette

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
            Section {
                LabeledContent {
                    Text(version).font(.system(.body, design: .monospaced))
                } label: {
                    Text("Version")
                }
                Link(destination: URL(string: "https://github.com/HunterEwok/clipboardbridge")!) {
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
