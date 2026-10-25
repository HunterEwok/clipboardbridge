// SPDX-License-Identifier: AGPL-3.0-only

import AppKit
import SwiftUI

/// The app's settings: the colour, light or dark, and error details.
struct SettingsView: View {
    @EnvironmentObject private var model: MacModel
    @Environment(\.palette) private var palette
    @AppStorage(AccentChoice.key) private var color = Tokens.colors[0].name
    @AppStorage(Appearance.key) private var appearance = Appearance.system.rawValue
    @AppStorage("ShowErrorDetails") private var errorDetails = MacModel.showsErrorDetails

    var body: some View {
        Form {
            Section {
                Picker(selection: $color) {
                    ForEach(Tokens.colors, id: \.name) { pair in
                        Text(AccentChoice.title(pair.name)).tag(pair.name)
                    }
                } label: { Text("Colour") }
                HStack(spacing: Tokens.spacingSmall) {
                    ForEach(Tokens.colors, id: \.name) { pair in
                        let p = (Appearance(rawValue: appearance) ?? .system).palette(pair.name, for: palette.dark ? .dark : .light)
                        Circle().fill(p.accent).frame(width: 20, height: 20)
                            .overlay(Circle().stroke(palette.text, lineWidth: pair.name == color ? 2 : 0).padding(-3))
                            .onTapGesture { color = pair.name }
                            .accessibilityLabel(Text(AccentChoice.title(pair.name)))
                    }
                }
                Picker(selection: $appearance) {
                    ForEach(Appearance.allCases) { a in Text(a.title).tag(a.rawValue) }
                } label: { Text("Appearance") }
            } header: { Text("Look") }
            Section {
                LabeledContent {
                    Text(verbatim: model.status?.version ?? "–").monospaced()
                } label: { Text("Service version") }
                Toggle(isOn: $errorDetails) { Text("Show error details") }
                Link(destination: URL(string: "https://github.com/HunterEwok/clipboardbridge")!) {
                    Text("Source code and license (AGPL-3.0)")
                }
            } header: { Text("About") } footer: {
                Text("Error messages show the error underneath them, to find out what failed.")
            }
        }
        .formStyle(.grouped)
        .frame(width: 460)
        .fixedSize(horizontal: false, vertical: true)
    }
}

/// The menu bar item: where the group stands, send and fetch, and the
/// window.
struct MenuContent: View {
    @EnvironmentObject private var model: MacModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        if let problem = model.problem {
            Text(verbatim: problem)
        } else if model.inGroup {
            Text("\(model.others.filter(\.online).count) of \(model.others.count) online")
            if model.awayOn { Text("Sync away from home is on") }
        } else {
            Text("This Mac is in no group yet")
        }
        Divider()
        Button { Task { await model.send() } } label: { Text("Send the clipboard") }
            .disabled(!model.inGroup || model.busy)
        Button { Task { await model.fetch() } } label: { Text("Fetch") }
            .disabled(!model.inGroup || model.busy)
        if let message = model.message { Text(verbatim: message) }
        Divider()
        Button {
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        } label: { Text("Open Clipboard Bridge") }
            .keyboardShortcut("o")
        SettingsLink { Text("Settings…") }.keyboardShortcut(",")
        Divider()
        Button { NSApp.terminate(nil) } label: { Text("Quit") }.keyboardShortcut("q")
    }
}
