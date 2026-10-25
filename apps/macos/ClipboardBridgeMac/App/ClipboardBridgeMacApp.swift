// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// The Mac app: a window and a menu bar item over the cbb service, which
/// syncs the clipboard by itself (docs/apps.md, The Mac app).
@main
struct ClipboardBridgeMacApp: App {
    @StateObject private var model = MacModel()

    var body: some Scene {
        Window(Text("Clipboard Bridge"), id: "main") {
            MainView().environmentObject(model).modifier(Themed())
        }
        .defaultSize(width: 920, height: 620)

        MenuBarExtra {
            MenuContent().environmentObject(model)
        } label: {
            // The label is drawn at launch, the menu only when it opens.
            Image(systemName: model.symbol).onAppear { model.start() }
        }

        Settings {
            SettingsView().environmentObject(model).modifier(Themed())
        }
    }
}
