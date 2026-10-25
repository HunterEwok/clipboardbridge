// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

@main
struct ClipboardBridgeApp: App {
    @StateObject private var model = AppModel.shared

    init() {
        Appearance.migrate()
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
        }
    }
}
