// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

@main
struct ClipboardBridgeApp: App {
    @StateObject private var model = AppModel.shared
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    init() {
        Appearance.migrate()
        // Early, for a watch that asks while the app is not running.
        WatchLink.shared.start()
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
        }
    }
}
