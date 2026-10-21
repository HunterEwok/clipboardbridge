// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

@main
struct ClipbridgeApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
        }
    }
}
