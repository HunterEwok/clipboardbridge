// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// The whole group. Removing devices comes with the phone's group CA
/// (docs/apps.md, Devices).
struct DevicesView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette

    var body: some View {
        List {
            if model.computers.isEmpty {
                Text("No computers connected.").foregroundStyle(palette.textDim)
            }
            ForEach(model.computers) { c in
                HStack {
                    Image(systemName: "desktopcomputer")
                    Text(c.name).font(.system(.body, design: .monospaced))
                    Spacer()
                    if c.online {
                        Text("online").foregroundStyle(palette.accent)
                    }
                }
                .listRowBackground(palette.surface)
            }
        }
        .scrollContentBackground(.hidden)
        .background(GridBackground())
        .navigationTitle(Text("Devices"))
    }
}
