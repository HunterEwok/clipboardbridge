// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// The big button, the result in one line, and the computers.
struct HomeView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.palette) private var palette
    @State private var adding = false

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: Tokens.spacingLarge) {
                Button {
                    Task { await model.sync() }
                } label: {
                    Text("Send or fetch")
                }
                .buttonStyle(AccentButtonStyle())
                .disabled(model.busy)
                .sensoryFeedback(.success, trigger: model.message)

                if let message = model.message {
                    Text(message).foregroundStyle(palette.textDim)
                }

                NavigationLink {
                    DevicesView()
                } label: {
                    ComputerList(computers: model.computers)
                }
                .buttonStyle(.plain)
                Spacer()
            }
            .padding(Tokens.spacingLarge)
            .background(GridBackground())
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    NavigationLink { SettingsView() } label: {
                        Image(systemName: "gearshape").accessibilityLabel(Text("Settings"))
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    if model.isAdmin {
                        Button { adding = true } label: {
                            Image(systemName: "plus").accessibilityLabel(Text("Add a device"))
                        }
                    }
                }
            }
            .sheet(isPresented: $adding) { AddDeviceView() }
            .task {
                // The live dots: which computers are connected now.
                while !Task.isCancelled {
                    await model.refresh()
                    try? await Task.sleep(for: .seconds(2))
                }
            }
        }
    }
}

/// The computers as a compact list with a live dot each.
struct ComputerList: View {
    let computers: [AppModel.Computer]
    @Environment(\.palette) private var palette

    var body: some View {
        VStack(alignment: .leading, spacing: Tokens.spacingSmall) {
            Text("Computers").font(.headline)
            if computers.isEmpty {
                Text("No computers connected.").foregroundStyle(palette.textDim)
            }
            ForEach(computers) { c in
                HStack {
                    Circle().fill(c.online ? palette.accent : palette.textDim).frame(width: 8, height: 8)
                    Text(c.name).font(.system(.body, design: .monospaced))
                }
                .accessibilityElement(children: .combine)
                .accessibilityValue(c.online ? Text("online") : Text("offline"))
            }
        }
        .padding(Tokens.spacingMedium)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassCard()
    }
}
