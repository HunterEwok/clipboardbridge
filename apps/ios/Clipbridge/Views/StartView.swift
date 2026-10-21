// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// No group yet: one sentence and one button.
struct StartView: View {
    @Environment(\.palette) private var palette
    @State private var adding = false

    var body: some View {
        VStack(spacing: Tokens.spacingLarge) {
            Spacer()
            Text("clipbridge")
                .font(.system(.largeTitle, design: .monospaced).weight(.bold))
                .foregroundStyle(palette.accent)
            Text("One clipboard for your phone and your computers. On a computer, run clipbridge join and scan its QR code.")
                .multilineTextAlignment(.center)
                .foregroundStyle(palette.textDim)
            Spacer()
            Button("Scan a computer") { adding = true }
                .buttonStyle(AccentButtonStyle())
        }
        .padding(Tokens.spacingLarge)
        .sheet(isPresented: $adding) { AddDeviceView() }
    }
}
