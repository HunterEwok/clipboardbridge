// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// One theme's colours (apps/design/tokens.json; Tokens.swift is generated
/// from it).
struct Palette: Equatable {
    let dark: Bool
    let background: Color
    let surface: Color
    let grid: Color
    let text: Color
    let textDim: Color
    let accent: Color
    let onAccent: Color
    let danger: Color
}

extension Color {
    /// A colour from 0xRRGGBB.
    init(rgb: UInt32) {
        self.init(red: Double(rgb >> 16 & 0xff) / 255, green: Double(rgb >> 8 & 0xff) / 255, blue: Double(rgb & 0xff) / 255)
    }
}

/// The theme the user picks in Settings; System follows the system's light
/// or dark mode with Terminal and Light.
enum ThemeChoice: String, CaseIterable, Identifiable {
    case system, terminal, midnight, amber, light

    var id: String { rawValue }

    var title: LocalizedStringKey {
        switch self {
        case .system: "System"
        case .terminal: "Terminal"
        case .midnight: "Midnight"
        case .amber: "Amber"
        case .light: "Light"
        }
    }

    func palette(for scheme: ColorScheme) -> Palette {
        switch self {
        case .system: scheme == .dark ? Tokens.terminal : Tokens.light
        case .terminal: Tokens.terminal
        case .midnight: Tokens.midnight
        case .amber: Tokens.amber
        case .light: Tokens.light
        }
    }
}

private struct PaletteKey: EnvironmentKey {
    static let defaultValue = Tokens.terminal
}

extension EnvironmentValues {
    var palette: Palette {
        get { self[PaletteKey.self] }
        set { self[PaletteKey.self] = newValue }
    }
}

/// The deep background with a faint grid.
struct GridBackground: View {
    @Environment(\.palette) private var palette

    var body: some View {
        Canvas { ctx, size in
            let step: CGFloat = 28
            var path = Path()
            var x: CGFloat = 0
            while x < size.width {
                path.move(to: CGPoint(x: x, y: 0))
                path.addLine(to: CGPoint(x: x, y: size.height))
                x += step
            }
            var y: CGFloat = 0
            while y < size.height {
                path.move(to: CGPoint(x: 0, y: y))
                path.addLine(to: CGPoint(x: size.width, y: y))
                y += step
            }
            ctx.stroke(path, with: .color(palette.grid), lineWidth: 0.5)
        }
        .background(palette.background)
        .ignoresSafeArea()
        .accessibilityHidden(true)
    }
}

/// The one big button style: rounded, generous, the accent colour.
struct AccentButtonStyle: ButtonStyle {
    @Environment(\.palette) private var palette

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.title3.weight(.semibold))
            .frame(maxWidth: .infinity, minHeight: 64)
            .foregroundStyle(palette.onAccent)
            .background(palette.accent.opacity(configuration.isPressed ? 0.8 : 1),
                        in: RoundedRectangle(cornerRadius: Tokens.radiusButton, style: .continuous))
    }
}
