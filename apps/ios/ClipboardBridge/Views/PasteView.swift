// SPDX-License-Identifier: AGPL-3.0-only

import SwiftUI

/// Remote paste (docs/design.md, "Remote paste"): a text to put where a
/// computer's focus is, pasted or typed, with Enter after it if asked. The
/// computer takes it only when its user turned remote paste on there.
struct PasteView: View {
    let device: AppModel.Computer
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.palette) private var palette
    @State private var text = ""
    @State private var typing = false
    @State private var enter = false
    @State private var secret = false
    @State private var sending = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField(String(localized: "Text", bundle: .app), text: $text, axis: .vertical)
                        .lineLimit(3...10)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    // PasteButton reads the clipboard without the system's prompt.
                    PasteButton(payloadType: String.self) { strings in
                        if let s = strings.first { text = s }
                    }
                } footer: {
                    Text("It goes where \(device.name)'s keyboard focus is, once its user turned remote paste on there.")
                }
                Section {
                    Toggle(isOn: $typing) { Text("Type it key by key") }
                    Toggle(isOn: $enter) { Text("Press Enter after it") }
                    Toggle(isOn: $secret) { Text("A secret") }
                } footer: {
                    Text("A paste suits most apps; typing suits those that take no paste, and only up to 4 KB. Enter runs a command in a terminal, so the computer takes it only when its user allowed that. A secret leaves no trace in the computer's log or clipboard.")
                }
                if let message = model.message, !sending {
                    Text(message).foregroundStyle(palette.textDim)
                }
            }
            .navigationTitle(Text("Paste on \(device.name)"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    if sending {
                        ProgressView()
                    } else {
                        Button { send() } label: { Text("Paste") }
                            .disabled(text.isEmpty)
                    }
                }
            }
            .onAppear { model.message = nil }
        }
    }

    private func send() {
        sending = true
        Task {
            let done = await model.paste(device.id, text: text, method: typing ? "type" : "paste", enter: enter, secret: secret)
            sending = false
            if done { dismiss() }
        }
    }
}
