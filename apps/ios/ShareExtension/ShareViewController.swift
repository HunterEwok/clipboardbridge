// SPDX-License-Identifier: AGPL-3.0-only

import ClipboardBridgeKit
import os
import SwiftUI
import UIKit
import UniformTypeIdentifiers

private let log = Logger(subsystem: "io.github.hunterewok.clipboardbridge", category: "share")

/// Share and the text selection menu's Share: sends the text or the link
/// to the group's computers at home, as the app's Home button sends the
/// clipboard (docs/apps.md, "Share"). It dials the computers it finds with
/// the phone's own member key and closes once they have it.
final class ShareViewController: UIViewController {
    private let model = ShareModel()

    override func viewDidLoad() {
        super.viewDidLoad()
        let host = UIHostingController(rootView: ShareView(model: model) { [weak self] in
            self?.extensionContext?.completeRequest(returningItems: nil)
        })
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
        let items = extensionContext?.inputItems as? [NSExtensionItem] ?? []
        Task { @MainActor in
            await model.send(items)
            if case .sent = model.state {
                try? await Task.sleep(for: .seconds(1))
                extensionContext?.completeRequest(returningItems: nil)
            }
        }
    }
}

@MainActor
final class ShareModel: ObservableObject {
    enum State: Equatable { case sending, sent, failed(String) }
    @Published var state = State.sending

    func send(_ items: [NSExtensionItem]) async {
        guard let text = await Self.text(of: items), !text.isEmpty else {
            state = .failed(String(localized: "There is no text to send."))
            return
        }
        do {
            try await OneShot.send(text)
            state = .sent
        } catch {
            let summary: String
            switch error {
            case OneShot.Failure.noGroup: summary = String(localized: "This phone is in no group yet: open Clipboard Bridge to make one or join one.")
            case OneShot.Failure.noKey: summary = String(localized: "Open Clipboard Bridge once, then share again.")
            case OneShot.Failure.noComputers: summary = String(localized: "No computer of your group answered. Are they on, and is this phone on the home network?")
            default: summary = String(localized: "Sending failed.")
            }
            let detail = String(reflecting: error)
            log.error("\(summary, privacy: .public) \(detail, privacy: .public)")
            state = .failed(Shared.showsErrorDetails ? summary + "\n\n" + detail : summary)
        }
    }

    /// The shared text, or the shared link as text.
    static func text(of items: [NSExtensionItem]) async -> String? {
        for item in items {
            for p in item.attachments ?? [] {
                if p.hasItemConformingToTypeIdentifier(UTType.url.identifier),
                   let url = try? await p.loadItem(forTypeIdentifier: UTType.url.identifier) as? URL {
                    return url.absoluteString
                }
                if p.hasItemConformingToTypeIdentifier(UTType.plainText.identifier),
                   let s = try? await p.loadItem(forTypeIdentifier: UTType.plainText.identifier) as? String {
                    return s
                }
            }
            if let s = item.attributedContentText?.string, !s.isEmpty { return s }
        }
        return nil
    }
}

struct ShareView: View {
    @ObservedObject var model: ShareModel
    let done: () -> Void

    var body: some View {
        VStack(spacing: 16) {
            switch model.state {
            case .sending:
                ProgressView()
                Text("Sending to your computers…")
            case .sent:
                Image(systemName: "checkmark.circle").font(.largeTitle)
                Text("Sent to your computers.")
            case .failed(let message):
                Image(systemName: "exclamationmark.triangle").font(.largeTitle)
                Text(verbatim: message).multilineTextAlignment(.center)
            }
            Button(action: done) { Text("Done") }
                .buttonStyle(.borderedProminent)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(uiColor: .systemBackground))
    }
}

/// One send: dials the computers of the group that browsing finds, as the
/// app does, and hands them the text once one is connected.
@MainActor
enum OneShot {
    enum Failure: Error { case noGroup, noKey, noComputers }

    /// Holds the dialer for the browser's callback, which comes first.
    private final class DialerRef: @unchecked Sendable { var dialer: MemberDialer? }

    static func send(_ text: String, wait: Duration = .seconds(8)) async throws {
        guard let g = try PhoneGroup.load(from: Shared.groupFile) else { throw Failure.noGroup }
        guard let key = try KeychainIdentity.loadKey(label: Shared.memberLabel) else { throw Failure.noKey }
        KeychainIdentity.removeCertificates(label: Shared.memberLabel)
        let id = try KeychainIdentity.identity(certificate: g.memberCert, key: key, label: Shared.memberLabel, storeKey: false)
        let node = MemberNode(engine: SyncEngine(device: g.device, clock: HybridClock()), name: UIDevice.current.name, os: "ios")
        let ref = DialerRef()
        let browser = BonjourBrowser { found in Task { await ref.dialer?.update(found) } }
        let dialer = MemberDialer(node: node, group: g.tag,
                                  dial: browser.dialer(identity: id, chain: g.memberIssuer.map { [$0] } ?? [], roots: g.trusted))
        ref.dialer = dialer
        browser.start()
        let deadline = ContinuousClock.now + wait
        var online = await node.connected
        while online.isEmpty, ContinuousClock.now < deadline {
            try? await Task.sleep(for: .milliseconds(200))
            online = await node.connected
        }
        if !online.isEmpty {
            _ = await node.send(text: text, kind: .text)
            // The event goes out on the connections; give them a moment.
            try? await Task.sleep(for: .seconds(1))
        }
        await dialer.stop()
        browser.stop()
        await node.closeAll()
        if online.isEmpty { throw Failure.noComputers }
    }
}
