// swift-tools-version:5.9
// SPDX-License-Identifier: AGPL-3.0-only

// ClipbridgeKit is the protocol core of the phone app: pairing (CPace, the
// frames, the welcome), the join QR code and the member protocol. It has no
// UI and runs on Linux too, so its tests run against the Go implementation's
// test vectors anywhere.
import PackageDescription

let package = Package(
    name: "ClipbridgeKit",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [.library(name: "ClipbridgeKit", targets: ["ClipbridgeKit"])],
    dependencies: [
        // CryptoKit's API, on Linux too; on Apple platforms it uses CryptoKit.
        .package(url: "https://github.com/apple/swift-crypto.git", "4.0.0"..<"5.0.0"),
    ],
    targets: [
        .target(name: "ClipbridgeKit", dependencies: [.product(name: "Crypto", package: "swift-crypto")]),
        .testTarget(name: "ClipbridgeKitTests", dependencies: ["ClipbridgeKit"]),
        // Plays the phone against the Go code in the Go tests; not shipped.
        .executableTarget(name: "clipbridge-interop", dependencies: ["ClipbridgeKit"]),
    ]
)
