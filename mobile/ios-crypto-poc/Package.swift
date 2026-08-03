// swift-tools-version: 6.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "ios-crypto-poc",
    platforms: [.macOS(.v12)],
    targets: [
        .executableTarget(
            name: "ios-crypto-poc"
        ),
    ],
    swiftLanguageModes: [.v6]
)
