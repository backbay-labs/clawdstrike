// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "ClawdStrikeNetworkExtension",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "ClawdStrikeNetworkExtension",
            targets: ["ClawdStrikeNetworkExtension"]
        ),
        .executable(
            name: "network-extension-status-tool",
            targets: ["NetworkExtensionStatusTool"]
        ),
    ],
    targets: [
        .target(
            name: "ClawdStrikeNetworkExtension"
        ),
        .executableTarget(
            name: "NetworkExtensionStatusTool",
            dependencies: ["ClawdStrikeNetworkExtension"]
        ),
        .testTarget(
            name: "ClawdStrikeNetworkExtensionTests",
            dependencies: ["ClawdStrikeNetworkExtension"]
        ),
    ]
)
