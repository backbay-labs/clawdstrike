// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "EndpointSecurityExtension",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "EndpointSecurityExtension",
            targets: ["EndpointSecurityExtension"]
        ),
        .executable(
            name: "endpoint-security-status-tool",
            targets: ["EndpointSecurityStatusTool"]
        )
    ],
    targets: [
        .target(
            name: "EndpointSecurityExtension",
            linkerSettings: [
                .linkedLibrary("EndpointSecurity"),
                .linkedLibrary("bsm")
            ]
        ),
        .executableTarget(
            name: "EndpointSecurityStatusTool",
            dependencies: ["EndpointSecurityExtension"]
        ),
        .testTarget(
            name: "EndpointSecurityExtensionTests",
            dependencies: ["EndpointSecurityExtension"]
        )
    ]
)
