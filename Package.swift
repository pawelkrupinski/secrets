// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "secrets",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "secrets",
            path: "Sources/secrets"
        )
    ]
)
