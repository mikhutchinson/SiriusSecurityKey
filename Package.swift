// swift-tools-version: 6.0

import PackageDescription

let package = Package(
  name: "SiriusSecurityKey",
  platforms: [
    .macOS(.v13),
    .iOS(.v16),
  ],
  products: [
    .library(
      name: "SiriusSecurityKey",
      targets: ["SiriusSecurityKey"]
    )
  ],
  targets: [
    .target(name: "SiriusSecurityKey"),
    .testTarget(
      name: "SiriusSecurityKeyTests",
      dependencies: ["SiriusSecurityKey"],
      resources: [.process("Vectors")]
    ),
  ]
)
