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
  dependencies: [
    .package(
      url: "https://github.com/karwa/swift-url.git",
      exact: "0.4.2"
    )
  ],
  targets: [
    .target(
      name: "SiriusSecurityKey",
      dependencies: [
        .product(name: "WebURL", package: "swift-url")
      ],
      resources: [.copy("Resources/effective_tld_names.dat")]
    ),
    .testTarget(
      name: "SiriusSecurityKeyTests",
      dependencies: ["SiriusSecurityKey"],
      resources: [.process("Vectors")]
    ),
  ]
)
