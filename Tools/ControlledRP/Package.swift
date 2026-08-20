// swift-tools-version: 6.0

import PackageDescription

let package = Package(
  name: "SiriusSecurityKeyControlledRP",
  platforms: [.macOS(.v13)],
  products: [
    .executable(
      name: "SiriusSecurityKeyControlledRP",
      targets: ["SiriusSecurityKeyControlledRP"]
    )
  ],
  dependencies: [
    .package(path: "../..")
  ],
  targets: [
    .executableTarget(
      name: "SiriusSecurityKeyControlledRP",
      dependencies: [
        .product(name: "SiriusSecurityKey", package: "SiriusSecurityKey")
      ]
    ),
    .testTarget(
      name: "SiriusSecurityKeyControlledRPTests",
      dependencies: ["SiriusSecurityKeyControlledRP"]
    ),
  ]
)
