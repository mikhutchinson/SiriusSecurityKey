import Foundation
import SiriusSecurityKey

@main
enum ControlledRPMain {
  static func main() async {
    do {
      try await run(Array(CommandLine.arguments.dropFirst()))
    } catch {
      fputs("controlled_rp_failed category=\(String(describing: type(of: error)))\n", stderr)
      exit(1)
    }
  }

  private static func run(_ arguments: [String]) async throws {
    guard let command = arguments.first else {
      throw ControlledRPError.invalidArguments
    }
    let options = try parseOptions(Array(arguments.dropFirst()))
    switch command {
    case "serve":
      guard let rawOrigin = options["origin"],
        let rawPort = options["port"],
        let port = UInt16(rawPort),
        let url = URL(string: rawOrigin),
        let host = url.host
      else {
        throw ControlledRPError.invalidArguments
      }
      let origin = try WebAuthnOrigin(rawOrigin)
      var authority = host
      if let originPort = url.port {
        authority += ":\(originPort)"
      }
      let state = try ControlledRPState(
        origin: origin,
        relyingPartyID: host
      )
      let server = ControlledRPHTTPServer(
        state: state,
        expectedAuthority: authority
      )
      try await server.run(port: port)

    case "assert":
      guard let rawServer = options["server"],
        let server = URL(string: rawServer),
        let mode = options["mode"],
        mode == "allow-list" || mode == "discoverable",
        let deviceLabel = options["device"],
        let rawProfile = options["profile"]
      else {
        throw ControlledRPError.invalidArguments
      }
      let profile: HybridWireProfile
      switch rawProfile {
      case "pxp-20260717":
        profile = .pxp20260717
      case "chromium-cable-v2-r0":
        profile = .chromiumCableV2Revision0
      default:
        throw ControlledRPError.invalidArguments
      }
      try await AssertionRunner.run(
        server: server,
        mode: mode,
        deviceLabel: deviceLabel,
        wireProfile: profile
      )

    default:
      throw ControlledRPError.invalidArguments
    }
  }

  private static func parseOptions(_ arguments: [String]) throws -> [String: String] {
    guard arguments.count.isMultiple(of: 2) else {
      throw ControlledRPError.invalidArguments
    }
    var result: [String: String] = [:]
    var index = 0
    while index < arguments.count {
      let key = arguments[index]
      let value = arguments[index + 1]
      guard key.hasPrefix("--"), key.count > 2,
        result.updateValue(value, forKey: String(key.dropFirst(2))) == nil
      else {
        throw ControlledRPError.invalidArguments
      }
      index += 2
    }
    return result
  }
}
