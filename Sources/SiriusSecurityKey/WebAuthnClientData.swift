import Foundation

/// Exact collected-client-data bytes bound to one WebAuthn ceremony.
public struct WebAuthnClientData: Sendable {
  public let json: Data
  public let hash: Data

  fileprivate init(json: Data) {
    self.json = json
    self.hash = ProtocolCryptography.sha256(json)
  }
}

enum WebAuthnClientDataBuilder {
  static func assertion(
    challenge: Data,
    origin: WebAuthnOrigin
  ) -> WebAuthnClientData {
    let encodedChallenge = base64URLEncoded(challenge)
    var json = #"{"type":"webauthn.get","challenge":""#
    json += jsonEscapedContents(encodedChallenge)
    json += #"","origin":""#
    json += jsonEscapedContents(origin.serialized)
    json += #"","crossOrigin":false}"#
    return WebAuthnClientData(json: Data(json.utf8))
  }

  private static func base64URLEncoded(_ data: Data) -> String {
    data.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  private static func jsonEscapedContents(_ value: String) -> String {
    var result = ""
    result.reserveCapacity(value.utf8.count)
    for scalar in value.unicodeScalars {
      switch scalar.value {
      case 0x22:
        result += #"\""#
      case 0x5c:
        result += #"\\"#
      case 0x00...0x1f:
        let hex = String(scalar.value, radix: 16, uppercase: false)
        result += "\\u" + String(repeating: "0", count: 4 - hex.count) + hex
      default:
        result.unicodeScalars.append(scalar)
      }
    }
    return result
  }
}
