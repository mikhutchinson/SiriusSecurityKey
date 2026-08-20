import Foundation
import Security
import SiriusSecurityKey

enum ControlledRPError: Error, Sendable {
  case invalidArguments
  case invalidRequest
  case invalidRegistration
  case registrationUnavailable
  case assertionUnavailable
  case serverVerificationFailed
  case transportFailure
}

struct RegistrationOptionsRequest: Codable, Sendable {
  let deviceLabel: String
}

struct RegistrationOptionsResponse: Codable, Sendable {
  let ceremonyID: String
  let publicKey: RegistrationPublicKeyOptions
}

struct RegistrationPublicKeyOptions: Codable, Sendable {
  struct RelyingParty: Codable, Sendable {
    let id: String
    let name: String
  }

  struct User: Codable, Sendable {
    let id: String
    let name: String
    let displayName: String
  }

  struct Algorithm: Codable, Sendable {
    let type: String
    let alg: Int
  }

  struct AuthenticatorSelection: Codable, Sendable {
    let residentKey: String
    let userVerification: String
  }

  struct Descriptor: Codable, Sendable {
    let type: String
    let id: String
  }

  let challenge: String
  let rp: RelyingParty
  let user: User
  let pubKeyCredParams: [Algorithm]
  let authenticatorSelection: AuthenticatorSelection
  let timeout: Int
  let attestation: String
  let excludeCredentials: [Descriptor]
}

struct RegistrationFinishRequest: Codable, Sendable {
  let ceremonyID: String
  let clientDataJSON: String
  let attestationObject: String
  let rawID: String
}

struct RegistrationReceipt: Codable, Sendable {
  let registered: Bool
  let deviceLabel: String
}

struct AssertionOptionsRequest: Codable, Sendable {
  let mode: String
  let deviceLabel: String
}

struct AssertionOptionsResponse: Codable, Sendable {
  let ceremonyID: String
  let mode: String
  let origin: String
  let relyingPartyID: String
  let challenge: String
  let userVerification: String
  let allowCredentials: [String]
}

struct AssertionFinishRequest: Codable, Sendable {
  let ceremonyID: String
  let credentialID: String
  let clientDataJSON: String
  let authenticatorData: String
  let signature: String
  let userHandle: String?
}

struct AssertionReceipt: Codable, Sendable {
  let verified: Bool
  let receiptID: String
  let mode: String
  let declaredDeviceLabel: String
  let counterAdvanced: Bool
}

struct StoredCredential: Sendable {
  let deviceLabel: String
  let credentialID: Data
  let publicKeyX963: Data
  let userHandle: Data
  var signCount: UInt32
}

struct PendingRegistration: Sendable {
  let challenge: Data
  let userHandle: Data
  let deviceLabel: String
  let issuedAt: ContinuousClock.Instant
}

struct PendingAssertion: Sendable {
  let challenge: Data
  let mode: WebAuthnAssertionVerificationContext.Mode
  let deviceLabel: String
  let issuedAt: ContinuousClock.Instant
}

enum Base64URL {
  static func encode(_ data: Data) -> String {
    data.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  static func decode(_ value: String, maximumBytes: Int) throws -> Data {
    guard !value.isEmpty, value.utf8.count <= maximumBytes * 2,
      value.unicodeScalars.allSatisfy({ scalar in
        scalar.isASCII
          && ((scalar.value >= 0x41 && scalar.value <= 0x5a)
            || (scalar.value >= 0x61 && scalar.value <= 0x7a)
            || (scalar.value >= 0x30 && scalar.value <= 0x39)
            || scalar == "-" || scalar == "_")
      })
    else {
      throw ControlledRPError.invalidRequest
    }
    var padded = value.replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    let remainder = padded.utf8.count % 4
    if remainder != 0 {
      padded += String(repeating: "=", count: 4 - remainder)
    }
    guard let data = Data(base64Encoded: padded), data.count <= maximumBytes else {
      throw ControlledRPError.invalidRequest
    }
    return data
  }
}

enum SecureRandom {
  static func bytes(count: Int) throws -> Data {
    guard count > 0, count <= 1_024 else {
      throw ControlledRPError.invalidRequest
    }
    var bytes = Data(repeating: 0, count: count)
    let status = bytes.withUnsafeMutableBytes { pointer in
      guard let baseAddress = pointer.baseAddress else {
        return errSecParam
      }
      return SecRandomCopyBytes(kSecRandomDefault, count, baseAddress)
    }
    guard status == errSecSuccess else {
      throw ControlledRPError.transportFailure
    }
    return bytes
  }
}

extension JSONEncoder {
  static let controlledRP: JSONEncoder = {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    return encoder
  }()
}
