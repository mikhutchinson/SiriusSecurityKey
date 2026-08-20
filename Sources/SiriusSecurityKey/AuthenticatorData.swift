import Foundation

public struct AuthenticatorDataFlags: OptionSet, Sendable, Hashable {
  public let rawValue: UInt8

  public init(rawValue: UInt8) {
    self.rawValue = rawValue
  }

  public static let userPresent = AuthenticatorDataFlags(rawValue: 1 << 0)
  public static let userVerified = AuthenticatorDataFlags(rawValue: 1 << 2)
  public static let backupEligible = AuthenticatorDataFlags(rawValue: 1 << 3)
  public static let backupState = AuthenticatorDataFlags(rawValue: 1 << 4)
  public static let attestedCredentialData = AuthenticatorDataFlags(rawValue: 1 << 6)
  public static let extensionData = AuthenticatorDataFlags(rawValue: 1 << 7)
}

/// Strictly decoded assertion authenticator data.
public struct AuthenticatorData: Sendable {
  public let relyingPartyIDHash: Data
  public let flags: AuthenticatorDataFlags
  public let signCount: UInt32
  public let extensionOutputs: CBORValue?
  public let rawBytes: Data
}

enum AuthenticatorDataParser {
  private static let fixedByteCount = 37
  private static let maximumByteCount = 128 << 10

  static func parseAssertion(_ input: Data) throws -> AuthenticatorData {
    guard input.count >= fixedByteCount, input.count <= maximumByteCount else {
      throw WebAuthnError.invalidAuthenticatorData
    }
    let data = Data(input)
    let relyingPartyIDHash = data.subdata(in: 0..<32)
    let flags = AuthenticatorDataFlags(rawValue: data[32])
    guard !flags.contains(.attestedCredentialData) else {
      throw WebAuthnError.invalidAuthenticatorData
    }
    guard !flags.contains(.backupState) || flags.contains(.backupEligible) else {
      throw WebAuthnError.invalidBackupState
    }

    let signCount =
      UInt32(data[33]) << 24
      | UInt32(data[34]) << 16
      | UInt32(data[35]) << 8
      | UInt32(data[36])

    let extensionOutputs: CBORValue?
    let trailing = data.subdata(in: fixedByteCount..<data.count)
    if flags.contains(.extensionData) {
      guard !trailing.isEmpty else {
        throw WebAuthnError.invalidAuthenticatorData
      }
      let decoded: CBORValue
      do {
        decoded = try CanonicalCBOR.decode(
          trailing,
          limits: CBORLimits(
            maximumMessageSize: maximumByteCount - fixedByteCount,
            maximumNestingDepth: 8,
            maximumCollectionCount: 128,
            maximumStringSize: 64 << 10,
            maximumTotalItems: 512
          )
        )
      } catch {
        throw WebAuthnError.invalidAuthenticatorData
      }
      guard case .map = decoded else {
        throw WebAuthnError.invalidAuthenticatorData
      }
      extensionOutputs = decoded
    } else {
      guard trailing.isEmpty else {
        throw WebAuthnError.invalidAuthenticatorData
      }
      extensionOutputs = nil
    }

    return AuthenticatorData(
      relyingPartyIDHash: relyingPartyIDHash,
      flags: flags,
      signCount: signCount,
      extensionOutputs: extensionOutputs,
      rawBytes: data
    )
  }
}
