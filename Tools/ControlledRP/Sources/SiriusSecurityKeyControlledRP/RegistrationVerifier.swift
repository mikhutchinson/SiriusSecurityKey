import CryptoKit
import Foundation
import SiriusSecurityKey

struct VerifiedRegistration: Sendable {
  let credentialID: Data
  let publicKeyX963: Data
  let signCount: UInt32
}

enum RegistrationVerifier {
  static func verify(
    clientDataJSON: Data,
    attestationObject: Data,
    rawCredentialID: Data,
    challenge: Data,
    origin: WebAuthnOrigin,
    relyingPartyID: String
  ) throws -> VerifiedRegistration {
    let expectedClientData =
      #"{"type":"webauthn.create","challenge":""#
      + Base64URL.encode(challenge)
      + #"","origin":""#
      + origin.serialized
      + #"","crossOrigin":false}"#
    guard clientDataJSON == Data(expectedClientData.utf8) else {
      throw ControlledRPError.invalidRegistration
    }

    let attestation = try CanonicalCBOR.decode(
      attestationObject,
      limits: CBORLimits(
        maximumMessageSize: 128 << 10,
        maximumNestingDepth: 8,
        maximumCollectionCount: 128,
        maximumStringSize: 128 << 10,
        maximumTotalItems: 512
      )
    )
    guard case .map = attestation,
      attestation.textValue("fmt") == .textString("none"),
      case .map(let statement)? = attestation.textValue("attStmt"),
      statement.isEmpty,
      case .byteString(let authenticatorData)? = attestation.textValue("authData")
    else {
      throw ControlledRPError.invalidRegistration
    }
    return try parseRegistrationAuthenticatorData(
      authenticatorData,
      rawCredentialID: rawCredentialID,
      relyingPartyID: relyingPartyID
    )
  }

  private static func parseRegistrationAuthenticatorData(
    _ data: Data,
    rawCredentialID: Data,
    relyingPartyID: String
  ) throws -> VerifiedRegistration {
    guard data.count >= 55, data.count <= 128 << 10 else {
      throw ControlledRPError.invalidRegistration
    }
    let expectedRPHash = Data(SHA256.hash(data: Data(relyingPartyID.utf8)))
    guard data.subdata(in: 0..<32) == expectedRPHash else {
      throw ControlledRPError.invalidRegistration
    }
    let flags = data[32]
    guard flags & 0x01 != 0, flags & 0x04 != 0, flags & 0x40 != 0,
      flags & 0x80 == 0,
      flags & 0x10 == 0 || flags & 0x08 != 0
    else {
      throw ControlledRPError.invalidRegistration
    }
    let signCount =
      UInt32(data[33]) << 24
      | UInt32(data[34]) << 16
      | UInt32(data[35]) << 8
      | UInt32(data[36])
    let credentialLength = Int(data[53]) << 8 | Int(data[54])
    guard credentialLength > 0, credentialLength <= 1_024,
      55 + credentialLength < data.count
    else {
      throw ControlledRPError.invalidRegistration
    }
    let credentialID = data.subdata(in: 55..<(55 + credentialLength))
    guard credentialID == rawCredentialID else {
      throw ControlledRPError.invalidRegistration
    }
    let keyBytes = data.subdata(in: (55 + credentialLength)..<data.count)
    let key = try CanonicalCBOR.decode(
      keyBytes,
      limits: CBORLimits(
        maximumMessageSize: 2_048,
        maximumNestingDepth: 4,
        maximumCollectionCount: 16,
        maximumStringSize: 1_024,
        maximumTotalItems: 64
      )
    )
    guard key.integerValue(1) == .unsigned(2),
      key.integerValue(3) == .negative(-7),
      key.integerValue(-1) == .unsigned(1),
      case .byteString(let x)? = key.integerValue(-2), x.count == 32,
      case .byteString(let y)? = key.integerValue(-3), y.count == 32
    else {
      throw ControlledRPError.invalidRegistration
    }
    var x963 = Data([0x04])
    x963.append(x)
    x963.append(y)
    guard (try? P256.Signing.PublicKey(x963Representation: x963)) != nil else {
      throw ControlledRPError.invalidRegistration
    }
    return VerifiedRegistration(
      credentialID: credentialID,
      publicKeyX963: x963,
      signCount: signCount
    )
  }
}

extension CBORValue {
  fileprivate func textValue(_ key: String) -> CBORValue? {
    guard case .map(let entries) = self else {
      return nil
    }
    return entries.first(where: { $0.key == .textString(key) })?.value
  }

  fileprivate func integerValue(_ key: Int64) -> CBORValue? {
    guard case .map(let entries) = self else {
      return nil
    }
    let encodedKey: CBORValue =
      key >= 0
      ? .unsigned(UInt32(key)) : .negative(key)
    return entries.first(where: { $0.key == encodedKey })?.value
  }
}
