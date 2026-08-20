import CryptoKit
import Foundation
import SiriusSecurityKey
import Testing

@testable import SiriusSecurityKeyControlledRP

private struct RegistrationFixture {
  let privateKey: P256.Signing.PrivateKey
  let credentialID: Data
  let clientDataJSON: Data
  let attestationObject: Data
}

private func registrationFixture(
  challenge: Data,
  origin: String,
  rpID: String
) throws -> RegistrationFixture {
  let privateKey = P256.Signing.PrivateKey()
  let credentialID = Data(repeating: 0xa1, count: 32)
  let x963 = privateKey.publicKey.x963Representation
  let coseKey = try CanonicalCBOR.encode(
    .map([
      CBORMapEntry(key: .unsigned(1), value: .unsigned(2)),
      CBORMapEntry(key: .unsigned(3), value: .negative(-7)),
      CBORMapEntry(key: .negative(-1), value: .unsigned(1)),
      CBORMapEntry(
        key: .negative(-2),
        value: .byteString(x963.subdata(in: 1..<33))
      ),
      CBORMapEntry(
        key: .negative(-3),
        value: .byteString(x963.subdata(in: 33..<65))
      ),
    ]),
    limits: CBORLimits(maximumMessageSize: 2_048)
  )
  var authenticatorData = Data(SHA256.hash(data: Data(rpID.utf8)))
  authenticatorData.append(0x45)
  authenticatorData.append(Data(repeating: 0, count: 4))
  authenticatorData.append(Data(repeating: 0, count: 16))
  authenticatorData.append(UInt8((credentialID.count >> 8) & 0xff))
  authenticatorData.append(UInt8(credentialID.count & 0xff))
  authenticatorData.append(credentialID)
  authenticatorData.append(coseKey)
  let attestationObject = try CanonicalCBOR.encode(
    .map([
      CBORMapEntry(key: .textString("fmt"), value: .textString("none")),
      CBORMapEntry(key: .textString("attStmt"), value: .map([])),
      CBORMapEntry(
        key: .textString("authData"),
        value: .byteString(authenticatorData)
      ),
    ]),
    limits: CBORLimits(maximumMessageSize: 128 << 10)
  )
  let clientData = Data(
    (#"{"type":"webauthn.create","challenge":""#
      + Base64URL.encode(challenge)
      + #"","origin":""#
      + origin
      + #"","crossOrigin":false}"#).utf8
  )
  return RegistrationFixture(
    privateKey: privateKey,
    credentialID: credentialID,
    clientDataJSON: clientData,
    attestationObject: attestationObject
  )
}

@Test("Controlled RP verifies browser registration and one assertion server-side")
func controlledRPEndToEndState() async throws {
  let origin = try WebAuthnOrigin("http://localhost:8765")
  let state = try ControlledRPState(origin: origin, relyingPartyID: "localhost")
  let registrationOptions = try await state.registrationOptions(
    RegistrationOptionsRequest(deviceLabel: "test-phone")
  )
  let registrationChallenge = try Base64URL.decode(
    registrationOptions.publicKey.challenge,
    maximumBytes: 1_024
  )
  let registration = try registrationFixture(
    challenge: registrationChallenge,
    origin: origin.serialized,
    rpID: "localhost"
  )
  let registrationReceipt = try await state.finishRegistration(
    RegistrationFinishRequest(
      ceremonyID: registrationOptions.ceremonyID,
      clientDataJSON: Base64URL.encode(registration.clientDataJSON),
      attestationObject: Base64URL.encode(registration.attestationObject),
      rawID: Base64URL.encode(registration.credentialID)
    )
  )
  #expect(registrationReceipt.registered)

  let assertionOptions = try await state.assertionOptions(
    AssertionOptionsRequest(mode: "allow-list", deviceLabel: "test-phone")
  )
  let assertionChallenge = try Base64URL.decode(
    assertionOptions.challenge,
    maximumBytes: 1_024
  )
  let clientData = Data(
    (#"{"type":"webauthn.get","challenge":""#
      + Base64URL.encode(assertionChallenge)
      + #"","origin":"http://localhost:8765","crossOrigin":false}"#).utf8
  )
  var authenticatorData = Data(SHA256.hash(data: Data("localhost".utf8)))
  authenticatorData.append(0x05)
  authenticatorData.append(contentsOf: [0, 0, 0, 1])
  var signedBytes = authenticatorData
  signedBytes.append(Data(SHA256.hash(data: clientData)))
  let signature = try registration.privateKey.signature(for: signedBytes)
    .derRepresentation
  let assertionReceipt = try await state.finishAssertion(
    AssertionFinishRequest(
      ceremonyID: assertionOptions.ceremonyID,
      credentialID: Base64URL.encode(registration.credentialID),
      clientDataJSON: Base64URL.encode(clientData),
      authenticatorData: Base64URL.encode(authenticatorData),
      signature: Base64URL.encode(signature),
      userHandle: nil
    )
  )
  #expect(assertionReceipt.verified)
  #expect(assertionReceipt.mode == "allow-list")
  #expect(assertionReceipt.counterAdvanced)
}

@Test("Controlled RP registration rejects altered client data")
func controlledRPRejectsAlteredRegistration() throws {
  let challenge = Data(repeating: 1, count: 32)
  let fixture = try registrationFixture(
    challenge: challenge,
    origin: "http://localhost:8765",
    rpID: "localhost"
  )
  var altered = fixture.clientDataJSON
  altered[altered.startIndex] = 0x5b
  #expect(throws: ControlledRPError.invalidRegistration) {
    try RegistrationVerifier.verify(
      clientDataJSON: altered,
      attestationObject: fixture.attestationObject,
      rawCredentialID: fixture.credentialID,
      challenge: challenge,
      origin: WebAuthnOrigin("http://localhost:8765"),
      relyingPartyID: "localhost"
    )
  }
}
