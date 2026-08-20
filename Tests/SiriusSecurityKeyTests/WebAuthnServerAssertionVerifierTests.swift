import CryptoKit
import Foundation
import Testing

@testable import SiriusSecurityKey

private func signedAssertion(
  ceremony: ValidatedWebAuthnAssertionCeremony,
  privateKey: P256.Signing.PrivateKey,
  credentialID: Data,
  signCount: UInt32,
  userHandle: Data? = nil
) throws -> WebAuthnAssertion {
  let plan = try WebAuthnAssertionPlanCompiler.compile(
    ceremony: ceremony,
    authenticatorInfo: assertionAuthenticatorInfo()
  )
  let authenticatorData = try assertionAuthenticatorData(signCount: signCount)
  var signedBytes = authenticatorData
  signedBytes.append(ceremony.clientData.hash)
  let signature = try privateKey.signature(for: signedBytes).derRepresentation
  let response = try assertionResponse(
    credentialID: credentialID,
    authenticatorData: authenticatorData,
    signature: signature,
    userID: userHandle
  )
  let parsed = try CTAPAssertionResponseParser.parse(
    response,
    plan: plan,
    isFirstResponse: true
  )
  return try CTAPAssertionResponseParser.finish(
    responses: [parsed],
    plan: plan,
    selectedResponseIndex: nil
  )
}

@Test("RP verifier independently validates signature and advances a strict counter")
func serverVerifiesES256Assertion() async throws {
  let credentialID = Data([0xa1, 0xa2])
  let ceremony = try await assertionCeremony(
    allowCredentials: [try WebAuthnCredentialDescriptor(id: credentialID)]
  )
  let privateKey = P256.Signing.PrivateKey()
  let assertion = try signedAssertion(
    ceremony: ceremony,
    privateKey: privateKey,
    credentialID: credentialID,
    signCount: 9
  )
  let record = try WebAuthnES256CredentialRecord(
    credentialID: credentialID,
    publicKeyX963Representation: privateKey.publicKey.x963Representation,
    previousSignCount: 8
  )
  let context = try WebAuthnAssertionVerificationContext(
    mode: .allowList,
    challenge: Data(repeating: 0x5a, count: 32),
    origin: WebAuthnOrigin("https://login.example.com"),
    relyingPartyID: "example.com",
    userVerification: .required,
    credentialRecords: [record]
  )

  let verified = try WebAuthnServerAssertionVerifier.verify(
    assertion,
    against: context
  )
  #expect(verified.credentialID == credentialID)
  #expect(verified.signCount == 9)
  #expect(verified.shouldStoreSignCount)
  #expect(verified.userWasVerified)
}

@Test("RP verifier rejects challenge mismatch, wrong key and counter rollback")
func serverRejectsAssertionTrustFailures() async throws {
  let credentialID = Data([0xb1])
  let ceremony = try await assertionCeremony(
    allowCredentials: [try WebAuthnCredentialDescriptor(id: credentialID)]
  )
  let privateKey = P256.Signing.PrivateKey()
  let assertion = try signedAssertion(
    ceremony: ceremony,
    privateKey: privateKey,
    credentialID: credentialID,
    signCount: 4
  )

  func context(
    challenge: Data = Data(repeating: 0x5a, count: 32),
    publicKey: P256.Signing.PublicKey = privateKey.publicKey,
    previousCount: UInt32 = 3
  ) throws -> WebAuthnAssertionVerificationContext {
    try WebAuthnAssertionVerificationContext(
      mode: .allowList,
      challenge: challenge,
      origin: WebAuthnOrigin("https://login.example.com"),
      relyingPartyID: "example.com",
      userVerification: .required,
      credentialRecords: [
        try WebAuthnES256CredentialRecord(
          credentialID: credentialID,
          publicKeyX963Representation: publicKey.x963Representation,
          previousSignCount: previousCount
        )
      ]
    )
  }

  #expect(throws: WebAuthnError.clientDataMismatch) {
    try WebAuthnServerAssertionVerifier.verify(
      assertion,
      against: context(challenge: Data(repeating: 0x6b, count: 32))
    )
  }
  #expect(throws: WebAuthnError.signatureInvalid) {
    try WebAuthnServerAssertionVerifier.verify(
      assertion,
      against: context(publicKey: P256.Signing.PrivateKey().publicKey)
    )
  }
  #expect(throws: WebAuthnError.signatureCounterRollback) {
    try WebAuthnServerAssertionVerifier.verify(
      assertion,
      against: context(previousCount: 4)
    )
  }
  #expect(throws: WebAuthnError.userHandleMismatch) {
    try WebAuthnServerAssertionVerifier.verify(
      WebAuthnAssertionSubmission(
        credentialID: assertion.credentialID,
        clientDataJSON: assertion.clientDataJSON,
        authenticatorData: assertion.authenticatorData,
        signature: assertion.signature,
        userHandle: Data([1])
      ),
      against: context()
    )
  }
}

@Test("Discoverable RP verification binds the returned user handle")
func serverBindsDiscoverableUserHandle() async throws {
  let credentialID = Data([0xc1])
  let userHandle = Data([0x10, 0x11])
  let ceremony = try await assertionCeremony(allowCredentials: [])
  let privateKey = P256.Signing.PrivateKey()
  let assertion = try signedAssertion(
    ceremony: ceremony,
    privateKey: privateKey,
    credentialID: credentialID,
    signCount: 0,
    userHandle: userHandle
  )
  let record = try WebAuthnES256CredentialRecord(
    credentialID: credentialID,
    publicKeyX963Representation: privateKey.publicKey.x963Representation,
    previousSignCount: 0,
    userHandle: userHandle
  )
  let context = try WebAuthnAssertionVerificationContext(
    mode: .discoverable,
    challenge: Data(repeating: 0x5a, count: 32),
    origin: WebAuthnOrigin("https://login.example.com"),
    relyingPartyID: "example.com",
    userVerification: .required,
    credentialRecords: [record]
  )
  let verified = try WebAuthnServerAssertionVerifier.verify(
    assertion,
    against: context
  )
  #expect(verified.userHandle == userHandle)
  #expect(!verified.shouldStoreSignCount)

  let wrongUserRecord = try WebAuthnES256CredentialRecord(
    credentialID: credentialID,
    publicKeyX963Representation: privateKey.publicKey.x963Representation,
    previousSignCount: 0,
    userHandle: Data([0xff])
  )
  let wrongUserContext = try WebAuthnAssertionVerificationContext(
    mode: .discoverable,
    challenge: Data(repeating: 0x5a, count: 32),
    origin: WebAuthnOrigin("https://login.example.com"),
    relyingPartyID: "example.com",
    userVerification: .required,
    credentialRecords: [wrongUserRecord]
  )
  #expect(throws: WebAuthnError.userHandleMismatch) {
    try WebAuthnServerAssertionVerifier.verify(
      assertion,
      against: wrongUserContext
    )
  }
}

@Test("RP verification rejects mutations of every signed boundary")
func serverRejectsSignedBoundaryMutations() async throws {
  let credentialID = Data([0xd1, 0xd2])
  let ceremony = try await assertionCeremony(
    allowCredentials: [try WebAuthnCredentialDescriptor(id: credentialID)]
  )
  let privateKey = P256.Signing.PrivateKey()
  let assertion = try signedAssertion(
    ceremony: ceremony,
    privateKey: privateKey,
    credentialID: credentialID,
    signCount: 1
  )
  let context = try WebAuthnAssertionVerificationContext(
    mode: .allowList,
    challenge: Data(repeating: 0x5a, count: 32),
    origin: WebAuthnOrigin("https://login.example.com"),
    relyingPartyID: "example.com",
    userVerification: .required,
    credentialRecords: [
      try WebAuthnES256CredentialRecord(
        credentialID: credentialID,
        publicKeyX963Representation: privateKey.publicKey.x963Representation,
        previousSignCount: 0
      )
    ]
  )

  func expectRejected(
    credentialID: Data = assertion.credentialID,
    clientDataJSON: Data = assertion.clientDataJSON,
    authenticatorData: Data = assertion.authenticatorData,
    signature: Data = assertion.signature
  ) {
    do {
      let submission = try WebAuthnAssertionSubmission(
        credentialID: credentialID,
        clientDataJSON: clientDataJSON,
        authenticatorData: authenticatorData,
        signature: signature,
        userHandle: assertion.userHandle
      )
      _ = try WebAuthnServerAssertionVerifier.verify(submission, against: context)
      Issue.record("mutated signed boundary was accepted")
    } catch {
      // Every mutation must fail either structural or cryptographic validation.
    }
  }

  var mutatedCredential = assertion.credentialID
  mutatedCredential[0] ^= 1
  expectRejected(credentialID: mutatedCredential)
  for index in assertion.clientDataJSON.indices {
    var bytes = assertion.clientDataJSON
    bytes[index] ^= 1
    expectRejected(clientDataJSON: bytes)
  }
  for index in assertion.authenticatorData.indices {
    var bytes = assertion.authenticatorData
    bytes[index] ^= 1
    expectRejected(authenticatorData: bytes)
  }
  for index in assertion.signature.indices {
    var bytes = assertion.signature
    bytes[index] ^= 1
    expectRejected(signature: bytes)
  }
}
