import Foundation
import SiriusSecurityKey

actor ControlledRPState {
  let origin: WebAuthnOrigin
  let relyingPartyID: String

  private var pendingRegistrations: [String: PendingRegistration] = [:]
  private var pendingAssertions: [String: PendingAssertion] = [:]
  private var credentialsByDevice: [String: StoredCredential] = [:]
  private let clock = ContinuousClock()

  init(origin: WebAuthnOrigin, relyingPartyID: String) throws {
    let validationRequest = try WebAuthnAssertionRequest(
      origin: origin,
      relyingPartyID: relyingPartyID,
      challenge: Data(repeating: 0, count: 32),
      allowCredentials: [],
      userVerification: .required
    )
    self.origin = origin
    self.relyingPartyID = validationRequest.relyingPartyID.value
  }

  func registrationOptions(
    _ request: RegistrationOptionsRequest
  ) throws -> RegistrationOptionsResponse {
    pruneExpiredCeremonies()
    let deviceLabel = try validateDeviceLabel(request.deviceLabel)
    guard pendingRegistrations.count < 16 else {
      throw ControlledRPError.registrationUnavailable
    }
    let challenge = try SecureRandom.bytes(count: 32)
    let userHandle = try SecureRandom.bytes(count: 32)
    let ceremonyID = UUID().uuidString.lowercased()
    pendingRegistrations[ceremonyID] = PendingRegistration(
      challenge: challenge,
      userHandle: userHandle,
      deviceLabel: deviceLabel,
      issuedAt: clock.now
    )
    let excludes = credentialsByDevice.values.map { credential in
      RegistrationPublicKeyOptions.Descriptor(
        type: "public-key",
        id: Base64URL.encode(credential.credentialID)
      )
    }
    return RegistrationOptionsResponse(
      ceremonyID: ceremonyID,
      publicKey: RegistrationPublicKeyOptions(
        challenge: Base64URL.encode(challenge),
        rp: .init(id: relyingPartyID, name: "SiriusSecurityKey Controlled RP"),
        user: .init(
          id: Base64URL.encode(userHandle),
          name: deviceLabel,
          displayName: deviceLabel
        ),
        pubKeyCredParams: [.init(type: "public-key", alg: -7)],
        authenticatorSelection: .init(
          residentKey: "required",
          userVerification: "required"
        ),
        timeout: 120_000,
        attestation: "none",
        excludeCredentials: excludes
      )
    )
  }

  func finishRegistration(
    _ request: RegistrationFinishRequest
  ) throws -> RegistrationReceipt {
    pruneExpiredCeremonies()
    guard let pending = pendingRegistrations.removeValue(forKey: request.ceremonyID)
    else {
      throw ControlledRPError.registrationUnavailable
    }
    let clientData = try Base64URL.decode(request.clientDataJSON, maximumBytes: 4_096)
    let attestation = try Base64URL.decode(
      request.attestationObject,
      maximumBytes: 128 << 10
    )
    let rawID = try Base64URL.decode(request.rawID, maximumBytes: 1_024)
    let verified = try RegistrationVerifier.verify(
      clientDataJSON: clientData,
      attestationObject: attestation,
      rawCredentialID: rawID,
      challenge: pending.challenge,
      origin: origin,
      relyingPartyID: relyingPartyID
    )
    guard
      !credentialsByDevice.values.contains(where: {
        $0.credentialID == verified.credentialID
      })
    else {
      throw ControlledRPError.invalidRegistration
    }
    credentialsByDevice[pending.deviceLabel] = StoredCredential(
      deviceLabel: pending.deviceLabel,
      credentialID: verified.credentialID,
      publicKeyX963: verified.publicKeyX963,
      userHandle: pending.userHandle,
      signCount: verified.signCount
    )
    return RegistrationReceipt(
      registered: true,
      deviceLabel: pending.deviceLabel
    )
  }

  func assertionOptions(
    _ request: AssertionOptionsRequest
  ) throws -> AssertionOptionsResponse {
    pruneExpiredCeremonies()
    let deviceLabel = try validateDeviceLabel(request.deviceLabel)
    let mode: WebAuthnAssertionVerificationContext.Mode
    switch request.mode {
    case "allow-list":
      mode = .allowList
      guard credentialsByDevice[deviceLabel] != nil else {
        throw ControlledRPError.assertionUnavailable
      }
    case "discoverable":
      mode = .discoverable
      guard !credentialsByDevice.isEmpty else {
        throw ControlledRPError.assertionUnavailable
      }
    default:
      throw ControlledRPError.invalidRequest
    }
    guard pendingAssertions.count < 16 else {
      throw ControlledRPError.assertionUnavailable
    }
    let challenge = try SecureRandom.bytes(count: 32)
    let ceremonyID = UUID().uuidString.lowercased()
    pendingAssertions[ceremonyID] = PendingAssertion(
      challenge: challenge,
      mode: mode,
      deviceLabel: deviceLabel,
      issuedAt: clock.now
    )
    let allowCredentials: [String]
    switch mode {
    case .allowList:
      guard let credential = credentialsByDevice[deviceLabel] else {
        throw ControlledRPError.assertionUnavailable
      }
      allowCredentials = [Base64URL.encode(credential.credentialID)]
    case .discoverable:
      allowCredentials = []
    }
    return AssertionOptionsResponse(
      ceremonyID: ceremonyID,
      mode: request.mode,
      origin: origin.serialized,
      relyingPartyID: relyingPartyID,
      challenge: Base64URL.encode(challenge),
      userVerification: "required",
      allowCredentials: allowCredentials
    )
  }

  func finishAssertion(
    _ request: AssertionFinishRequest
  ) throws -> AssertionReceipt {
    pruneExpiredCeremonies()
    guard let pending = pendingAssertions.removeValue(forKey: request.ceremonyID)
    else {
      throw ControlledRPError.assertionUnavailable
    }
    let submission = try WebAuthnAssertionSubmission(
      credentialID: Base64URL.decode(request.credentialID, maximumBytes: 1_024),
      clientDataJSON: Base64URL.decode(request.clientDataJSON, maximumBytes: 4_096),
      authenticatorData: Base64URL.decode(
        request.authenticatorData,
        maximumBytes: 128 << 10
      ),
      signature: Base64URL.decode(request.signature, maximumBytes: 8_192),
      userHandle: try request.userHandle.map {
        try Base64URL.decode($0, maximumBytes: 64)
      }
    )

    let selectedCredentials: [StoredCredential]
    switch pending.mode {
    case .allowList:
      guard let credential = credentialsByDevice[pending.deviceLabel] else {
        throw ControlledRPError.assertionUnavailable
      }
      selectedCredentials = [credential]
    case .discoverable:
      selectedCredentials = Array(credentialsByDevice.values)
    }
    let records = try selectedCredentials.map { credential in
      try WebAuthnES256CredentialRecord(
        credentialID: credential.credentialID,
        publicKeyX963Representation: credential.publicKeyX963,
        previousSignCount: credential.signCount,
        userHandle: credential.userHandle
      )
    }
    let context = try WebAuthnAssertionVerificationContext(
      mode: pending.mode,
      challenge: pending.challenge,
      origin: origin,
      relyingPartyID: relyingPartyID,
      userVerification: .required,
      credentialRecords: records
    )
    let verified = try WebAuthnServerAssertionVerifier.verify(
      submission,
      against: context
    )
    guard
      let key = credentialsByDevice.first(where: {
        $0.value.credentialID == verified.credentialID
      })?.key
    else {
      throw ControlledRPError.serverVerificationFailed
    }
    if verified.shouldStoreSignCount {
      credentialsByDevice[key]?.signCount = verified.signCount
    }
    return AssertionReceipt(
      verified: true,
      receiptID: UUID().uuidString.lowercased(),
      mode: pending.mode == .allowList ? "allow-list" : "discoverable",
      declaredDeviceLabel: pending.deviceLabel,
      counterAdvanced: verified.shouldStoreSignCount
    )
  }

  private func validateDeviceLabel(_ input: String) throws -> String {
    let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty, trimmed.utf8.count <= 64,
      trimmed.unicodeScalars.allSatisfy({ scalar in
        scalar.isASCII && scalar.value >= 0x20 && scalar.value <= 0x7e
      })
    else {
      throw ControlledRPError.invalidRequest
    }
    return trimmed
  }

  private func pruneExpiredCeremonies() {
    let now = clock.now
    let lifetime = Duration.seconds(300)
    pendingRegistrations = pendingRegistrations.filter {
      $0.value.issuedAt.duration(to: now) < lifetime
    }
    pendingAssertions = pendingAssertions.filter {
      $0.value.issuedAt.duration(to: now) < lifetime
    }
  }
}
