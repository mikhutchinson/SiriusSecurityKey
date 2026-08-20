import Foundation

public enum WebAuthnAuthenticatorTransport: String, Sendable, Hashable, CaseIterable {
  case usb
  case nfc
  case ble
  case smartCard = "smart-card"
  case hybrid
  case `internal`
}

public enum WebAuthnUserVerificationRequirement: String, Sendable, Hashable {
  case required
  case preferred
  case discouraged
}

/// A bounded public-key credential descriptor supplied by the RP.
public struct WebAuthnCredentialDescriptor: Sendable, Hashable {
  public let id: Data
  public let transports: Set<WebAuthnAuthenticatorTransport>?

  public init(
    id: Data,
    transports: Set<WebAuthnAuthenticatorTransport>? = nil
  ) throws {
    guard !id.isEmpty, id.count <= 1_024 else {
      throw WebAuthnError.credentialIDOutOfBounds
    }
    self.id = Data(id)
    if let transports, !transports.isEmpty {
      self.transports = transports
    } else {
      self.transports = nil
    }
  }
}

/// Fully bounded but not yet intent-authorized assertion inputs.
public struct WebAuthnAssertionRequest: Sendable {
  public let origin: WebAuthnOrigin
  public let relyingPartyID: WebAuthnRelyingPartyID
  public let challenge: Data
  public let allowCredentials: [WebAuthnCredentialDescriptor]
  public let userVerification: WebAuthnUserVerificationRequirement

  public init(
    origin: WebAuthnOrigin,
    relyingPartyID: String,
    challenge: Data,
    allowCredentials: [WebAuthnCredentialDescriptor],
    userVerification: WebAuthnUserVerificationRequirement
  ) throws {
    guard challenge.count >= 16, challenge.count <= 1_024 else {
      throw WebAuthnError.challengeOutOfBounds
    }
    guard allowCredentials.count <= 64 else {
      throw WebAuthnError.credentialListTooLarge
    }
    var credentialIDs: Set<Data> = []
    for descriptor in allowCredentials {
      guard credentialIDs.insert(descriptor.id).inserted else {
        throw WebAuthnError.duplicateCredential
      }
    }

    self.origin = origin
    self.relyingPartyID = try WebAuthnTrustValidator.validateRelyingPartyID(
      relyingPartyID,
      for: origin
    )
    self.challenge = Data(challenge)
    self.allowCredentials = allowCredentials
    self.userVerification = userVerification
  }
}

/// Public, non-secret facts presented to a consumer-owned intent authority.
public struct WebAuthnUserIntentRequest: Sendable {
  public let origin: WebAuthnOrigin
  public let relyingPartyID: String
  public let isDiscoverable: Bool
  public let userVerification: WebAuthnUserVerificationRequirement
}

/// Consumer boundary for explicit gesture/consent authorization.
///
/// The package provides no default or permissive implementation. Returning
/// successfully authorizes exactly the immutable facts in the request.
public protocol WebAuthnUserIntentAuthorizer: Sendable {
  func authorize(_ request: WebAuthnUserIntentRequest) async throws
}

/// An immutable, validated and explicitly authorized assertion ceremony.
///
/// There is no public initializer. The only construction path validates the RP
/// binding, builds exact client data, and invokes a consumer intent authority.
public struct ValidatedWebAuthnAssertionCeremony: Sendable {
  public let origin: WebAuthnOrigin
  public let relyingPartyID: WebAuthnRelyingPartyID
  public let clientData: WebAuthnClientData
  public let requestedUserVerification: WebAuthnUserVerificationRequirement
  public let isDiscoverable: Bool

  let allowCredentials: [WebAuthnCredentialDescriptor]

  public static func authorize(
    _ request: WebAuthnAssertionRequest,
    using authorizer: any WebAuthnUserIntentAuthorizer
  ) async throws -> ValidatedWebAuthnAssertionCeremony {
    guard !Task.isCancelled else {
      throw WebAuthnError.cancelled
    }

    let clientData = WebAuthnClientDataBuilder.assertion(
      challenge: request.challenge,
      origin: request.origin
    )
    let intent = WebAuthnUserIntentRequest(
      origin: request.origin,
      relyingPartyID: request.relyingPartyID.value,
      isDiscoverable: request.allowCredentials.isEmpty,
      userVerification: request.userVerification
    )
    do {
      try await authorizer.authorize(intent)
    } catch is CancellationError {
      throw WebAuthnError.cancelled
    } catch let error as WebAuthnError where error == .cancelled {
      throw WebAuthnError.cancelled
    } catch {
      throw WebAuthnError.userIntentDenied
    }
    guard !Task.isCancelled else {
      throw WebAuthnError.cancelled
    }

    return ValidatedWebAuthnAssertionCeremony(
      origin: request.origin,
      relyingPartyID: request.relyingPartyID,
      clientData: clientData,
      requestedUserVerification: request.userVerification,
      isDiscoverable: request.allowCredentials.isEmpty,
      allowCredentials: request.allowCredentials
    )
  }

  private init(
    origin: WebAuthnOrigin,
    relyingPartyID: WebAuthnRelyingPartyID,
    clientData: WebAuthnClientData,
    requestedUserVerification: WebAuthnUserVerificationRequirement,
    isDiscoverable: Bool,
    allowCredentials: [WebAuthnCredentialDescriptor]
  ) {
    self.origin = origin
    self.relyingPartyID = relyingPartyID
    self.clientData = clientData
    self.requestedUserVerification = requestedUserVerification
    self.isDiscoverable = isDiscoverable
    self.allowCredentials = allowCredentials
  }
}

/// Consumer-owned account-selection candidate for a discoverable assertion.
public struct WebAuthnAccountCandidate: Sendable {
  public let userHandle: Data
  public let name: String?
  public let displayName: String?

  let responseIndex: Int
}

/// Consumer presentation boundary for multiple discoverable accounts.
public protocol WebAuthnAccountSelector: Sendable {
  func selectAccount(from candidates: [WebAuthnAccountCandidate]) async throws -> Int
}

/// Validated WebAuthn assertion material returned to the relying party.
public struct WebAuthnAssertion: Sendable {
  public let credentialID: Data
  public let clientDataJSON: Data
  public let authenticatorData: Data
  public let signature: Data
  public let userHandle: Data?
  public let signCount: UInt32
  public let userWasPresent: Bool
  public let userWasVerified: Bool
  public let backupEligible: Bool
  public let backupState: Bool
  public let authenticatorExtensionOutputs: CBORValue?
  public let authenticatorAttachment: WebAuthnAuthenticatorTransport

  /// Minimal wire submission sent to an RP verifier.
  public var submission: WebAuthnAssertionSubmission {
    WebAuthnAssertionSubmission(
      uncheckedCredentialID: credentialID,
      clientDataJSON: clientDataJSON,
      authenticatorData: authenticatorData,
      signature: signature,
      userHandle: userHandle
    )
  }
}

/// Untrusted assertion fields accepted at an RP's network boundary.
///
/// Construction performs only resource bounds. Trust is established solely by
/// `WebAuthnServerAssertionVerifier` against server-retained ceremony state.
public struct WebAuthnAssertionSubmission: Sendable {
  public let credentialID: Data
  public let clientDataJSON: Data
  public let authenticatorData: Data
  public let signature: Data
  public let userHandle: Data?

  public init(
    credentialID: Data,
    clientDataJSON: Data,
    authenticatorData: Data,
    signature: Data,
    userHandle: Data?
  ) throws {
    guard !credentialID.isEmpty, credentialID.count <= 1_024 else {
      throw WebAuthnError.credentialIDOutOfBounds
    }
    guard !clientDataJSON.isEmpty, clientDataJSON.count <= 4_096,
      authenticatorData.count >= 37, authenticatorData.count <= 128 << 10,
      !signature.isEmpty, signature.count <= 8_192
    else {
      throw WebAuthnError.invalidAssertionResponse
    }
    if let userHandle {
      guard !userHandle.isEmpty, userHandle.count <= 64 else {
        throw WebAuthnError.userHandleMismatch
      }
      self.userHandle = Data(userHandle)
    } else {
      self.userHandle = nil
    }
    self.credentialID = Data(credentialID)
    self.clientDataJSON = Data(clientDataJSON)
    self.authenticatorData = Data(authenticatorData)
    self.signature = Data(signature)
  }

  fileprivate init(
    uncheckedCredentialID credentialID: Data,
    clientDataJSON: Data,
    authenticatorData: Data,
    signature: Data,
    userHandle: Data?
  ) {
    self.credentialID = Data(credentialID)
    self.clientDataJSON = Data(clientDataJSON)
    self.authenticatorData = Data(authenticatorData)
    self.signature = Data(signature)
    self.userHandle = userHandle.map { Data($0) }
  }
}
