import CryptoKit
import Foundation

/// Server-side registration record for one ES256 WebAuthn credential.
public struct WebAuthnES256CredentialRecord: Sendable {
  public let credentialID: Data
  public let publicKeyX963Representation: Data
  public let previousSignCount: UInt32
  public let userHandle: Data?

  public init(
    credentialID: Data,
    publicKeyX963Representation: Data,
    previousSignCount: UInt32,
    userHandle: Data? = nil
  ) throws {
    guard !credentialID.isEmpty, credentialID.count <= 1_024 else {
      throw WebAuthnError.credentialIDOutOfBounds
    }
    guard publicKeyX963Representation.count == 65,
      (try? P256.Signing.PublicKey(
        x963Representation: publicKeyX963Representation
      )) != nil
    else {
      throw WebAuthnError.credentialPublicKeyInvalid
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
    self.publicKeyX963Representation = Data(publicKeyX963Representation)
    self.previousSignCount = previousSignCount
  }
}

/// Exact server-owned facts retained when issuing an assertion challenge.
public struct WebAuthnAssertionVerificationContext: Sendable {
  public enum Mode: String, Sendable {
    case allowList
    case discoverable
  }

  public let mode: Mode
  public let challenge: Data
  public let origin: WebAuthnOrigin
  public let relyingPartyID: WebAuthnRelyingPartyID
  public let userVerification: WebAuthnUserVerificationRequirement
  public let credentialRecords: [WebAuthnES256CredentialRecord]

  public init(
    mode: Mode,
    challenge: Data,
    origin: WebAuthnOrigin,
    relyingPartyID: String,
    userVerification: WebAuthnUserVerificationRequirement,
    credentialRecords: [WebAuthnES256CredentialRecord]
  ) throws {
    guard challenge.count >= 16, challenge.count <= 1_024 else {
      throw WebAuthnError.challengeOutOfBounds
    }
    guard !credentialRecords.isEmpty, credentialRecords.count <= 64 else {
      throw WebAuthnError.credentialListTooLarge
    }
    var credentialIDs: Set<Data> = []
    for record in credentialRecords {
      guard credentialIDs.insert(record.credentialID).inserted else {
        throw WebAuthnError.duplicateCredential
      }
    }

    self.mode = mode
    self.challenge = Data(challenge)
    self.origin = origin
    self.relyingPartyID = try WebAuthnTrustValidator.validateRelyingPartyID(
      relyingPartyID,
      for: origin
    )
    self.userVerification = userVerification
    self.credentialRecords = credentialRecords
  }
}

/// Server-side receipt after every client-data, authenticator-data, signature,
/// user-handle and counter gate has passed.
public struct VerifiedWebAuthnAssertion: Sendable {
  public let credentialID: Data
  public let userHandle: Data?
  public let signCount: UInt32
  public let shouldStoreSignCount: Bool
  public let userWasVerified: Bool
  public let backupEligible: Bool
  public let backupState: Bool
}

/// Independent RP-side verifier for the package's strict ES256 assertion
/// profile. The verifier takes server-retained ceremony facts; it never trusts
/// client-derived origin, RP ID, UV or counter state.
public enum WebAuthnServerAssertionVerifier {
  public static func verify(
    _ assertion: WebAuthnAssertion,
    against context: WebAuthnAssertionVerificationContext
  ) throws -> VerifiedWebAuthnAssertion {
    try verify(assertion.submission, against: context)
  }

  public static func verify(
    _ assertion: WebAuthnAssertionSubmission,
    against context: WebAuthnAssertionVerificationContext
  ) throws -> VerifiedWebAuthnAssertion {
    let expectedClientData = WebAuthnClientDataBuilder.assertion(
      challenge: context.challenge,
      origin: context.origin
    )
    guard assertion.clientDataJSON == expectedClientData.json else {
      throw WebAuthnError.clientDataMismatch
    }

    guard
      let credential = context.credentialRecords.first(where: {
        $0.credentialID == assertion.credentialID
      })
    else {
      throw WebAuthnError.credentialMismatch
    }
    if context.mode == .discoverable {
      guard let returnedUserHandle = assertion.userHandle,
        let expectedUserHandle = credential.userHandle,
        returnedUserHandle == expectedUserHandle
      else {
        throw WebAuthnError.userHandleMismatch
      }
    } else if let returnedUserHandle = assertion.userHandle {
      guard credential.userHandle == returnedUserHandle else {
        throw WebAuthnError.userHandleMismatch
      }
    }

    let authenticatorData = try AuthenticatorDataParser.parseAssertion(
      assertion.authenticatorData
    )
    let expectedRPIDHash = ProtocolCryptography.sha256(
      Data(context.relyingPartyID.value.utf8)
    )
    guard authenticatorData.relyingPartyIDHash == expectedRPIDHash else {
      throw WebAuthnError.relyingPartyHashMismatch
    }
    guard authenticatorData.flags.contains(.userPresent) else {
      throw WebAuthnError.userPresenceMissing
    }
    if context.mode == .discoverable || context.userVerification == .required {
      guard authenticatorData.flags.contains(.userVerified) else {
        throw WebAuthnError.userVerificationMissing
      }
    }

    let publicKey: P256.Signing.PublicKey
    let signature: P256.Signing.ECDSASignature
    do {
      publicKey = try P256.Signing.PublicKey(
        x963Representation: credential.publicKeyX963Representation
      )
      signature = try P256.Signing.ECDSASignature(
        derRepresentation: assertion.signature
      )
    } catch {
      throw WebAuthnError.signatureInvalid
    }

    var signedBytes = assertion.authenticatorData
    signedBytes.append(expectedClientData.hash)
    guard publicKey.isValidSignature(signature, for: signedBytes) else {
      throw WebAuthnError.signatureInvalid
    }

    let oldCount = credential.previousSignCount
    let newCount = authenticatorData.signCount
    if oldCount != 0 || newCount != 0 {
      guard newCount > oldCount else {
        throw WebAuthnError.signatureCounterRollback
      }
    }

    return VerifiedWebAuthnAssertion(
      credentialID: assertion.credentialID,
      userHandle: assertion.userHandle,
      signCount: newCount,
      shouldStoreSignCount: newCount != 0,
      userWasVerified: authenticatorData.flags.contains(.userVerified),
      backupEligible: authenticatorData.flags.contains(.backupEligible),
      backupState: authenticatorData.flags.contains(.backupState)
    )
  }
}
