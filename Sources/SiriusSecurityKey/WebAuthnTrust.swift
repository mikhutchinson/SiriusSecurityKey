import Foundation
import WebURL

/// Stable, secret-free WebAuthn failure categories.
public enum WebAuthnError: Error, Sendable, Equatable {
  case invalidOrigin
  case untrustworthyOrigin
  case invalidRelyingPartyID
  case relyingPartyIDIsPublicSuffix
  case challengeOutOfBounds
  case credentialListTooLarge
  case credentialIDOutOfBounds
  case duplicateCredential
  case userIntentDenied
  case cancelled
  case authenticatorCapabilityMismatch
  case discoverableCredentialsUnsupported
  case userVerificationUnavailable
  case ctapMessageTooLarge
  case invalidAuthenticatorData
  case relyingPartyHashMismatch
  case userPresenceMissing
  case userVerificationMissing
  case invalidBackupState
  case invalidAssertionResponse
  case credentialMismatch
  case accountSelectionRequired
  case invalidAccountSelection
  case accountSelectionTimedOut
  case tooManyAssertions
  case ctapStatus(UInt8)
  case clientDataMismatch
  case credentialPublicKeyInvalid
  case signatureInvalid
  case signatureCounterRollback
  case userHandleMismatch
}

/// A normalized, potentially trustworthy WebAuthn origin.
///
/// Construction performs pinned WHATWG/UTS #46 parsing. It accepts HTTPS, or
/// HTTP only for `localhost` and its subdomains. IP literals, credentials,
/// non-origin paths, queries, fragments, and invalid DNS labels are rejected.
public struct WebAuthnOrigin: Sendable, Hashable {
  public let scheme: String
  public let host: String
  public let port: Int?
  public let serialized: String

  public init(_ input: String) throws {
    guard !input.isEmpty, input.utf8.count <= 2_048,
      let url = WebURL(input),
      url.username == nil,
      url.password == nil,
      url.path == "/",
      url.query == nil,
      url.fragment == nil,
      let host = url.hostname,
      !host.isEmpty,
      !host.hasSuffix("."),
      Self.isValidDNSHost(host),
      !Self.isIPAddress(host)
    else {
      throw WebAuthnError.invalidOrigin
    }

    let isLocalhost = host == "localhost" || host.hasSuffix(".localhost")
    guard url.scheme == "https" || (url.scheme == "http" && isLocalhost) else {
      throw WebAuthnError.untrustworthyOrigin
    }

    scheme = url.scheme
    self.host = host
    port = url.port
    if let port = url.port {
      serialized = "\(url.scheme)://\(host):\(port)"
    } else {
      serialized = "\(url.scheme)://\(host)"
    }
  }

  fileprivate static func canonicalRelyingPartyHost(_ input: String) throws -> String {
    guard !input.isEmpty, input.utf8.count <= 253,
      !input.contains(":"),
      !input.contains("/"),
      !input.contains("\\"),
      !input.contains("?"),
      !input.contains("#"),
      !input.contains("@"),
      !input.hasSuffix("."),
      let url = WebURL("https://\(input)/"),
      url.username == nil,
      url.password == nil,
      url.port == nil,
      url.path == "/",
      url.query == nil,
      url.fragment == nil,
      let host = url.hostname,
      isValidDNSHost(host),
      !isIPAddress(host)
    else {
      throw WebAuthnError.invalidRelyingPartyID
    }
    return host
  }

  fileprivate static func isValidDNSHost(_ host: String) -> Bool {
    guard !host.isEmpty, host.utf8.count <= 253 else {
      return false
    }
    let labels = host.split(separator: ".", omittingEmptySubsequences: false)
    guard !labels.isEmpty else {
      return false
    }
    return labels.allSatisfy { label in
      guard !label.isEmpty, label.utf8.count <= 63,
        label.first != "-", label.last != "-"
      else {
        return false
      }
      return label.utf8.allSatisfy { byte in
        (byte >= 0x61 && byte <= 0x7a)
          || (byte >= 0x30 && byte <= 0x39)
          || byte == 0x2d
      }
    }
  }

  fileprivate static func isIPAddress(_ host: String) -> Bool {
    if host.contains(":") || host.hasPrefix("[") || host.hasSuffix("]") {
      return true
    }
    let labels = host.split(separator: ".", omittingEmptySubsequences: false)
    guard labels.count == 4 else {
      return false
    }
    return labels.allSatisfy { label in
      guard !label.isEmpty, label.count <= 3,
        label.allSatisfy({ $0.isASCII && $0.isNumber }),
        let value = UInt8(label)
      else {
        return false
      }
      return String(value) == label || (value == 0 && label == "0")
    }
  }
}

/// An RP ID that has been normalized and authorized for one immutable origin.
public struct WebAuthnRelyingPartyID: Sendable, Hashable {
  public let value: String
  public let origin: WebAuthnOrigin

  fileprivate init(value: String, origin: WebAuthnOrigin) {
    self.value = value
    self.origin = origin
  }
}

enum WebAuthnTrustValidator {
  static func validateRelyingPartyID(
    _ input: String,
    for origin: WebAuthnOrigin
  ) throws -> WebAuthnRelyingPartyID {
    let rpID = try WebAuthnOrigin.canonicalRelyingPartyHost(input)
    if rpID == origin.host {
      return WebAuthnRelyingPartyID(value: rpID, origin: origin)
    }

    guard origin.host.hasSuffix(".\(rpID)") else {
      throw WebAuthnError.invalidRelyingPartyID
    }

    let database: PublicSuffixDatabase
    do {
      database = try PublicSuffixDatabase.bundled()
    } catch {
      throw WebAuthnError.invalidRelyingPartyID
    }

    guard database.registrableDomain(for: rpID) != nil else {
      throw WebAuthnError.relyingPartyIDIsPublicSuffix
    }
    guard let callerPublicSuffix = database.publicSuffix(for: origin.host) else {
      throw WebAuthnError.invalidRelyingPartyID
    }

    let claimedLabels = rpID.split(separator: ".").count
    let callerSuffixLabels = callerPublicSuffix.split(separator: ".").count
    guard claimedLabels > callerSuffixLabels else {
      throw WebAuthnError.relyingPartyIDIsPublicSuffix
    }
    return WebAuthnRelyingPartyID(value: rpID, origin: origin)
  }
}
