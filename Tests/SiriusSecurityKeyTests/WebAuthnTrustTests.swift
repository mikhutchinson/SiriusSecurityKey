import Foundation
import Testing

@testable import SiriusSecurityKey

private actor RecordingIntentAuthorizer: WebAuthnUserIntentAuthorizer {
  private(set) var requests: [WebAuthnUserIntentRequest] = []
  let outcome: Outcome

  enum Outcome: Sendable {
    case allow
    case deny
    case cancel
  }

  init(_ outcome: Outcome = .allow) {
    self.outcome = outcome
  }

  func authorize(_ request: WebAuthnUserIntentRequest) async throws {
    requests.append(request)
    switch outcome {
    case .allow:
      return
    case .deny:
      throw WebAuthnError.userIntentDenied
    case .cancel:
      throw CancellationError()
    }
  }
}

@Test("WebAuthn origin uses pinned UTS 46 normalization and exact serialization")
func webAuthnOriginNormalization() throws {
  let unicode = try WebAuthnOrigin("https://BÜCHER.example:443/")
  #expect(unicode.scheme == "https")
  #expect(unicode.host == "xn--bcher-kva.example")
  #expect(unicode.port == nil)
  #expect(unicode.serialized == "https://xn--bcher-kva.example")

  let local = try WebAuthnOrigin("http://LOGIN.localhost:8080")
  #expect(local.serialized == "http://login.localhost:8080")
}

@Test("Untrustworthy and non-origin URL inputs fail closed")
func webAuthnOriginRejections() {
  let rejected = [
    "http://example.com",
    "https://user@example.com",
    "https://example.com/path",
    "https://example.com/?query=1",
    "https://example.com/#fragment",
    "https://127.0.0.1",
    "https://[::1]",
    "ftp://example.com",
  ]
  for input in rejected {
    #expect(throws: WebAuthnError.self) {
      try WebAuthnOrigin(input)
    }
  }
}

@Test("RP ID binding includes private PSL rules and exception rules")
func relyingPartyBindingUsesPinnedPSL() throws {
  let origin = try WebAuthnOrigin("https://login.example.com")
  let request = try WebAuthnAssertionRequest(
    origin: origin,
    relyingPartyID: "EXAMPLE.com",
    challenge: Data(repeating: 1, count: 32),
    allowCredentials: [],
    userVerification: .required
  )
  #expect(request.relyingPartyID.value == "example.com")

  #expect(throws: WebAuthnError.relyingPartyIDIsPublicSuffix) {
    try WebAuthnAssertionRequest(
      origin: WebAuthnOrigin("https://tenant.appspot.com"),
      relyingPartyID: "appspot.com",
      challenge: Data(repeating: 1, count: 32),
      allowCredentials: [],
      userVerification: .required
    )
  }
  #expect(throws: WebAuthnError.relyingPartyIDIsPublicSuffix) {
    try WebAuthnAssertionRequest(
      origin: WebAuthnOrigin("https://tenant.up.railway.app"),
      relyingPartyID: "up.railway.app",
      challenge: Data(repeating: 1, count: 32),
      allowCredentials: [],
      userVerification: .required
    )
  }

  let exception = try WebAuthnAssertionRequest(
    origin: WebAuthnOrigin("https://login.city.kawasaki.jp"),
    relyingPartyID: "city.kawasaki.jp",
    challenge: Data(repeating: 1, count: 32),
    allowCredentials: [],
    userVerification: .required
  )
  #expect(exception.relyingPartyID.value == "city.kawasaki.jp")
}

@Test("RP ID cannot escape the normalized origin")
func relyingPartyBindingRejectsUnrelatedDomains() throws {
  let origin = try WebAuthnOrigin("https://login.example.com")
  for rpID in ["evil.com", "ample.com", "com", "example.com.", "https://example.com"] {
    #expect(throws: WebAuthnError.self) {
      try WebAuthnAssertionRequest(
        origin: origin,
        relyingPartyID: rpID,
        challenge: Data(repeating: 1, count: 32),
        allowCredentials: [],
        userVerification: .required
      )
    }
  }
}

@Test("Collected client data has exact WebAuthn Level 3 normal form bytes")
func exactAssertionClientDataJSON() async throws {
  let authorizer = RecordingIntentAuthorizer()
  let ceremony = try await ValidatedWebAuthnAssertionCeremony.authorize(
    WebAuthnAssertionRequest(
      origin: WebAuthnOrigin("https://login.example.com"),
      relyingPartyID: "example.com",
      challenge: Data(0...15),
      allowCredentials: [
        try WebAuthnCredentialDescriptor(id: Data([0xaa]), transports: [.hybrid])
      ],
      userVerification: .required
    ),
    using: authorizer
  )

  let expected =
    #"{"type":"webauthn.get","challenge":"AAECAwQFBgcICQoLDA0ODw","origin":"https://login.example.com","crossOrigin":false}"#
  #expect(ceremony.clientData.json == Data(expected.utf8))
  #expect(
    ceremony.clientData.hash.testHex
      == "46f1878ce4e2ddba32f788e73968f3bca685d43bfc7ddffba91be4e2e7da9b5c"
  )
  #expect(ceremony.relyingPartyID.value == "example.com")
  #expect(!ceremony.isDiscoverable)
  #expect(await authorizer.requests.count == 1)
}

@Test("Explicit intent denial and cancellation cannot construct a ceremony")
func ceremonyAuthorizationFailsClosed() async throws {
  let request = try WebAuthnAssertionRequest(
    origin: WebAuthnOrigin("https://example.com"),
    relyingPartyID: "example.com",
    challenge: Data(repeating: 2, count: 32),
    allowCredentials: [],
    userVerification: .required
  )
  await #expect(throws: WebAuthnError.userIntentDenied) {
    try await ValidatedWebAuthnAssertionCeremony.authorize(
      request,
      using: RecordingIntentAuthorizer(.deny)
    )
  }
  await #expect(throws: WebAuthnError.cancelled) {
    try await ValidatedWebAuthnAssertionCeremony.authorize(
      request,
      using: RecordingIntentAuthorizer(.cancel)
    )
  }
}

@Test("Ceremony inputs reject unbounded and duplicate attacker data")
func ceremonyInputBounds() throws {
  let origin = try WebAuthnOrigin("https://example.com")
  #expect(throws: WebAuthnError.challengeOutOfBounds) {
    try WebAuthnAssertionRequest(
      origin: origin,
      relyingPartyID: "example.com",
      challenge: Data(repeating: 0, count: 15),
      allowCredentials: [],
      userVerification: .required
    )
  }
  let duplicate = try WebAuthnCredentialDescriptor(id: Data([1]))
  #expect(throws: WebAuthnError.duplicateCredential) {
    try WebAuthnAssertionRequest(
      origin: origin,
      relyingPartyID: "example.com",
      challenge: Data(repeating: 0, count: 16),
      allowCredentials: [duplicate, duplicate],
      userVerification: .required
    )
  }
  #expect(throws: WebAuthnError.credentialIDOutOfBounds) {
    try WebAuthnCredentialDescriptor(id: Data(repeating: 0, count: 1_025))
  }
}
