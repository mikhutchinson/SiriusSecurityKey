import Foundation
import Testing

@testable import SiriusSecurityKey

private struct AllowIntent: WebAuthnUserIntentAuthorizer {
  func authorize(_ request: WebAuthnUserIntentRequest) async throws {}
}

func assertionCeremony(
  allowCredentials: [WebAuthnCredentialDescriptor],
  userVerification: WebAuthnUserVerificationRequirement = .required
) async throws -> ValidatedWebAuthnAssertionCeremony {
  try await ValidatedWebAuthnAssertionCeremony.authorize(
    WebAuthnAssertionRequest(
      origin: WebAuthnOrigin("https://login.example.com"),
      relyingPartyID: "example.com",
      challenge: Data(repeating: 0x5a, count: 32),
      allowCredentials: allowCredentials,
      userVerification: userVerification
    ),
    using: AllowIntent()
  )
}

func assertionAuthenticatorInfo(
  versions: [String] = ["FIDO_2_1"],
  options: [String: Bool] = ["rk": true, "uv": true],
  maximumMessageSize: UInt32 = 4_096,
  maximumCredentialCount: UInt32? = 64,
  maximumCredentialIDLength: UInt32? = 1_024,
  transports: [String] = ["hybrid", "internal"]
) throws -> AuthenticatorInfo {
  var entries = [
    CBORMapEntry(
      key: .unsigned(1),
      value: .array(versions.map(CBORValue.textString))
    ),
    CBORMapEntry(
      key: .unsigned(3),
      value: .byteString(Data(repeating: 0, count: 16))
    ),
    CBORMapEntry(
      key: .unsigned(4),
      value: .map(
        options.map { key, value in
          CBORMapEntry(key: .textString(key), value: .boolean(value))
        })
    ),
    CBORMapEntry(key: .unsigned(5), value: .unsigned(maximumMessageSize)),
    CBORMapEntry(
      key: .unsigned(9),
      value: .array(transports.map(CBORValue.textString))
    ),
  ]
  if let maximumCredentialCount {
    entries.append(
      CBORMapEntry(key: .unsigned(7), value: .unsigned(maximumCredentialCount))
    )
  }
  if let maximumCredentialIDLength {
    entries.append(
      CBORMapEntry(key: .unsigned(8), value: .unsigned(maximumCredentialIDLength))
    )
  }
  return try AuthenticatorInfoParser.parse(
    payload: CanonicalCBOR.encode(.map(entries))
  )
}

func assertionAuthenticatorData(
  rpID: String = "example.com",
  flags: UInt8 = 0x05,
  signCount: UInt32 = 42,
  extensionOutputs: CBORValue? = nil
) throws -> Data {
  var result = ProtocolCryptography.sha256(Data(rpID.utf8))
  result.append(flags)
  result.append(UInt8((signCount >> 24) & 0xff))
  result.append(UInt8((signCount >> 16) & 0xff))
  result.append(UInt8((signCount >> 8) & 0xff))
  result.append(UInt8(signCount & 0xff))
  if let extensionOutputs {
    result.append(try CanonicalCBOR.encode(extensionOutputs))
  }
  return result
}

func assertionResponse(
  credentialID: Data? = Data([0xa1]),
  authenticatorData: Data,
  signature: Data = Data([0x30, 0x01]),
  userID: Data? = nil,
  userName: String? = nil,
  numberOfCredentials: UInt32? = nil,
  userSelected: Bool? = nil
) throws -> CTAPResponse {
  var entries = [
    CBORMapEntry(key: .unsigned(2), value: .byteString(authenticatorData)),
    CBORMapEntry(key: .unsigned(3), value: .byteString(signature)),
  ]
  if let credentialID {
    entries.append(
      CBORMapEntry(
        key: .unsigned(1),
        value: .map([
          CBORMapEntry(key: .textString("id"), value: .byteString(credentialID)),
          CBORMapEntry(
            key: .textString("type"),
            value: .textString("public-key")
          ),
        ])
      )
    )
  }
  if let userID {
    var userEntries = [
      CBORMapEntry(key: .textString("id"), value: .byteString(userID))
    ]
    if let userName {
      userEntries.append(
        CBORMapEntry(key: .textString("name"), value: .textString(userName))
      )
    }
    entries.append(
      CBORMapEntry(key: .unsigned(4), value: .map(userEntries))
    )
  }
  if let numberOfCredentials {
    entries.append(
      CBORMapEntry(key: .unsigned(5), value: .unsigned(numberOfCredentials))
    )
  }
  if let userSelected {
    entries.append(
      CBORMapEntry(key: .unsigned(6), value: .boolean(userSelected))
    )
  }
  return CTAPResponse(
    status: 0,
    payload: try CanonicalCBOR.encode(.map(entries))
  )
}

@Test("Compiler emits one exact canonical CTAP2 getAssertion plan")
func compileExactGetAssertionPlan() async throws {
  let descriptor = try WebAuthnCredentialDescriptor(
    id: Data([0xa1]),
    transports: [.hybrid, .internal]
  )
  let ceremony = try await assertionCeremony(allowCredentials: [descriptor])
  let plan = try WebAuthnAssertionPlanCompiler.compile(
    ceremony: ceremony,
    authenticatorInfo: assertionAuthenticatorInfo()
  )

  #expect(plan.operation == .getAssertion)
  #expect(plan.initialRequest.command == 0x02)
  #expect(plan.requiresUserVerification)
  let body = try CanonicalCBOR.decode(plan.initialRequest.payload)
  #expect(body.value(forUnsignedKey: 1) == .textString("example.com"))
  #expect(body.value(forUnsignedKey: 2) == .byteString(ceremony.clientData.hash))
  guard case .array(let allowList)? = body.value(forUnsignedKey: 3),
    allowList.count == 1,
    case .map(let descriptorEntries) = allowList[0]
  else {
    Issue.record("missing canonical allowList")
    return
  }
  #expect(descriptorEntries.count == 2)
  #expect(allowList[0].value(forTextKey: "id") == .byteString(Data([0xa1])))
  #expect(allowList[0].value(forTextKey: "type") == .textString("public-key"))
  #expect(allowList[0].value(forTextKey: "transports") == nil)
  #expect(
    body.value(forUnsignedKey: 5)
      == .map([CBORMapEntry(key: .textString("uv"), value: .boolean(true))])
  )
  #expect(try CanonicalCBOR.encode(body) == plan.initialRequest.payload)
}

@Test("Compiler forbids U2F, UV downgrade and unsupported discoverable routes")
func compilerCapabilityFailures() async throws {
  let allowList = [try WebAuthnCredentialDescriptor(id: Data([1]))]
  let required = try await assertionCeremony(allowCredentials: allowList)

  #expect(throws: WebAuthnError.authenticatorCapabilityMismatch) {
    try WebAuthnAssertionPlanCompiler.compile(
      ceremony: required,
      authenticatorInfo: assertionAuthenticatorInfo(versions: ["U2F_V2"])
    )
  }
  #expect(throws: WebAuthnError.authenticatorCapabilityMismatch) {
    try WebAuthnAssertionPlanCompiler.compile(
      ceremony: required,
      authenticatorInfo: assertionAuthenticatorInfo(versions: ["FIDO_2_UNKNOWN"])
    )
  }
  #expect(throws: WebAuthnError.userVerificationUnavailable) {
    try WebAuthnAssertionPlanCompiler.compile(
      ceremony: required,
      authenticatorInfo: assertionAuthenticatorInfo(options: ["rk": true])
    )
  }

  let discoverable = try await assertionCeremony(allowCredentials: [])
  #expect(throws: WebAuthnError.discoverableCredentialsUnsupported) {
    try WebAuthnAssertionPlanCompiler.compile(
      ceremony: discoverable,
      authenticatorInfo: assertionAuthenticatorInfo(options: ["uv": true])
    )
  }
  #expect(throws: WebAuthnError.userVerificationUnavailable) {
    try WebAuthnAssertionPlanCompiler.compile(
      ceremony: discoverable,
      authenticatorInfo: assertionAuthenticatorInfo(options: ["rk": true])
    )
  }
}

@Test("Compiler honors authenticator allow-list and credential bounds")
func compilerAuthenticatorBounds() async throws {
  let ceremony = try await assertionCeremony(
    allowCredentials: [
      try WebAuthnCredentialDescriptor(id: Data([1, 2])),
      try WebAuthnCredentialDescriptor(id: Data([3, 4])),
    ]
  )
  #expect(throws: WebAuthnError.credentialListTooLarge) {
    try WebAuthnAssertionPlanCompiler.compile(
      ceremony: ceremony,
      authenticatorInfo: assertionAuthenticatorInfo(maximumCredentialCount: 1)
    )
  }
  #expect(throws: WebAuthnError.credentialIDOutOfBounds) {
    try WebAuthnAssertionPlanCompiler.compile(
      ceremony: ceremony,
      authenticatorInfo: assertionAuthenticatorInfo(maximumCredentialIDLength: 1)
    )
  }
}

@Test("Assertion authenticator data parses flags, counter and canonical extensions")
func parseAssertionAuthenticatorData() throws {
  let extensionMap = CBORValue.map([
    CBORMapEntry(key: .textString("example"), value: .boolean(true))
  ])
  let bytes = try assertionAuthenticatorData(
    flags: 0x9d,
    signCount: 0x0102_0304,
    extensionOutputs: extensionMap
  )
  let parsed = try AuthenticatorDataParser.parseAssertion(bytes)
  #expect(parsed.flags.contains(.userPresent))
  #expect(parsed.flags.contains(.userVerified))
  #expect(parsed.flags.contains(.backupEligible))
  #expect(parsed.flags.contains(.backupState))
  #expect(parsed.flags.contains(.extensionData))
  #expect(parsed.signCount == 0x0102_0304)
  #expect(parsed.extensionOutputs == extensionMap)
  #expect(parsed.rawBytes == bytes)
}

@Test("Assertion authenticator data rejects malformed flag and extension states")
func rejectMalformedAssertionAuthenticatorData() throws {
  let short = Data(repeating: 0, count: 36)
  #expect(throws: WebAuthnError.invalidAuthenticatorData) {
    try AuthenticatorDataParser.parseAssertion(short)
  }
  #expect(throws: WebAuthnError.invalidBackupState) {
    try AuthenticatorDataParser.parseAssertion(
      assertionAuthenticatorData(flags: 0x11)
    )
  }
  #expect(throws: WebAuthnError.invalidAuthenticatorData) {
    try AuthenticatorDataParser.parseAssertion(
      assertionAuthenticatorData(flags: 0x41)
    )
  }
  #expect(throws: WebAuthnError.invalidAuthenticatorData) {
    try AuthenticatorDataParser.parseAssertion(
      assertionAuthenticatorData(flags: 0x81)
    )
  }
  var trailing = try assertionAuthenticatorData(flags: 0x01)
  trailing.append(0xa0)
  #expect(throws: WebAuthnError.invalidAuthenticatorData) {
    try AuthenticatorDataParser.parseAssertion(trailing)
  }
  #expect(throws: WebAuthnError.invalidAuthenticatorData) {
    try AuthenticatorDataParser.parseAssertion(
      assertionAuthenticatorData(
        flags: 0x81,
        extensionOutputs: .array([])
      )
    )
  }
}

@Test("Strict assertion response binds RP, UP, UV, credential and counter")
func parseBoundAssertionResponse() async throws {
  let descriptor = try WebAuthnCredentialDescriptor(id: Data([0xa1]))
  let ceremony = try await assertionCeremony(allowCredentials: [descriptor])
  let plan = try WebAuthnAssertionPlanCompiler.compile(
    ceremony: ceremony,
    authenticatorInfo: assertionAuthenticatorInfo()
  )
  let response = try assertionResponse(
    credentialID: nil,
    authenticatorData: assertionAuthenticatorData(signCount: 42)
  )
  let parsed = try CTAPAssertionResponseParser.parse(
    response,
    plan: plan,
    isFirstResponse: true
  )
  let assertion = try CTAPAssertionResponseParser.finish(
    responses: [parsed],
    plan: plan,
    selectedResponseIndex: nil
  )
  #expect(assertion.credentialID == Data([0xa1]))
  #expect(assertion.signCount == 42)
  #expect(assertion.userWasPresent)
  #expect(assertion.userWasVerified)
  #expect(assertion.clientDataJSON == ceremony.clientData.json)
}

@Test("Assertion response mismatches terminate without normalization")
func rejectAssertionResponseMismatches() async throws {
  let ceremony = try await assertionCeremony(
    allowCredentials: [try WebAuthnCredentialDescriptor(id: Data([0xa1]))]
  )
  let plan = try WebAuthnAssertionPlanCompiler.compile(
    ceremony: ceremony,
    authenticatorInfo: assertionAuthenticatorInfo()
  )

  #expect(throws: WebAuthnError.relyingPartyHashMismatch) {
    try CTAPAssertionResponseParser.parse(
      assertionResponse(authenticatorData: assertionAuthenticatorData(rpID: "evil.com")),
      plan: plan,
      isFirstResponse: true
    )
  }
  #expect(throws: WebAuthnError.userPresenceMissing) {
    try CTAPAssertionResponseParser.parse(
      assertionResponse(authenticatorData: assertionAuthenticatorData(flags: 0x04)),
      plan: plan,
      isFirstResponse: true
    )
  }
  #expect(throws: WebAuthnError.userVerificationMissing) {
    try CTAPAssertionResponseParser.parse(
      assertionResponse(authenticatorData: assertionAuthenticatorData(flags: 0x01)),
      plan: plan,
      isFirstResponse: true
    )
  }
  #expect(throws: WebAuthnError.credentialMismatch) {
    try CTAPAssertionResponseParser.parse(
      assertionResponse(
        credentialID: Data([0xff]),
        authenticatorData: assertionAuthenticatorData()
      ),
      plan: plan,
      isFirstResponse: true
    )
  }
  #expect(throws: WebAuthnError.ctapStatus(0x2e)) {
    try CTAPAssertionResponseParser.parse(
      CTAPResponse(status: 0x2e),
      plan: plan,
      isFirstResponse: true
    )
  }
}

@Test("Bounded getNextAssertion results require explicit account selection")
func multipleDiscoverableAssertions() async throws {
  let ceremony = try await assertionCeremony(allowCredentials: [])
  let plan = try WebAuthnAssertionPlanCompiler.compile(
    ceremony: ceremony,
    authenticatorInfo: assertionAuthenticatorInfo()
  )
  let first = try CTAPAssertionResponseParser.parse(
    assertionResponse(
      credentialID: Data([1]),
      authenticatorData: assertionAuthenticatorData(signCount: 10),
      userID: Data([0x11]),
      userName: "first",
      numberOfCredentials: 2
    ),
    plan: plan,
    isFirstResponse: true
  )
  let second = try CTAPAssertionResponseParser.parse(
    assertionResponse(
      credentialID: Data([2]),
      authenticatorData: assertionAuthenticatorData(signCount: 20),
      userID: Data([0x22]),
      userName: "second"
    ),
    plan: plan,
    isFirstResponse: false
  )
  let candidates = try CTAPAssertionResponseParser.accountCandidates(
    for: [first, second],
    maximumAssertionCount: plan.maximumAssertionCount
  )
  #expect(candidates.map(\.name) == ["first", "second"])
  #expect(throws: WebAuthnError.accountSelectionRequired) {
    try CTAPAssertionResponseParser.finish(
      responses: [first, second],
      plan: plan,
      selectedResponseIndex: nil
    )
  }
  let assertion = try CTAPAssertionResponseParser.finish(
    responses: [first, second],
    plan: plan,
    selectedResponseIndex: 1
  )
  #expect(assertion.credentialID == Data([2]))
  #expect(assertion.userHandle == Data([0x22]))
  #expect(assertion.signCount == 20)
}

@Test("Assertion count and follow-up response fields are strictly bounded")
func assertionResponseCountBounds() async throws {
  let ceremony = try await assertionCeremony(allowCredentials: [])
  let plan = try WebAuthnAssertionPlanCompiler.compile(
    ceremony: ceremony,
    authenticatorInfo: assertionAuthenticatorInfo()
  )
  #expect(throws: WebAuthnError.tooManyAssertions) {
    try CTAPAssertionResponseParser.parse(
      assertionResponse(
        authenticatorData: assertionAuthenticatorData(),
        userID: Data([1]),
        numberOfCredentials: 65
      ),
      plan: plan,
      isFirstResponse: true
    )
  }
  #expect(throws: WebAuthnError.invalidAssertionResponse) {
    try CTAPAssertionResponseParser.parse(
      assertionResponse(
        authenticatorData: assertionAuthenticatorData(),
        userID: Data([1]),
        numberOfCredentials: 2
      ),
      plan: plan,
      isFirstResponse: false
    )
  }
}

@Test("Every truncated assertion response is rejected before field access")
func assertionResponseTruncations() async throws {
  let ceremony = try await assertionCeremony(
    allowCredentials: [try WebAuthnCredentialDescriptor(id: Data([0xa1]))]
  )
  let plan = try WebAuthnAssertionPlanCompiler.compile(
    ceremony: ceremony,
    authenticatorInfo: assertionAuthenticatorInfo()
  )
  let response = try assertionResponse(
    authenticatorData: assertionAuthenticatorData()
  )
  for end in 0..<response.payload.count {
    #expect(throws: WebAuthnError.self) {
      try CTAPAssertionResponseParser.parse(
        CTAPResponse(status: 0, payload: response.payload.prefix(end)),
        plan: plan,
        isFirstResponse: true
      )
    }
  }
}
