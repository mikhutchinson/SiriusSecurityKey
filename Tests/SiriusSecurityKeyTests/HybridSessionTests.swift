import CryptoKit
import Foundation
import Testing

@testable import SiriusSecurityKey

private struct SessionScanner: HybridBluetoothScanner {
  let advertisement: HybridBluetoothAdvertisement

  func scan(
    serviceUUID: UUID
  ) async throws -> AsyncThrowingStream<HybridBluetoothAdvertisement, any Error> {
    AsyncThrowingStream { continuation in
      continuation.yield(advertisement)
      continuation.finish()
    }
  }

  func stop() async {}
}

private struct SessionSleeper: HybridSleeper {
  func sleep(for duration: Duration) async throws {
    try await ContinuousClock().sleep(for: .seconds(60))
  }
}

private final class BlockingSessionScanner: HybridBluetoothScanner, @unchecked Sendable {
  private let lock = NSLock()
  private var continuation:
    AsyncThrowingStream<HybridBluetoothAdvertisement, any Error>.Continuation?

  func scan(
    serviceUUID: UUID
  ) async throws -> AsyncThrowingStream<HybridBluetoothAdvertisement, any Error> {
    let stream = AsyncThrowingStream<HybridBluetoothAdvertisement, any Error> {
      newContinuation in
      lock.lock()
      continuation = newContinuation
      lock.unlock()
    }
    return stream
  }

  func stop() async {
    finish()
  }

  func waitUntilStarted() async {
    while !hasStarted() {
      await Task.yield()
    }
  }

  private func hasStarted() -> Bool {
    lock.lock()
    let started = continuation != nil
    lock.unlock()
    return started
  }

  private func finish() {
    lock.lock()
    let current = continuation
    continuation = nil
    lock.unlock()
    current?.finish()
  }
}

private actor PhoneConnector: HybridWebSocketConnector {
  let channel: ScriptedPhoneChannel
  private(set) var connectedURL: URL?

  init(channel: ScriptedPhoneChannel) {
    self.channel = channel
  }

  func connect(
    to url: URL,
    subprotocol: String,
    maximumMessageSize: Int
  ) async throws -> any HybridBinaryChannel {
    guard url.scheme == "wss", subprotocol == "fido.cable",
      maximumMessageSize == 1 << 20
    else {
      throw HybridProtocolError.invalidTunnelURL
    }
    connectedURL = url
    return channel
  }
}

private actor BlockingConnector: HybridWebSocketConnector {
  private var started = false

  func connect(
    to url: URL,
    subprotocol: String,
    maximumMessageSize: Int
  ) async throws -> any HybridBinaryChannel {
    started = true
    try await ContinuousClock().sleep(for: .seconds(60))
    throw HybridTunnelError.connectionFailed
  }

  func waitUntilStarted() async {
    while !started {
      await Task.yield()
    }
  }
}

private actor ScriptedPhoneChannel: HybridBinaryChannel {
  private let peerIdentity: Data
  private let preSharedKey: Data
  private let responderRandomSource: any HybridRandomSource
  private let profile: HybridWireProfile
  private let getInfoPayload: Data
  private var assertionResponses: [CTAPResponse]
  private var responder: HybridNoiseResponderResult?
  private var queuedMessages: [Data] = []
  private var postHandshakeSent = false
  private(set) var sawShutdown = false
  private(set) var ctapCommands: [UInt8] = []
  private var closed = false

  init(
    peerIdentity: Data,
    preSharedKey: Data,
    responderRandomSource: any HybridRandomSource,
    profile: HybridWireProfile,
    getInfoPayload: Data,
    assertionResponses: [CTAPResponse] = []
  ) {
    self.peerIdentity = peerIdentity
    self.preSharedKey = preSharedKey
    self.responderRandomSource = responderRandomSource
    self.profile = profile
    self.getInfoPayload = getInfoPayload
    self.assertionResponses = assertionResponses
  }

  func send(_ data: Data) async throws {
    guard !closed else {
      throw HybridTunnelError.connectionClosed
    }
    if responder == nil {
      let result = try HybridNoiseTestResponder.respond(
        to: data,
        peerIdentity: peerIdentity,
        preSharedKey: preSharedKey,
        randomSource: responderRandomSource
      )
      responder = result
      queuedMessages.append(result.response)
      return
    }

    guard let responder else {
      throw HybridProtocolError.handshakeStateViolation
    }
    let plaintext = try await responder.cipher.decrypt(data)
    if profile == .pxp20260717, plaintext == Data([0]) {
      sawShutdown = true
      return
    }
    let requestBytes: Data
    switch profile {
    case .pxp20260717:
      guard plaintext.first == 1 else {
        throw HybridProtocolError.invalidHybridMessage
      }
      requestBytes = Data(plaintext.dropFirst())
    case .chromiumCableV2Revision0:
      requestBytes = plaintext
    }
    guard let request = try? CTAPRequest(encoded: requestBytes) else {
      throw HybridProtocolError.invalidHybridMessage
    }
    ctapCommands.append(request.command)

    let ctapResponse: CTAPResponse
    switch request.command {
    case 0x04:
      ctapResponse = CTAPResponse(status: 0, payload: getInfoPayload)
    case 0x02, 0x08:
      guard !assertionResponses.isEmpty else {
        throw HybridTunnelError.receiveFailed
      }
      ctapResponse = assertionResponses.removeFirst()
    default:
      throw HybridProtocolError.invalidHybridMessage
    }
    var response = Data()
    if profile == .pxp20260717 {
      response.append(1)
    }
    response.append(ctapResponse.encoded)
    queuedMessages.append(try await responder.cipher.encrypt(response))
  }

  func receive() async throws -> Data {
    guard !closed else {
      throw HybridTunnelError.connectionClosed
    }
    if !queuedMessages.isEmpty {
      return queuedMessages.removeFirst()
    }
    guard let responder, !postHandshakeSent else {
      throw HybridTunnelError.receiveFailed
    }

    let cbor = try CanonicalCBOR.encode(
      .map([
        CBORMapEntry(key: .unsigned(1), value: .byteString(getInfoPayload)),
        CBORMapEntry(
          key: .unsigned(3),
          value: .array([.textString("ctap")])
        ),
      ]),
      limits: CBORLimits(maximumMessageSize: 128 << 10)
    )
    let postHandshake: Data
    switch profile {
    case .pxp20260717:
      postHandshake = cbor
    case .chromiumCableV2Revision0:
      postHandshake = revisionZeroPadded(cbor)
    }
    postHandshakeSent = true
    return try await responder.cipher.encrypt(postHandshake)
  }

  func cancel() async {
    closed = true
  }

  private func revisionZeroPadded(_ cbor: Data) -> Data {
    let paddedSize = (cbor.count + 2 + 511) & ~511
    let paddingLength = paddedSize - cbor.count - 2
    var result = cbor
    result.append(Data(repeating: 0, count: paddingLength))
    result.append(UInt8(paddingLength & 0xff))
    result.append(UInt8((paddingLength >> 8) & 0xff))
    return result
  }
}

private struct SelectingAccount: WebAuthnAccountSelector {
  let index: Int

  func selectAccount(from candidates: [WebAuthnAccountCandidate]) async throws -> Int {
    index
  }
}

private struct BlockingAccountSelector: WebAuthnAccountSelector {
  func selectAccount(from candidates: [WebAuthnAccountCandidate]) async throws -> Int {
    try await ContinuousClock().sleep(for: .seconds(60))
    return 0
  }
}

private struct SelectionTimeoutSleeper: HybridSleeper {
  func sleep(for duration: Duration) async throws {
    if duration < .seconds(1) {
      return
    }
    try await ContinuousClock().sleep(for: .seconds(60))
  }
}

private struct HybridAssertionFixture {
  let session: HybridSession
  let scanner: SessionScanner
  let phone: ScriptedPhoneChannel
  let connector: PhoneConnector
}

private func makeHybridAssertionFixture(
  profile: HybridWireProfile = .pxp20260717,
  getInfoPayload: Data,
  assertionResponses: [CTAPResponse]
) throws -> HybridAssertionFixture {
  let identity = Data(repeating: 1, count: 32)
  let qrSecret = Data(repeating: 2, count: 16)
  let session = try HybridSession(
    qrConfiguration: HybridQRConfiguration(requestType: .getAssertion),
    wireProfile: profile,
    randomSource: SequenceRandomSource([
      identity,
      qrSecret,
      Data(repeating: 3, count: 32),
    ])
  )
  let parsedQR = try HybridQRCode.parse(session.qrURI)
  let peerIdentity = try P256.KeyAgreement.PublicKey(
    compressedRepresentation: parsedQR.compressedPublicKey
  ).x963Representation
  let advertPlaintext = Data([0] + Array(1...10) + [9, 10, 11, 0, 0])
  let bootstrap = HybridQRBootstrap(
    uri: session.qrURI,
    identityPrivateKey: identity,
    qrSecret: parsedQR.qrSecret
  )
  let advertisement = try makeAdvertisement(
    bootstrap: bootstrap,
    plaintext: advertPlaintext
  )
  let psk = try HybridCryptography.derive(
    secret: parsedQR.qrSecret,
    salt: advertPlaintext,
    purpose: .psk,
    outputByteCount: 32
  )
  let phone = ScriptedPhoneChannel(
    peerIdentity: peerIdentity,
    preSharedKey: psk,
    responderRandomSource: SequenceRandomSource([Data(repeating: 4, count: 32)]),
    profile: profile,
    getInfoPayload: getInfoPayload,
    assertionResponses: assertionResponses
  )
  return HybridAssertionFixture(
    session: session,
    scanner: SessionScanner(advertisement: advertisement),
    phone: phone,
    connector: PhoneConnector(channel: phone)
  )
}

@Test(
  "Hybrid transport executes one allow-list assertion without getInfo replay",
  arguments: HybridWireProfile.allCases
)
func hybridAllowListAssertion(profile: HybridWireProfile) async throws {
  let credentialID = Data([0xa1])
  let ceremony = try await assertionCeremony(
    allowCredentials: [
      try WebAuthnCredentialDescriptor(id: credentialID, transports: [.hybrid])
    ]
  )
  let fixture = try makeHybridAssertionFixture(
    profile: profile,
    getInfoPayload: makeGetInfoPayload(),
    assertionResponses: [
      try assertionResponse(
        credentialID: credentialID,
        authenticatorData: assertionAuthenticatorData(signCount: 7)
      )
    ]
  )

  let assertion = try await fixture.session.getAssertion(
    ceremony: ceremony,
    scanner: fixture.scanner,
    connector: fixture.connector,
    proximityTimeout: .seconds(1),
    accountSelectionTimeout: .seconds(1),
    sleeper: SessionSleeper()
  )

  #expect(assertion.credentialID == credentialID)
  #expect(assertion.signCount == 7)
  #expect(assertion.authenticatorAttachment == .hybrid)
  #expect(await fixture.phone.ctapCommands == [0x02])
  #expect(await fixture.phone.sawShutdown == (profile == .pxp20260717))
  #expect(await fixture.session.state == .complete)
}

@Test("Hybrid transport bounds getNextAssertion and selects an explicit account")
func hybridDiscoverableAssertion() async throws {
  let ceremony = try await assertionCeremony(allowCredentials: [])
  let fixture = try makeHybridAssertionFixture(
    getInfoPayload: makeGetInfoPayload(),
    assertionResponses: [
      try assertionResponse(
        credentialID: Data([1]),
        authenticatorData: assertionAuthenticatorData(signCount: 1),
        userID: Data([0x11]),
        userName: "first",
        numberOfCredentials: 2
      ),
      try assertionResponse(
        credentialID: Data([2]),
        authenticatorData: assertionAuthenticatorData(signCount: 2),
        userID: Data([0x22]),
        userName: "second"
      ),
    ]
  )

  let assertion = try await fixture.session.getAssertion(
    ceremony: ceremony,
    scanner: fixture.scanner,
    accountSelector: SelectingAccount(index: 1),
    connector: fixture.connector,
    proximityTimeout: .seconds(1),
    accountSelectionTimeout: .seconds(1),
    sleeper: SessionSleeper()
  )

  #expect(assertion.credentialID == Data([2]))
  #expect(assertion.userHandle == Data([0x22]))
  #expect(await fixture.phone.ctapCommands == [0x02, 0x08])
  #expect(await fixture.session.state == .complete)
}

@Test("Known ceremony mismatches fail before transport dispatch")
func hybridCeremonyPreflightFailures() async throws {
  let discoverable = try await assertionCeremony(allowCredentials: [])
  let discoverableFixture = try makeHybridAssertionFixture(
    getInfoPayload: makeGetInfoPayload(),
    assertionResponses: []
  )
  await #expect(throws: WebAuthnError.accountSelectionRequired) {
    try await discoverableFixture.session.getAssertion(
      ceremony: discoverable,
      scanner: discoverableFixture.scanner,
      connector: discoverableFixture.connector
    )
  }
  #expect(await discoverableFixture.session.state == .readyToDisplayQR)
  #expect(await discoverableFixture.connector.connectedURL == nil)

  let wrongTransport = try await assertionCeremony(
    allowCredentials: [
      try WebAuthnCredentialDescriptor(id: Data([1]), transports: [.usb])
    ]
  )
  let transportFixture = try makeHybridAssertionFixture(
    getInfoPayload: makeGetInfoPayload(),
    assertionResponses: []
  )
  await #expect(throws: WebAuthnError.authenticatorCapabilityMismatch) {
    try await transportFixture.session.getAssertion(
      ceremony: wrongTransport,
      scanner: transportFixture.scanner,
      connector: transportFixture.connector
    )
  }
  #expect(await transportFixture.session.state == .readyToDisplayQR)
  #expect(await transportFixture.connector.connectedURL == nil)
}

@Test("Ambiguous post-dispatch failure is terminal and never replayed")
func hybridAssertionNeverReplaysAfterDispatch() async throws {
  let ceremony = try await assertionCeremony(
    allowCredentials: [
      try WebAuthnCredentialDescriptor(id: Data([1]), transports: [.hybrid])
    ]
  )
  let fixture = try makeHybridAssertionFixture(
    getInfoPayload: makeGetInfoPayload(),
    assertionResponses: []
  )

  await #expect(throws: HybridTunnelError.receiveFailed) {
    try await fixture.session.getAssertion(
      ceremony: ceremony,
      scanner: fixture.scanner,
      connector: fixture.connector,
      proximityTimeout: .seconds(1),
      accountSelectionTimeout: .seconds(1),
      sleeper: SessionSleeper()
    )
  }
  #expect(await fixture.phone.ctapCommands == [0x02])
  #expect(await fixture.session.state == .failed)
}

@Test("Required UV capability mismatch fails before assertion dispatch")
func hybridRequiredUVFailsBeforeDispatch() async throws {
  let ceremony = try await assertionCeremony(
    allowCredentials: [
      try WebAuthnCredentialDescriptor(id: Data([1]), transports: [.hybrid])
    ]
  )
  let noUVInfo = try assertionAuthenticatorInfo(options: ["rk": true])
  let fixture = try makeHybridAssertionFixture(
    getInfoPayload: CanonicalCBOR.encode(noUVInfo.rawResponse),
    assertionResponses: []
  )
  await #expect(throws: WebAuthnError.userVerificationUnavailable) {
    try await fixture.session.getAssertion(
      ceremony: ceremony,
      scanner: fixture.scanner,
      connector: fixture.connector,
      proximityTimeout: .seconds(1),
      accountSelectionTimeout: .seconds(1),
      sleeper: SessionSleeper()
    )
  }
  #expect(await fixture.phone.ctapCommands.isEmpty)
  #expect(await fixture.session.state == .failed)
}

@Test("Account selection timeout is terminal after bounded getNext sequencing")
func hybridAccountSelectionTimeout() async throws {
  let ceremony = try await assertionCeremony(allowCredentials: [])
  let fixture = try makeHybridAssertionFixture(
    getInfoPayload: makeGetInfoPayload(),
    assertionResponses: [
      try assertionResponse(
        credentialID: Data([1]),
        authenticatorData: assertionAuthenticatorData(),
        userID: Data([1]),
        numberOfCredentials: 2
      ),
      try assertionResponse(
        credentialID: Data([2]),
        authenticatorData: assertionAuthenticatorData(),
        userID: Data([2])
      ),
    ]
  )
  await #expect(throws: WebAuthnError.accountSelectionTimedOut) {
    try await fixture.session.getAssertion(
      ceremony: ceremony,
      scanner: fixture.scanner,
      accountSelector: BlockingAccountSelector(),
      connector: fixture.connector,
      proximityTimeout: .seconds(2),
      accountSelectionTimeout: .milliseconds(1),
      sleeper: SelectionTimeoutSleeper()
    )
  }
  #expect(await fixture.phone.ctapCommands == [0x02, 0x08])
  #expect(await fixture.session.state == .failed)
}

@Test(
  "Complete hybrid session reaches explicit authenticatorGetInfo",
  arguments: HybridWireProfile.allCases
)
func completeHybridSession(profile: HybridWireProfile) async throws {
  let identity = Data(repeating: 1, count: 32)
  let qrSecret = Data(repeating: 2, count: 16)
  let session = try HybridSession(
    qrConfiguration: HybridQRConfiguration(requestType: .getAssertion),
    wireProfile: profile,
    randomSource: SequenceRandomSource([
      identity,
      qrSecret,
      Data(repeating: 3, count: 32),
    ])
  )
  let parsedQR = try HybridQRCode.parse(session.qrURI)
  let peerIdentity = try P256.KeyAgreement.PublicKey(
    compressedRepresentation: parsedQR.compressedPublicKey
  ).x963Representation
  let advertPlaintext = Data([0] + Array(1...10) + [9, 10, 11, 0, 0])
  let bootstrap = HybridQRBootstrap(
    uri: session.qrURI,
    identityPrivateKey: identity,
    qrSecret: parsedQR.qrSecret
  )
  let advertisement = try makeAdvertisement(
    bootstrap: bootstrap,
    plaintext: advertPlaintext
  )
  let psk = try HybridCryptography.derive(
    secret: parsedQR.qrSecret,
    salt: advertPlaintext,
    purpose: .psk,
    outputByteCount: 32
  )
  let phone = ScriptedPhoneChannel(
    peerIdentity: peerIdentity,
    preSharedKey: psk,
    responderRandomSource: SequenceRandomSource([Data(repeating: 4, count: 32)]),
    profile: profile,
    getInfoPayload: try makeGetInfoPayload()
  )
  let connector = PhoneConnector(channel: phone)

  let info = try await session.getInfo(
    scanner: SessionScanner(advertisement: advertisement),
    connector: connector,
    proximityTimeout: .seconds(1),
    sleeper: SessionSleeper()
  )

  #expect(info.versions == ["FIDO_2_0", "FIDO_2_1"])
  #expect(await session.state == .complete)
  #expect(await phone.sawShutdown == (profile == .pxp20260717))
  #expect(await connector.connectedURL?.host == "cable.ua5v.com")
  #expect(await connector.connectedURL?.path.hasPrefix("/cable/connect/090a0b/") == true)
}

@Test("Hybrid wire profiles never auto-fallback")
func hybridSessionDoesNotFallbackProfiles() async throws {
  let identity = Data(repeating: 1, count: 32)
  let qrSecret = Data(repeating: 2, count: 16)
  let session = try HybridSession(
    qrConfiguration: HybridQRConfiguration(requestType: .getAssertion),
    wireProfile: .pxp20260717,
    randomSource: SequenceRandomSource([
      identity,
      qrSecret,
      Data(repeating: 3, count: 32),
    ])
  )
  let parsedQR = try HybridQRCode.parse(session.qrURI)
  let peerIdentity = try P256.KeyAgreement.PublicKey(
    compressedRepresentation: parsedQR.compressedPublicKey
  ).x963Representation
  let advertPlaintext = Data([0] + Array(1...10) + [9, 10, 11, 0, 0])
  let bootstrap = HybridQRBootstrap(
    uri: session.qrURI,
    identityPrivateKey: identity,
    qrSecret: qrSecret
  )
  let advertisement = try makeAdvertisement(
    bootstrap: bootstrap,
    plaintext: advertPlaintext
  )
  let psk = try HybridCryptography.derive(
    secret: qrSecret,
    salt: advertPlaintext,
    purpose: .psk,
    outputByteCount: 32
  )
  let phone = ScriptedPhoneChannel(
    peerIdentity: peerIdentity,
    preSharedKey: psk,
    responderRandomSource: SequenceRandomSource([Data(repeating: 4, count: 32)]),
    profile: .chromiumCableV2Revision0,
    getInfoPayload: try makeGetInfoPayload()
  )

  await #expect(throws: HybridProtocolError.invalidPostHandshakeMessage) {
    try await session.getInfo(
      scanner: SessionScanner(advertisement: advertisement),
      connector: PhoneConnector(channel: phone),
      proximityTimeout: .seconds(1),
      sleeper: SessionSleeper()
    )
  }
  #expect(await session.state == .failed)
}

@Test("HybridSession.cancel is terminal without cancelling the caller task")
func hybridSessionExplicitCancellation() async throws {
  let session = try HybridSession(
    qrConfiguration: HybridQRConfiguration(requestType: .getAssertion),
    wireProfile: .pxp20260717,
    randomSource: SequenceRandomSource([
      Data(repeating: 1, count: 32),
      Data(repeating: 2, count: 16),
      Data(repeating: 3, count: 32),
    ])
  )
  let scanner = BlockingSessionScanner()
  let operation = Task {
    try await session.getInfo(
      scanner: scanner,
      connector: URLSessionHybridWebSocketConnector(),
      proximityTimeout: .seconds(60),
      sleeper: SessionSleeper()
    )
  }
  await scanner.waitUntilStarted()
  await session.cancel()

  await #expect(throws: HybridProtocolError.cancelled) {
    try await operation.value
  }
  #expect(await session.state == .cancelled)
}

@Test("Caller task cancellation is terminal and closes discovery")
func hybridSessionCallerCancellation() async throws {
  let session = try HybridSession(
    qrConfiguration: HybridQRConfiguration(requestType: .getAssertion),
    wireProfile: .pxp20260717,
    randomSource: SequenceRandomSource([
      Data(repeating: 1, count: 32),
      Data(repeating: 2, count: 16),
    ])
  )
  let scanner = BlockingSessionScanner()
  let operation = Task {
    try await session.getInfo(
      scanner: scanner,
      proximityTimeout: .seconds(60),
      sleeper: SessionSleeper()
    )
  }
  await scanner.waitUntilStarted()
  operation.cancel()

  await #expect(throws: HybridProtocolError.cancelled) {
    try await operation.value
  }
  #expect(await session.state == .cancelled)
}

@Test("HybridSession.cancel interrupts an in-progress tunnel connection")
func hybridSessionCancelsTunnelConnection() async throws {
  let identity = Data(repeating: 1, count: 32)
  let qrSecret = Data(repeating: 2, count: 16)
  let session = try HybridSession(
    qrConfiguration: HybridQRConfiguration(requestType: .getAssertion),
    wireProfile: .pxp20260717,
    randomSource: SequenceRandomSource([identity, qrSecret])
  )
  let parsedQR = try HybridQRCode.parse(session.qrURI)
  let bootstrap = HybridQRBootstrap(
    uri: session.qrURI,
    identityPrivateKey: identity,
    qrSecret: parsedQR.qrSecret
  )
  let advertisement = try makeAdvertisement(
    bootstrap: bootstrap,
    plaintext: Data([0] + Array(1...10) + [9, 10, 11, 0, 0])
  )
  let connector = BlockingConnector()
  let operation = Task {
    try await session.getInfo(
      scanner: SessionScanner(advertisement: advertisement),
      connector: connector,
      proximityTimeout: .seconds(1),
      sleeper: SessionSleeper()
    )
  }
  await connector.waitUntilStarted()
  await session.cancel()

  await #expect(throws: HybridProtocolError.cancelled) {
    try await operation.value
  }
  #expect(await session.state == .cancelled)
}

@Test("HybridSession refuses to advertise unimplemented QR capabilities")
func hybridSessionRejectsUnsupportedCapabilities() throws {
  #expect(throws: HybridProtocolError.invalidConfiguration) {
    try HybridSession(
      qrConfiguration: HybridQRConfiguration(requestType: .makeCredential),
      wireProfile: .pxp20260717
    )
  }
  #expect(throws: HybridProtocolError.invalidConfiguration) {
    try HybridSession(
      qrConfiguration: HybridQRConfiguration(
        supportsLinking: true,
        requestType: .getAssertion
      ),
      wireProfile: .pxp20260717
    )
  }
  #expect(throws: HybridProtocolError.invalidConfiguration) {
    try HybridSession(
      qrConfiguration: HybridQRConfiguration(
        requestType: .getAssertion,
        transferChannels: [.bluetoothLowEnergy]
      ),
      wireProfile: .pxp20260717
    )
  }
  #expect(throws: HybridProtocolError.invalidConfiguration) {
    try HybridSession(
      qrConfiguration: HybridQRConfiguration(
        assignedTunnelServerDomainCount: 3,
        requestType: .getAssertion
      ),
      wireProfile: .pxp20260717
    )
  }
}
