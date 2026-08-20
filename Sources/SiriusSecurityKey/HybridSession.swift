// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// retained in THIRD_PARTY_NOTICES.md.

import Foundation

/// Public, secret-free phases of a one-shot hybrid transaction.
public enum HybridSessionState: String, Sendable {
  case readyToDisplayQR
  case awaitingProximity
  case connectingTunnel
  case handshaking
  case awaitingPostHandshake
  case compilingAssertion
  case requestingGetInfo
  case requestingAssertion
  case requestingNextAssertion
  case selectingAccount
  case complete
  case failed
  case cancelled
}

private enum HybridSessionOperation: Sendable {
  case getInfo
  case getAssertion(
    ceremony: ValidatedWebAuthnAssertionCeremony,
    accountSelector: (any WebAuthnAccountSelector)?,
    accountSelectionTimeout: Duration
  )
}

private enum HybridSessionResult: Sendable {
  case getInfo(AuthenticatorInfo)
  case getAssertion(WebAuthnAssertion)
}

/// Actor-owned, one-shot QR-initiated hybrid authenticator session.
///
/// The session owns proximity, tunnel, Noise and the private CTAP transport.
/// Public callers can request validated capabilities or execute an authorized
/// WebAuthn assertion; raw CTAP is intentionally not exposed.
public actor HybridSession {
  /// Canonical uppercase `FIDO:/` URI for consumer-owned QR presentation.
  public nonisolated let qrURI: String
  /// Explicit post-handshake and established-message framing for this session.
  public nonisolated let wireProfile: HybridWireProfile
  /// Current terminal or in-progress secret-free session phase.
  public private(set) var state: HybridSessionState = .readyToDisplayQR

  private let bootstrap: HybridQRBootstrap
  private let randomSource: any HybridRandomSource
  private let cancellationSignal = HybridCancellationSignal()
  private var activeScanner: (any HybridBluetoothScanner)?
  private var activeChannel: (any HybridBinaryChannel)?

  /// Generates a fresh one-shot QR bootstrap without beginning discovery.
  public init(
    qrConfiguration: HybridQRConfiguration,
    wireProfile: HybridWireProfile,
    randomSource: any HybridRandomSource = SystemHybridRandomSource()
  ) throws {
    guard qrConfiguration.requestType == .getAssertion,
      qrConfiguration.assignedTunnelServerDomainCount == 2,
      qrConfiguration.supportsLinking != true,
      qrConfiguration.transferChannels == nil
        || qrConfiguration.transferChannels == [.webSocket]
    else {
      throw HybridProtocolError.invalidConfiguration
    }
    let bootstrap = try HybridQRCode.generate(
      configuration: qrConfiguration,
      randomSource: randomSource
    )
    self.bootstrap = bootstrap
    self.qrURI = bootstrap.uri
    self.wireProfile = wireProfile
    self.randomSource = randomSource
  }

  /// Performs one explicit CTAP2 `authenticatorGetInfo` exchange through the
  /// same private transport used by typed ceremonies.
  public func getInfo(
    scanner: any HybridBluetoothScanner,
    connector: any HybridWebSocketConnector = URLSessionHybridWebSocketConnector(),
    proximityTimeout: Duration = .seconds(120),
    sleeper: any HybridSleeper = ContinuousHybridSleeper()
  ) async throws -> AuthenticatorInfo {
    let result = try await execute(
      operation: .getInfo,
      scanner: scanner,
      connector: connector,
      proximityTimeout: proximityTimeout,
      sleeper: sleeper
    )
    guard case .getInfo(let info) = result else {
      throw HybridProtocolError.handshakeStateViolation
    }
    return info
  }

  /// Executes one authorized assertion without exposing a raw CTAP route.
  ///
  /// Discoverable requests require an explicit account selector before any
  /// network or CTAP dispatch, even if the authenticator ultimately returns a
  /// single user-selected credential.
  public func getAssertion(
    ceremony: ValidatedWebAuthnAssertionCeremony,
    scanner: any HybridBluetoothScanner,
    accountSelector: (any WebAuthnAccountSelector)? = nil,
    connector: any HybridWebSocketConnector = URLSessionHybridWebSocketConnector(),
    proximityTimeout: Duration = .seconds(120),
    accountSelectionTimeout: Duration = .seconds(120),
    sleeper: any HybridSleeper = ContinuousHybridSleeper()
  ) async throws -> WebAuthnAssertion {
    guard proximityTimeout > .zero, accountSelectionTimeout > .zero else {
      throw HybridProtocolError.invalidConfiguration
    }
    guard !ceremony.isDiscoverable || accountSelector != nil else {
      throw WebAuthnError.accountSelectionRequired
    }
    guard
      ceremony.allowCredentials.allSatisfy({ descriptor in
        guard let transports = descriptor.transports else {
          return true
        }
        return transports.contains(.hybrid)
      })
    else {
      throw WebAuthnError.authenticatorCapabilityMismatch
    }

    let result = try await execute(
      operation: .getAssertion(
        ceremony: ceremony,
        accountSelector: accountSelector,
        accountSelectionTimeout: accountSelectionTimeout
      ),
      scanner: scanner,
      connector: connector,
      proximityTimeout: proximityTimeout,
      sleeper: sleeper
    )
    guard case .getAssertion(let assertion) = result else {
      throw HybridProtocolError.handshakeStateViolation
    }
    return assertion
  }

  private func execute(
    operation: HybridSessionOperation,
    scanner: any HybridBluetoothScanner,
    connector: any HybridWebSocketConnector,
    proximityTimeout: Duration,
    sleeper: any HybridSleeper
  ) async throws -> HybridSessionResult {
    if state == .cancelled {
      throw HybridProtocolError.cancelled
    }
    guard state == .readyToDisplayQR, proximityTimeout > .zero else {
      throw HybridProtocolError.handshakeStateViolation
    }
    activeScanner = scanner
    state = .awaitingProximity

    do {
      return try await withThrowingTaskGroup(of: HybridSessionResult.self) { group in
        group.addTask {
          try await self.perform(
            operation: operation,
            scanner: scanner,
            connector: connector,
            proximityTimeout: proximityTimeout,
            sleeper: sleeper
          )
        }
        group.addTask {
          await self.cancellationSignal.wait()
          throw HybridProtocolError.cancelled
        }
        defer { group.cancelAll() }
        guard let result = try await group.next() else {
          throw HybridProtocolError.cancelled
        }
        return result
      }
    } catch is CancellationError {
      await terminateActiveResources(scanner: scanner)
      state = .cancelled
      throw HybridProtocolError.cancelled
    }
  }

  private func perform(
    operation: HybridSessionOperation,
    scanner: any HybridBluetoothScanner,
    connector: any HybridWebSocketConnector,
    proximityTimeout: Duration,
    sleeper: any HybridSleeper
  ) async throws -> HybridSessionResult {
    var channel: (any HybridBinaryChannel)?
    var transport: HybridAuthenticatorTransport?

    do {
      let discovery = HybridProximityDiscovery()
      let match = try await discovery.awaitMatch(
        bootstrap: bootstrap,
        scanner: scanner,
        timeout: proximityTimeout,
        sleeper: sleeper
      )

      try checkCancellation()
      state = .connectingTunnel
      let endpoint = try HybridTunnelRouting.endpoint(
        match: match,
        bootstrap: bootstrap
      )
      let openedChannel = try await connector.connect(
        to: endpoint.url,
        subprotocol: endpoint.subprotocolName,
        maximumMessageSize: endpoint.maximumMessageSize
      )
      channel = openedChannel
      activeChannel = openedChannel

      try checkCancellation()
      state = .handshaking
      let preSharedKey = try HybridCryptography.derive(
        secret: bootstrap.qrSecret,
        salt: match.plaintext,
        purpose: .psk,
        outputByteCount: 32
      )
      let initiator = try HybridNoiseHandshakeInitiator(
        bootstrap: bootstrap,
        preSharedKey: preSharedKey,
        randomSource: randomSource
      )
      let initialMessage = try await initiator.makeInitialMessage()
      try await openedChannel.send(initialMessage)
      try checkCancellation()
      let response = try await openedChannel.receive()
      try checkCancellation()
      let handshake = try await initiator.processResponse(response)

      try checkCancellation()
      state = .awaitingPostHandshake
      let encryptedPostHandshake = try await openedChannel.receive()
      try checkCancellation()
      let postHandshake = try await handshake.cipher.decrypt(encryptedPostHandshake)
      let postHandshakeInfo = try parsePostHandshakeGetInfo(postHandshake)

      let ownedTransport = HybridAuthenticatorTransport(
        channel: openedChannel,
        cipher: handshake.cipher,
        wireProfile: wireProfile
      )
      transport = ownedTransport

      let result: HybridSessionResult
      switch operation {
      case .getInfo:
        state = .requestingGetInfo
        let response = try await ownedTransport.transact(CTAPRequest(command: 0x04))
        result = .getInfo(try AuthenticatorInfoParser.parse(response: response))

      case .getAssertion(
        let ceremony,
        let accountSelector,
        let accountSelectionTimeout
      ):
        state = .compilingAssertion
        try checkCancellation()
        if !postHandshakeInfo.transports.isEmpty,
          !postHandshakeInfo.transports.contains(where: {
            $0 == "hybrid" || $0 == "cable" || $0 == "internal"
          })
        {
          throw WebAuthnError.authenticatorCapabilityMismatch
        }
        let plan = try WebAuthnAssertionPlanCompiler.compile(
          ceremony: ceremony,
          authenticatorInfo: postHandshakeInfo
        )

        state = .requestingAssertion
        let initial = try await ownedTransport.transact(plan.initialRequest)
        var responses = [
          try CTAPAssertionResponseParser.parse(
            initial,
            plan: plan,
            isFirstResponse: true
          )
        ]
        let expectedCount = responses[0].numberOfCredentials ?? 1
        guard expectedCount <= plan.maximumAssertionCount else {
          throw WebAuthnError.tooManyAssertions
        }
        if expectedCount > 1 {
          state = .requestingNextAssertion
          for _ in 1..<expectedCount {
            try checkCancellation()
            let next = try await ownedTransport.transact(plan.nextAssertionRequest)
            responses.append(
              try CTAPAssertionResponseParser.parse(
                next,
                plan: plan,
                isFirstResponse: false
              )
            )
          }
          guard Set(responses.map(\.credentialID)).count == responses.count else {
            throw WebAuthnError.invalidAssertionResponse
          }
        }

        let selectedIndex: Int?
        if responses.count > 1 {
          guard let accountSelector else {
            throw WebAuthnError.accountSelectionRequired
          }
          let candidates = try CTAPAssertionResponseParser.accountCandidates(
            for: responses,
            maximumAssertionCount: plan.maximumAssertionCount
          )
          state = .selectingAccount
          selectedIndex = try await selectAccount(
            from: candidates,
            using: accountSelector,
            timeout: accountSelectionTimeout,
            sleeper: sleeper
          )
        } else {
          selectedIndex = nil
        }
        result = .getAssertion(
          try CTAPAssertionResponseParser.finish(
            responses: responses,
            plan: plan,
            selectedResponseIndex: selectedIndex
          )
        )
      }

      try checkCancellation()
      try await ownedTransport.finish()
      await scanner.stop()
      activeChannel = nil
      activeScanner = nil
      state = .complete
      return result
    } catch is CancellationError {
      await scanner.stop()
      if let transport {
        await transport.cancel()
      } else if let channel {
        await channel.cancel()
      }
      activeChannel = nil
      activeScanner = nil
      state = .cancelled
      throw HybridProtocolError.cancelled
    } catch {
      await scanner.stop()
      if let transport {
        await transport.cancel()
      } else if let channel {
        await channel.cancel()
      }
      activeChannel = nil
      activeScanner = nil
      if state == .cancelled || error as? HybridProtocolError == .cancelled {
        state = .cancelled
        throw HybridProtocolError.cancelled
      }
      state = .failed
      throw error
    }
  }

  /// Terminates active discovery and tunnel resources. Cancellation is
  /// terminal and idempotent.
  public func cancel() async {
    guard state != .complete, state != .failed, state != .cancelled else {
      return
    }
    state = .cancelled
    cancellationSignal.cancel()
    if let activeScanner {
      await activeScanner.stop()
    }
    if let activeChannel {
      await activeChannel.cancel()
    }
    self.activeScanner = nil
    self.activeChannel = nil
  }

  private func selectAccount(
    from candidates: [WebAuthnAccountCandidate],
    using selector: any WebAuthnAccountSelector,
    timeout: Duration,
    sleeper: any HybridSleeper
  ) async throws -> Int {
    do {
      return try await withThrowingTaskGroup(of: Int.self) { group in
        group.addTask {
          try await selector.selectAccount(from: candidates)
        }
        group.addTask {
          try await sleeper.sleep(for: timeout)
          throw WebAuthnError.accountSelectionTimedOut
        }
        defer { group.cancelAll() }
        guard let index = try await group.next() else {
          throw WebAuthnError.accountSelectionTimedOut
        }
        guard candidates.indices.contains(index) else {
          throw WebAuthnError.invalidAccountSelection
        }
        return index
      }
    } catch is CancellationError {
      throw WebAuthnError.cancelled
    } catch let error as WebAuthnError {
      throw error
    } catch {
      throw WebAuthnError.invalidAccountSelection
    }
  }

  private func parsePostHandshakeGetInfo(_ plaintext: Data) throws -> AuthenticatorInfo {
    let cborBytes: Data
    switch wireProfile {
    case .pxp20260717:
      cborBytes = plaintext
    case .chromiumCableV2Revision0:
      cborBytes = try Self.removeRevisionZeroPadding(plaintext)
    }

    let limits = CBORLimits(
      maximumMessageSize: 128 << 10,
      maximumNestingDepth: 4,
      maximumCollectionCount: 64,
      maximumStringSize: 128 << 10,
      maximumTotalItems: 256
    )
    let message: CBORValue
    do {
      message = try CanonicalCBOR.decode(cborBytes, limits: limits)
    } catch {
      throw HybridProtocolError.invalidPostHandshakeMessage
    }
    guard case .map = message else {
      throw HybridProtocolError.invalidPostHandshakeMessage
    }

    if let padding = message.value(forUnsignedKey: 0) {
      guard case .byteString(let bytes) = padding,
        bytes.allSatisfy({ $0 == 0 })
      else {
        throw HybridProtocolError.invalidPostHandshakeMessage
      }
    }

    var features = ["ctap"]
    if let rawFeatures = message.value(forUnsignedKey: 3) {
      guard case .array(let values) = rawFeatures else {
        throw HybridProtocolError.invalidPostHandshakeMessage
      }
      features = try values.map { value in
        guard case .textString(let feature) = value, !feature.isEmpty else {
          throw HybridProtocolError.invalidPostHandshakeMessage
        }
        return feature
      }
    }
    guard features.contains("ctap") else {
      throw HybridProtocolError.unsupportedPostHandshakeFeature
    }

    guard case .byteString(let getInfo)? = message.value(forUnsignedKey: 1) else {
      throw HybridProtocolError.invalidPostHandshakeMessage
    }
    return try AuthenticatorInfoParser.parse(payload: getInfo)
  }

  private func checkCancellation() throws {
    if state == .cancelled || Task.isCancelled {
      throw HybridProtocolError.cancelled
    }
  }

  private func terminateActiveResources(scanner: any HybridBluetoothScanner) async {
    await scanner.stop()
    if let activeChannel {
      await activeChannel.cancel()
    }
    activeScanner = nil
    activeChannel = nil
  }

  private static func removeRevisionZeroPadding(_ plaintext: Data) throws -> Data {
    guard plaintext.count >= 2, plaintext.count <= 128 << 10 else {
      throw HybridProtocolError.invalidPostHandshakeMessage
    }
    let paddingLength =
      Int(plaintext[plaintext.count - 2])
      | Int(plaintext[plaintext.count - 1]) << 8
    guard paddingLength + 2 <= plaintext.count else {
      throw HybridProtocolError.invalidPadding
    }
    let cborEnd = plaintext.count - paddingLength - 2
    guard plaintext[cborEnd..<(plaintext.count - 2)].allSatisfy({ $0 == 0 }) else {
      throw HybridProtocolError.invalidPadding
    }
    return plaintext.prefix(cborEnd)
  }
}

private final class HybridCancellationSignal: @unchecked Sendable {
  private let stream: AsyncStream<Void>
  private let continuation: AsyncStream<Void>.Continuation

  init() {
    let pair = AsyncStream<Void>.makeStream()
    stream = pair.stream
    continuation = pair.continuation
  }

  func wait() async {
    for await _ in stream {}
  }

  func cancel() {
    continuation.finish()
  }
}
