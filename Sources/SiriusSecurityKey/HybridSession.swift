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
  case requestingGetInfo
  case complete
  case failed
  case cancelled
}

/// One-shot QR-initiated hybrid session through a validated
/// `authenticatorGetInfo` response.
public actor HybridSession {
  /// Canonical uppercase `FIDO:/` URI for consumer-owned QR presentation.
  public nonisolated let qrURI: String
  /// Explicit post-handshake framing selected for this session.
  public nonisolated let wireProfile: HybridWireProfile
  /// Current terminal or in-progress session phase.
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

  /// Performs proximity, tunnel, Noise, post-handshake validation, and one
  /// explicit CTAP `authenticatorGetInfo` exchange.
  public func getInfo(
    scanner: any HybridBluetoothScanner,
    connector: any HybridWebSocketConnector = URLSessionHybridWebSocketConnector(),
    proximityTimeout: Duration = .seconds(120),
    sleeper: any HybridSleeper = ContinuousHybridSleeper()
  ) async throws -> AuthenticatorInfo {
    if state == .cancelled {
      throw HybridProtocolError.cancelled
    }
    guard state == .readyToDisplayQR else {
      throw HybridProtocolError.handshakeStateViolation
    }
    activeScanner = scanner
    state = .awaitingProximity
    do {
      return try await withThrowingTaskGroup(of: AuthenticatorInfo.self) { group in
        group.addTask {
          try await self.performGetInfo(
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
      await scanner.stop()
      if let activeChannel {
        await activeChannel.cancel()
      }
      activeScanner = nil
      activeChannel = nil
      state = .cancelled
      throw HybridProtocolError.cancelled
    }
  }

  private func performGetInfo(
    scanner: any HybridBluetoothScanner,
    connector: any HybridWebSocketConnector,
    proximityTimeout: Duration,
    sleeper: any HybridSleeper
  ) async throws -> AuthenticatorInfo {
    var channel: (any HybridBinaryChannel)?

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
      _ = try parsePostHandshakeGetInfo(postHandshake)

      state = .requestingGetInfo
      let request = Data([1, 0x04])
      let encryptedRequest = try await handshake.cipher.encrypt(request)
      try await openedChannel.send(encryptedRequest)
      try checkCancellation()
      let info = try await receiveExplicitGetInfo(
        channel: openedChannel,
        cipher: handshake.cipher
      )

      let shutdown = try await handshake.cipher.encrypt(Data([0]))
      try await openedChannel.send(shutdown)
      await openedChannel.cancel()
      activeChannel = nil
      activeScanner = nil
      state = .complete
      return info
    } catch is CancellationError {
      await scanner.stop()
      if let channel {
        await channel.cancel()
      }
      activeChannel = nil
      activeScanner = nil
      state = .cancelled
      throw HybridProtocolError.cancelled
    } catch {
      await scanner.stop()
      if let channel {
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

  /// Terminates all active discovery and tunnel resources. Cancellation is
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

  private func receiveExplicitGetInfo(
    channel: any HybridBinaryChannel,
    cipher: HybridNoiseCipher
  ) async throws -> AuthenticatorInfo {
    for _ in 0..<16 {
      let encrypted = try await channel.receive()
      let plaintext = try await cipher.decrypt(encrypted)
      guard let messageType = plaintext.first else {
        throw HybridProtocolError.invalidHybridMessage
      }
      let payload = plaintext.dropFirst()
      switch messageType {
      case 0:
        throw HybridProtocolError.unexpectedShutdown
      case 1:
        let response: CTAPResponse
        do {
          response = try CTAPResponse(encoded: payload)
        } catch {
          throw HybridProtocolError.invalidHybridMessage
        }
        return try AuthenticatorInfoParser.parse(response: response)
      case 2:
        do {
          _ = try CanonicalCBOR.decode(payload)
        } catch {
          throw HybridProtocolError.invalidHybridMessage
        }
      default:
        throw HybridProtocolError.invalidHybridMessage
      }
    }
    throw HybridProtocolError.messageTooLarge
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
