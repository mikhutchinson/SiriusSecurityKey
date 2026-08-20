import Foundation
import Testing

@testable import SiriusSecurityKey

private struct AdvertisementScanner: HybridBluetoothScanner {
  let advertisements: [HybridBluetoothAdvertisement]

  func scan(
    serviceUUID: UUID
  ) async throws -> AsyncThrowingStream<HybridBluetoothAdvertisement, any Error> {
    AsyncThrowingStream { continuation in
      for advertisement in advertisements {
        continuation.yield(advertisement)
      }
      continuation.finish()
    }
  }

  func stop() async {}
}

private struct SlowSleeper: HybridSleeper {
  func sleep(for duration: Duration) async throws {
    try await ContinuousClock().sleep(for: .seconds(60))
  }
}

private struct ImmediateSleeper: HybridSleeper {
  func sleep(for duration: Duration) async throws {}
}

private final class NeverScanner: HybridBluetoothScanner, @unchecked Sendable {
  private let lock = NSLock()
  private var continuation:
    AsyncThrowingStream<HybridBluetoothAdvertisement, any Error>.Continuation?

  func scan(
    serviceUUID: UUID
  ) async throws -> AsyncThrowingStream<HybridBluetoothAdvertisement, any Error> {
    prepareStream()
  }

  func stop() async {
    finish()
  }

  private func prepareStream() -> AsyncThrowingStream<
    HybridBluetoothAdvertisement,
    any Error
  > {
    let stream = AsyncThrowingStream<HybridBluetoothAdvertisement, any Error> {
      newContinuation in
      lock.lock()
      continuation = newContinuation
      lock.unlock()
    }
    return stream
  }

  private func finish() {
    lock.lock()
    let current = continuation
    continuation = nil
    lock.unlock()
    current?.finish()
  }
}

@Test("PXP proximity authenticates and decrypts the active QR advertisement")
func proximityMatchesActiveBootstrap() async throws {
  let bootstrap = HybridQRBootstrap(
    uri: "FIDO:/",
    identityPrivateKey: Data(repeating: 1, count: 32),
    qrSecret: Data(repeating: 2, count: 16)
  )
  let plaintext = Data([0] + Array(1...10) + [9, 10, 11, 0, 0])
  let valid = try makeAdvertisement(bootstrap: bootstrap, plaintext: plaintext)
  #expect(valid.serviceData.testHex == (try TestVectors.value("advert")))
  #expect(
    try HybridCryptography.derive(
      secret: bootstrap.qrSecret,
      purpose: .eidKey,
      outputByteCount: 64
    ).testHex == (try TestVectors.value("eid_key"))
  )
  #expect(
    try HybridCryptography.derive(
      secret: bootstrap.qrSecret,
      salt: plaintext,
      purpose: .psk,
      outputByteCount: 32
    ).testHex == (try TestVectors.value("pxp_psk"))
  )
  var tampered = valid.serviceData
  tampered[tampered.startIndex] ^= 1
  let scanner = AdvertisementScanner(
    advertisements: [
      HybridBluetoothAdvertisement(
        serviceUUID: HybridProximityDiscovery.serviceUUID,
        serviceData: tampered
      ),
      valid,
    ]
  )
  let discovery = HybridProximityDiscovery()
  let match = try await discovery.awaitMatch(
    bootstrap: bootstrap,
    scanner: scanner,
    timeout: .seconds(1),
    sleeper: SlowSleeper()
  )

  #expect(match.plaintext == plaintext)
  #expect(match.nonce == Data(Array(1...10)))
  #expect(match.routingID == Data([9, 10, 11]))
  #expect(match.tunnelServerDomain.rawValue == 0)
  #expect(await discovery.state == .matched)
}

@Test("PXP proximity rejects unknown assigned domains and bad reserved bits")
func proximityRejectsInvalidPlaintext() async throws {
  let bootstrap = HybridQRBootstrap(
    uri: "FIDO:/",
    identityPrivateKey: Data(repeating: 1, count: 32),
    qrSecret: Data(repeating: 2, count: 16)
  )
  let invalidPlaintexts = [
    Data([1] + Array(repeating: 0, count: 15)),
    Data([0] + Array(repeating: 0, count: 13) + [255, 0]),
  ]

  for plaintext in invalidPlaintexts {
    let scanner = AdvertisementScanner(
      advertisements: [try makeAdvertisement(bootstrap: bootstrap, plaintext: plaintext)]
    )
    let discovery = HybridProximityDiscovery()
    await #expect(throws: HybridBluetoothError.scanFailed) {
      try await discovery.awaitMatch(
        bootstrap: bootstrap,
        scanner: scanner,
        timeout: .seconds(1),
        sleeper: SlowSleeper()
      )
    }
  }
}

@Test("Tunnel domain and route derivation match pinned Chromium vectors")
func tunnelDerivationVectors() throws {
  #expect(try HybridTunnelServerDomain(rawValue: 0).host == "cable.ua5v.com")
  #expect(try HybridTunnelServerDomain(rawValue: 1).host == "cable.auth.com")
  #expect(try HybridTunnelServerDomain(rawValue: 266).host == "cable.wufkweyy3uaxb.com")
  #expect(throws: HybridProtocolError.unknownTunnelDomain) {
    try HybridTunnelServerDomain(rawValue: 2)
  }

  let bootstrap = HybridQRBootstrap(
    uri: "FIDO:/",
    identityPrivateKey: Data(repeating: 1, count: 32),
    qrSecret: Data(repeating: 2, count: 16)
  )
  let match = HybridProximityMatch(
    plaintext: Data(repeating: 0, count: 16),
    nonce: Data(repeating: 0, count: 10),
    routingID: Data([9, 10, 11]),
    tunnelServerDomain: try HybridTunnelServerDomain(rawValue: 0)
  )
  let endpoint = try HybridTunnelRouting.endpoint(match: match, bootstrap: bootstrap)

  #expect(endpoint.url.scheme == "wss")
  #expect(endpoint.url.host == "cable.ua5v.com")
  #expect(endpoint.url.path.hasPrefix("/cable/connect/090a0b/"))
  #expect(endpoint.url.path.hasSuffix(try TestVectors.value("tunnel_id")))
  #expect(endpoint.subprotocolName == "fido.cable")
}

@Test("Proximity timeout and caller cancellation are terminal")
func proximityTimeoutAndCancellation() async throws {
  let bootstrap = HybridQRBootstrap(
    uri: "FIDO:/",
    identityPrivateKey: Data(repeating: 1, count: 32),
    qrSecret: Data(repeating: 2, count: 16)
  )

  let timedOut = HybridProximityDiscovery()
  await #expect(throws: HybridProtocolError.timeout) {
    try await timedOut.awaitMatch(
      bootstrap: bootstrap,
      scanner: NeverScanner(),
      timeout: .seconds(1),
      sleeper: ImmediateSleeper()
    )
  }
  #expect(await timedOut.state == .failed)

  let cancelled = HybridProximityDiscovery()
  let scanner = NeverScanner()
  let operation = Task {
    try await cancelled.awaitMatch(
      bootstrap: bootstrap,
      scanner: scanner,
      timeout: .seconds(60),
      sleeper: SlowSleeper()
    )
  }
  await Task.yield()
  operation.cancel()
  await #expect(throws: HybridProtocolError.cancelled) {
    try await operation.value
  }
  #expect(await cancelled.state == .cancelled)
}

@Test("URLSession tunnel connector rejects non-WSS endpoints before I/O")
func tunnelConnectorRejectsInsecureURL() async throws {
  guard let url = URL(string: "ws://example.com/cable/connect/00/00") else {
    Issue.record("Static URL failed to parse")
    return
  }
  await #expect(throws: HybridProtocolError.invalidTunnelURL) {
    try await URLSessionHybridWebSocketConnector().connect(
      to: url,
      subprotocol: "fido.cable",
      maximumMessageSize: 1024
    )
  }
}

@Test("URLSession WebSocket open wait is cancellable before delegate callbacks")
func tunnelOpenWaitIsCancellable() async throws {
  let delegate = HybridWebSocketDelegate(expectedSubprotocol: "fido.cable")
  let wait = Task {
    try await delegate.waitUntilOpen()
  }
  await Task.yield()
  delegate.cancelPendingOpen()

  await #expect(throws: CancellationError.self) {
    try await wait.value
  }
}

func makeAdvertisement(
  bootstrap: HybridQRBootstrap,
  plaintext: Data
) throws -> HybridBluetoothAdvertisement {
  let eidKey = try HybridCryptography.derive(
    secret: bootstrap.qrSecret,
    purpose: .eidKey,
    outputByteCount: 64
  )
  let ciphertext = try HybridCryptography.encryptAES256Block(
    plaintext,
    key: eidKey.prefix(32)
  )
  var serviceData = ciphertext
  serviceData.append(
    HybridCryptography.hmacSHA256(
      key: eidKey.suffix(32),
      message: ciphertext
    ).prefix(4)
  )
  return HybridBluetoothAdvertisement(
    serviceUUID: HybridProximityDiscovery.serviceUUID,
    serviceData: serviceData
  )
}
