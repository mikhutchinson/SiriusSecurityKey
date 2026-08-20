import CryptoKit
import Foundation
import Testing

@testable import SiriusSecurityKey

@Test("Noise KNpsk0 completes with equal transcript and counterparty traffic keys")
func noiseKNpsk0RoundTrip() async throws {
  let identityBytes = Data(repeating: 1, count: 32)
  let bootstrap = HybridQRBootstrap(
    uri: "FIDO:/",
    identityPrivateKey: identityBytes,
    qrSecret: Data(repeating: 0, count: 16)
  )
  let psk = Data(repeating: 0, count: 32)
  let initiator = try HybridNoiseHandshakeInitiator(
    bootstrap: bootstrap,
    preSharedKey: psk,
    randomSource: SequenceRandomSource([Data(repeating: 2, count: 32)])
  )
  let initial = try await initiator.makeInitialMessage()
  let identity = try P256.KeyAgreement.PrivateKey(rawRepresentation: identityBytes)
  let responder = try HybridNoiseTestResponder.respond(
    to: initial,
    peerIdentity: identity.publicKey.x963Representation,
    preSharedKey: psk,
    randomSource: SequenceRandomSource([Data(repeating: 3, count: 32)])
  )
  let result = try await initiator.processResponse(responder.response)

  #expect(initial.count == 81)
  #expect(responder.response.count == 81)
  #expect(result.handshakeHash == responder.handshakeHash)
  #expect(initial.testHex == (try TestVectors.value("noise_initial")))
  #expect(responder.response.testHex == (try TestVectors.value("noise_response")))
  #expect(result.handshakeHash.testHex == (try TestVectors.value("noise_hash")))

  let toResponder = try await result.cipher.encrypt(Data("client".utf8))
  #expect(toResponder.testHex == (try TestVectors.value("transport_client")))
  #expect(try await responder.cipher.decrypt(toResponder) == Data("client".utf8))
  let toInitiator = try await responder.cipher.encrypt(Data("phone".utf8))
  #expect(try await result.cipher.decrypt(toInitiator) == Data("phone".utf8))
}

@Test("Noise handshake rejects wrong PSK, malformed points, and state reuse")
func noiseHandshakeNegativeCases() async throws {
  let identityBytes = Data(repeating: 1, count: 32)
  let bootstrap = HybridQRBootstrap(
    uri: "FIDO:/",
    identityPrivateKey: identityBytes,
    qrSecret: Data(repeating: 0, count: 16)
  )
  let initiator = try HybridNoiseHandshakeInitiator(
    bootstrap: bootstrap,
    preSharedKey: Data(repeating: 0, count: 32),
    randomSource: SequenceRandomSource([Data(repeating: 2, count: 32)])
  )
  let initial = try await initiator.makeInitialMessage()
  await #expect(throws: HybridProtocolError.handshakeStateViolation) {
    try await initiator.makeInitialMessage()
  }

  let identity = try P256.KeyAgreement.PrivateKey(rawRepresentation: identityBytes)
  #expect(throws: (any Error).self) {
    try HybridNoiseTestResponder.respond(
      to: initial,
      peerIdentity: identity.publicKey.x963Representation,
      preSharedKey: Data(repeating: 1, count: 32),
      randomSource: SequenceRandomSource([Data(repeating: 3, count: 32)])
    )
  }
  await #expect(throws: HybridProtocolError.invalidHandshakeMessage) {
    try await initiator.processResponse(Data(repeating: 0, count: 80))
  }
}

@Test("Noise transport fails terminally on tamper")
func noiseTransportTamperIsTerminal() async throws {
  let pair = try await makeNoisePair()
  let ciphertext = try await pair.initiator.encrypt(Data("secret".utf8))
  var tampered = ciphertext
  tampered[tampered.startIndex] ^= 1

  do {
    _ = try await pair.responder.decrypt(tampered)
    Issue.record("Tampered ciphertext unexpectedly authenticated")
  } catch {
    #expect(error as? HybridProtocolError == .messageAuthenticationFailed)
  }
  do {
    _ = try await pair.responder.decrypt(ciphertext)
    Issue.record("Cipher remained usable after authentication failure")
  } catch {
    #expect(error as? HybridProtocolError == .handshakeStateViolation)
  }
}

@Test("Noise transport rejects replay, truncation, padding, and exhausted counters terminally")
func noiseTransportNegativeStateCases() async throws {
  let replayPair = try await makeNoisePair()
  let message = try await replayPair.initiator.encrypt(Data("once".utf8))
  #expect(try await replayPair.responder.decrypt(message) == Data("once".utf8))
  await #expect(throws: HybridProtocolError.messageAuthenticationFailed) {
    try await replayPair.responder.decrypt(message)
  }
  await #expect(throws: HybridProtocolError.handshakeStateViolation) {
    try await replayPair.responder.decrypt(message)
  }

  let truncated = HybridNoiseCipher(
    readKey: Data(repeating: 1, count: 32),
    writeKey: Data(repeating: 2, count: 32)
  )
  await #expect(throws: HybridProtocolError.messageAuthenticationFailed) {
    try await truncated.decrypt(Data(repeating: 0, count: 15))
  }

  let readKey = Data(repeating: 3, count: 32)
  let invalidPadding = HybridNoiseCipher(
    readKey: readKey,
    writeKey: Data(repeating: 4, count: 32)
  )
  let invalidPlaintext = Data([0, 0, 0, 8])
  let authenticatedInvalidPadding = try HybridCryptography.sealAES256GCM(
    plaintext: invalidPlaintext,
    key: readKey,
    nonce: Data(repeating: 0, count: 12),
    authenticatedData: Data()
  )
  await #expect(throws: HybridProtocolError.invalidPadding) {
    try await invalidPadding.decrypt(authenticatedInvalidPadding)
  }

  let exhausted = HybridNoiseCipher(
    readKey: Data(repeating: 5, count: 32),
    writeKey: Data(repeating: 6, count: 32),
    readSequence: HybridNoiseCipher.maximumSequence + 1,
    writeSequence: HybridNoiseCipher.maximumSequence + 1
  )
  await #expect(throws: HybridProtocolError.sequenceExhausted) {
    try await exhausted.encrypt(Data())
  }
  await #expect(throws: HybridProtocolError.handshakeStateViolation) {
    try await exhausted.decrypt(Data(repeating: 0, count: 16))
  }
}

private func makeNoisePair() async throws -> (
  initiator: HybridNoiseCipher,
  responder: HybridNoiseCipher
) {
  let identityBytes = Data(repeating: 1, count: 32)
  let bootstrap = HybridQRBootstrap(
    uri: "FIDO:/",
    identityPrivateKey: identityBytes,
    qrSecret: Data(repeating: 0, count: 16)
  )
  let psk = Data(repeating: 0, count: 32)
  let initiator = try HybridNoiseHandshakeInitiator(
    bootstrap: bootstrap,
    preSharedKey: psk,
    randomSource: SequenceRandomSource([Data(repeating: 2, count: 32)])
  )
  let initial = try await initiator.makeInitialMessage()
  let identity = try P256.KeyAgreement.PrivateKey(rawRepresentation: identityBytes)
  let responder = try HybridNoiseTestResponder.respond(
    to: initial,
    peerIdentity: identity.publicKey.x963Representation,
    preSharedKey: psk,
    randomSource: SequenceRandomSource([Data(repeating: 3, count: 32)])
  )
  let result = try await initiator.processResponse(responder.response)
  return (result.cipher, responder.cipher)
}
