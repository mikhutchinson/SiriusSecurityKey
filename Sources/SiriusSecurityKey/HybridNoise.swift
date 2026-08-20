// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// retained in THIRD_PARTY_NOTICES.md.

import CryptoKit
import Foundation

struct HybridNoiseHandshakeResult: Sendable {
  let cipher: HybridNoiseCipher
  let handshakeHash: Data
}

/// Single-use Noise KNpsk0 initiator for QR-initiated PXP sessions.
actor HybridNoiseHandshakeInitiator {
  private enum State {
    case ready
    case waitingForResponse(
      noise: NoiseSymmetricState,
      ephemeralPrivateKey: Data
    )
    case complete
    case failed
  }

  private let identityPrivateKey: Data
  private let preSharedKey: Data
  private let randomSource: any HybridRandomSource
  private var state: State = .ready

  init(
    bootstrap: HybridQRBootstrap,
    preSharedKey: Data,
    randomSource: any HybridRandomSource
  ) throws {
    guard bootstrap.identityPrivateKey.count == 32, preSharedKey.count == 32,
      (try? P256.KeyAgreement.PrivateKey(
        rawRepresentation: bootstrap.identityPrivateKey
      )) != nil
    else {
      throw HybridProtocolError.invalidKeyMaterial
    }
    self.identityPrivateKey = bootstrap.identityPrivateKey
    self.preSharedKey = preSharedKey
    self.randomSource = randomSource
  }

  func makeInitialMessage() throws -> Data {
    guard case .ready = state else {
      throw HybridProtocolError.handshakeStateViolation
    }

    do {
      let identity = try P256.KeyAgreement.PrivateKey(
        rawRepresentation: identityPrivateKey
      )
      var noise = NoiseSymmetricState(pattern: .knpsk0)
      noise.mixHash(Data([1]))
      noise.mixHash(identity.publicKey.x963Representation)
      try noise.mixKeyAndHash(preSharedKey)

      let ephemeral = try HybridCryptography.privateKey(randomSource: randomSource)
      let ephemeralPublic = ephemeral.publicKey.x963Representation
      noise.mixHash(ephemeralPublic)
      try noise.mixKey(ephemeralPublic)
      let ciphertext = try noise.encryptAndHash(Data())

      var message = ephemeralPublic
      message.append(ciphertext)
      state = .waitingForResponse(
        noise: noise,
        ephemeralPrivateKey: ephemeral.rawRepresentation
      )
      return message
    } catch {
      state = .failed
      throw mapHandshakeError(error)
    }
  }

  func processResponse(_ response: Data) throws -> HybridNoiseHandshakeResult {
    guard case .waitingForResponse(var noise, let ephemeralPrivateKey) = state else {
      throw HybridProtocolError.handshakeStateViolation
    }
    guard response.count == 81 else {
      state = .failed
      throw HybridProtocolError.invalidHandshakeMessage
    }

    do {
      let identity = try P256.KeyAgreement.PrivateKey(
        rawRepresentation: identityPrivateKey
      )
      let ephemeral = try P256.KeyAgreement.PrivateKey(
        rawRepresentation: ephemeralPrivateKey
      )
      let peerPointBytes = response.prefix(65)
      let ciphertext = response.suffix(16)
      let peerPoint = try P256.KeyAgreement.PublicKey(
        x963Representation: peerPointBytes
      )

      noise.mixHash(peerPointBytes)
      try noise.mixKey(peerPointBytes)
      try noise.mixKey(
        ephemeral.sharedSecretFromKeyAgreement(with: peerPoint).data
      )
      try noise.mixKey(
        identity.sharedSecretFromKeyAgreement(with: peerPoint).data
      )
      let plaintext = try noise.decryptAndHash(ciphertext)
      guard plaintext.isEmpty else {
        throw HybridProtocolError.invalidHandshakeMessage
      }

      let (writeKey, readKey) = try noise.split()
      let result = HybridNoiseHandshakeResult(
        cipher: HybridNoiseCipher(readKey: readKey, writeKey: writeKey),
        handshakeHash: noise.handshakeHash
      )
      state = .complete
      return result
    } catch {
      state = .failed
      throw mapHandshakeError(error)
    }
  }

  private func mapHandshakeError(_ error: any Error) -> any Error {
    if let error = error as? HybridProtocolError {
      return error
    }
    return HybridProtocolError.handshakeAuthenticationFailed
  }
}

/// Ordered AES-256-GCM transport state produced by a completed PXP handshake.
/// Authentication or padding failure permanently closes the state.
actor HybridNoiseCipher {
  static let maximumSequence: UInt32 = (1 << 24) - 1
  private static let paddingGranularity = 32
  private static let maximumPlaintextSize = 1 << 20

  private let readKey: Data
  private let writeKey: Data
  private var readSequence: UInt32 = 0
  private var writeSequence: UInt32 = 0
  private var failed = false

  init(
    readKey: Data,
    writeKey: Data,
    readSequence: UInt32 = 0,
    writeSequence: UInt32 = 0
  ) {
    self.readKey = readKey
    self.writeKey = writeKey
    self.readSequence = readSequence
    self.writeSequence = writeSequence
  }

  func encrypt(_ plaintext: Data) throws -> Data {
    guard !failed else {
      throw HybridProtocolError.handshakeStateViolation
    }
    guard plaintext.count <= Self.maximumPlaintextSize else {
      failed = true
      throw HybridProtocolError.messageTooLarge
    }
    guard writeSequence <= Self.maximumSequence else {
      failed = true
      throw HybridProtocolError.sequenceExhausted
    }

    let extraBytes = Self.paddingGranularity - plaintext.count % Self.paddingGranularity
    var padded = Data(count: plaintext.count + extraBytes)
    padded.replaceSubrange(0..<plaintext.count, with: plaintext)
    padded[padded.count - 1] = UInt8(extraBytes - 1)

    do {
      let ciphertext = try HybridCryptography.sealAES256GCM(
        plaintext: padded,
        key: writeKey,
        nonce: Self.transportNonce(sequence: writeSequence),
        authenticatedData: Data()
      )
      writeSequence += 1
      return ciphertext
    } catch {
      failed = true
      throw HybridProtocolError.messageAuthenticationFailed
    }
  }

  func decrypt(_ ciphertext: Data) throws -> Data {
    guard !failed else {
      throw HybridProtocolError.handshakeStateViolation
    }
    guard readSequence <= Self.maximumSequence else {
      failed = true
      throw HybridProtocolError.sequenceExhausted
    }
    guard ciphertext.count >= 16 else {
      failed = true
      throw HybridProtocolError.messageAuthenticationFailed
    }
    guard ciphertext.count <= Self.maximumPlaintextSize + Self.paddingGranularity + 16 else {
      failed = true
      throw HybridProtocolError.messageTooLarge
    }

    do {
      let padded = try HybridCryptography.openAES256GCM(
        ciphertextAndTag: ciphertext,
        key: readKey,
        nonce: Self.transportNonce(sequence: readSequence),
        authenticatedData: Data()
      )
      readSequence += 1
      guard let finalByte = padded.last else {
        throw HybridProtocolError.invalidPadding
      }
      let paddingLength = Int(finalByte)
      guard paddingLength + 1 <= padded.count else {
        throw HybridProtocolError.invalidPadding
      }
      return Data(padded.prefix(padded.count - paddingLength - 1))
    } catch let error as HybridProtocolError {
      failed = true
      throw error
    } catch {
      failed = true
      throw HybridProtocolError.messageAuthenticationFailed
    }
  }

  private static func transportNonce(sequence: UInt32) -> Data {
    Data([
      0, 0, 0, 0, 0, 0, 0, 0,
      UInt8((sequence >> 24) & 0xff),
      UInt8((sequence >> 16) & 0xff),
      UInt8((sequence >> 8) & 0xff),
      UInt8(sequence & 0xff),
    ])
  }
}

private enum NoisePattern {
  case knpsk0

  var protocolName: String {
    switch self {
    case .knpsk0:
      return "Noise_KNpsk0_P256_AESGCM_SHA256"
    }
  }
}

private struct NoiseSymmetricState: Sendable {
  private(set) var chainingKey: Data
  private(set) var handshakeHash: Data
  private var symmetricKey: Data?
  private var symmetricNonce: UInt32 = 0

  init(pattern: NoisePattern) {
    var initial = Data(pattern.protocolName.utf8)
    initial.append(Data(repeating: 0, count: 32 - initial.count))
    chainingKey = initial
    handshakeHash = initial
  }

  mutating func mixHash(_ input: some DataProtocol) {
    var hashInput = handshakeHash
    hashInput.append(contentsOf: input)
    handshakeHash = HybridCryptography.sha256(hashInput)
  }

  mutating func mixKey(_ inputKeyMaterial: some DataProtocol) throws {
    let output = try HybridCryptography.hkdfSHA256(
      inputKeyMaterial: Data(inputKeyMaterial),
      salt: chainingKey,
      outputByteCount: 64
    )
    chainingKey = output.prefix(32)
    initializeKey(output.suffix(32))
  }

  mutating func mixKeyAndHash(_ inputKeyMaterial: some DataProtocol) throws {
    let output = try HybridCryptography.hkdfSHA256(
      inputKeyMaterial: Data(inputKeyMaterial),
      salt: chainingKey,
      outputByteCount: 96
    )
    chainingKey = output.prefix(32)
    mixHash(output.subdata(in: 32..<64))
    initializeKey(output.suffix(32))
  }

  mutating func encryptAndHash(_ plaintext: Data) throws -> Data {
    guard let symmetricKey else {
      throw HybridProtocolError.handshakeStateViolation
    }
    let ciphertext = try HybridCryptography.sealAES256GCM(
      plaintext: plaintext,
      key: symmetricKey,
      nonce: try handshakeNonce(),
      authenticatedData: handshakeHash
    )
    symmetricNonce += 1
    mixHash(ciphertext)
    return ciphertext
  }

  mutating func decryptAndHash(_ ciphertext: some DataProtocol) throws -> Data {
    guard let symmetricKey else {
      throw HybridProtocolError.handshakeStateViolation
    }
    let plaintext: Data
    do {
      plaintext = try HybridCryptography.openAES256GCM(
        ciphertextAndTag: Data(ciphertext),
        key: symmetricKey,
        nonce: try handshakeNonce(),
        authenticatedData: handshakeHash
      )
    } catch {
      throw HybridProtocolError.handshakeAuthenticationFailed
    }
    symmetricNonce += 1
    mixHash(ciphertext)
    return plaintext
  }

  func split() throws -> (Data, Data) {
    let output = try HybridCryptography.hkdfSHA256(
      inputKeyMaterial: Data(),
      salt: chainingKey,
      outputByteCount: 64
    )
    return (output.prefix(32), output.suffix(32))
  }

  private mutating func initializeKey(_ key: some DataProtocol) {
    symmetricKey = Data(key)
    symmetricNonce = 0
  }

  private func handshakeNonce() throws -> Data {
    guard symmetricNonce <= HybridNoiseCipher.maximumSequence else {
      throw HybridProtocolError.sequenceExhausted
    }
    return Data([
      UInt8((symmetricNonce >> 24) & 0xff),
      UInt8((symmetricNonce >> 16) & 0xff),
      UInt8((symmetricNonce >> 8) & 0xff),
      UInt8(symmetricNonce & 0xff),
      0, 0, 0, 0, 0, 0, 0, 0,
    ])
  }
}

struct HybridNoiseResponderResult: Sendable {
  let response: Data
  let cipher: HybridNoiseCipher
  let handshakeHash: Data
}

enum HybridNoiseTestResponder {
  static func respond(
    to initialMessage: Data,
    peerIdentity: Data,
    preSharedKey: Data,
    randomSource: any HybridRandomSource
  ) throws -> HybridNoiseResponderResult {
    guard initialMessage.count == 81, peerIdentity.count == 65,
      preSharedKey.count == 32
    else {
      throw HybridProtocolError.invalidHandshakeMessage
    }

    let peerEphemeralBytes = initialMessage.prefix(65)
    let peerCiphertext = initialMessage.suffix(16)
    let peerEphemeral = try P256.KeyAgreement.PublicKey(
      x963Representation: peerEphemeralBytes
    )
    let peerIdentityKey = try P256.KeyAgreement.PublicKey(
      x963Representation: peerIdentity
    )

    var noise = NoiseSymmetricState(pattern: .knpsk0)
    noise.mixHash(Data([1]))
    noise.mixHash(peerIdentity)
    try noise.mixKeyAndHash(preSharedKey)
    noise.mixHash(peerEphemeralBytes)
    try noise.mixKey(peerEphemeralBytes)
    guard try noise.decryptAndHash(peerCiphertext).isEmpty else {
      throw HybridProtocolError.invalidHandshakeMessage
    }

    let ephemeral = try HybridCryptography.privateKey(randomSource: randomSource)
    let ephemeralPublic = ephemeral.publicKey.x963Representation
    noise.mixHash(ephemeralPublic)
    try noise.mixKey(ephemeralPublic)
    try noise.mixKey(
      ephemeral.sharedSecretFromKeyAgreement(with: peerEphemeral).data
    )
    try noise.mixKey(
      ephemeral.sharedSecretFromKeyAgreement(with: peerIdentityKey).data
    )
    let ciphertext = try noise.encryptAndHash(Data())
    var response = ephemeralPublic
    response.append(ciphertext)

    let (readKey, writeKey) = try noise.split()
    return HybridNoiseResponderResult(
      response: response,
      cipher: HybridNoiseCipher(readKey: readKey, writeKey: writeKey),
      handshakeHash: noise.handshakeHash
    )
  }
}
