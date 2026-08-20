// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// retained in THIRD_PARTY_NOTICES.md.

import Foundation

/// Session-private owner of an established hybrid CTAP channel.
///
/// The type is intentionally not public: ceremony policy is the only public
/// route to assertion commands. Every transaction has one dispatch attempt;
/// any ambiguous send or receive failure permanently closes the transport.
actor HybridAuthenticatorTransport: AuthenticatorTransport {
  nonisolated let kind: AuthenticatorTransportKind = .hybrid

  private let channel: any HybridBinaryChannel
  private let cipher: HybridNoiseCipher
  private let wireProfile: HybridWireProfile
  private var isTerminal = false

  init(
    channel: any HybridBinaryChannel,
    cipher: HybridNoiseCipher,
    wireProfile: HybridWireProfile
  ) {
    self.channel = channel
    self.cipher = cipher
    self.wireProfile = wireProfile
  }

  func transact(_ request: CTAPRequest) async throws -> CTAPResponse {
    guard !isTerminal else {
      throw HybridProtocolError.handshakeStateViolation
    }

    var plaintext = Data()
    if wireProfile == .pxp20260717 {
      plaintext.append(1)
    }
    plaintext.append(request.encoded)
    let encrypted: Data
    do {
      encrypted = try await cipher.encrypt(plaintext)
    } catch {
      await terminate()
      throw error
    }

    do {
      // There is deliberately one send and no retry after this point.
      try await channel.send(encrypted)
      return try await receiveCTAPResponse()
    } catch {
      await terminate()
      throw error
    }
  }

  func finish() async throws {
    guard !isTerminal else {
      return
    }
    if wireProfile == .chromiumCableV2Revision0 {
      isTerminal = true
      await channel.cancel()
      return
    }
    do {
      let shutdown = try await cipher.encrypt(Data([0]))
      try await channel.send(shutdown)
      isTerminal = true
      await channel.cancel()
    } catch {
      await terminate()
      throw error
    }
  }

  func cancel() async {
    await terminate()
  }

  private func receiveCTAPResponse() async throws -> CTAPResponse {
    if wireProfile == .chromiumCableV2Revision0 {
      let encrypted = try await channel.receive()
      let plaintext = try await cipher.decrypt(encrypted)
      do {
        return try CTAPResponse(encoded: plaintext)
      } catch {
        throw HybridProtocolError.invalidHybridMessage
      }
    }

    // Status messages are bounded and never interpreted as command success.
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
        do {
          return try CTAPResponse(encoded: Data(payload))
        } catch {
          throw HybridProtocolError.invalidHybridMessage
        }
      case 2:
        do {
          _ = try CanonicalCBOR.decode(
            Data(payload),
            limits: CBORLimits(
              maximumMessageSize: 4_096,
              maximumNestingDepth: 4,
              maximumCollectionCount: 32,
              maximumStringSize: 2_048,
              maximumTotalItems: 128
            )
          )
        } catch {
          throw HybridProtocolError.invalidHybridMessage
        }
      default:
        throw HybridProtocolError.invalidHybridMessage
      }
    }
    throw HybridProtocolError.messageTooLarge
  }

  private func terminate() async {
    guard !isTerminal else {
      return
    }
    isTerminal = true
    await channel.cancel()
  }
}
