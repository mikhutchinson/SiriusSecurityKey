import Foundation

/// Stable, secret-free categories for failures in a hybrid transaction.
public enum HybridProtocolError: Error, Sendable, Equatable {
  case invalidConfiguration
  case invalidRandomness
  case invalidKeyMaterial
  case invalidQRPayload
  case invalidAdvertisement
  case unknownTunnelDomain
  case invalidTunnelURL
  case invalidWebSocketSubprotocol
  case nonBinaryWebSocketMessage
  case messageTooLarge
  case handshakeStateViolation
  case invalidHandshakeMessage
  case handshakeAuthenticationFailed
  case sequenceExhausted
  case messageAuthenticationFailed
  case invalidPadding
  case invalidPostHandshakeMessage
  case unsupportedPostHandshakeFeature
  case invalidHybridMessage
  case unexpectedShutdown
  case ctapStatus(UInt8)
  case invalidAuthenticatorInfo
  case cancelled
  case timeout
}

/// The wire profile selected for a hybrid transaction.
///
/// Profiles are explicit. The implementation never retries a failed parse as a
/// different profile.
public enum HybridWireProfile: String, Sendable, CaseIterable {
  /// Current PXP framing: the post-handshake plaintext is one canonical CBOR
  /// map without an outer padding trailer.
  case pxp20260717

  /// Chromium caBLE v2 revision-zero framing: the canonical CBOR map is
  /// followed by zero padding and a little-endian UInt16 padding length.
  case chromiumCableV2Revision0
}
