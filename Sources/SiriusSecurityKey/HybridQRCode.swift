// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// retained in THIRD_PARTY_NOTICES.md.

import CryptoKit
import Foundation

/// Early request hint carried in a FIDO QR bootstrap.
public enum HybridRequestType: String, Sendable, CaseIterable {
  case getAssertion = "ga"
  case makeCredential = "mc"
  case credentialPresentation = "dcp"
  case credentialIssuance = "dci"
}

/// PXP data-transfer channel identifiers.
public enum HybridTransferChannel: UInt32, Sendable, CaseIterable {
  case webSocket = 0
  case bluetoothLowEnergy = 1
}

/// Non-secret inputs encoded into a `FIDO:/` bootstrap URI.
public struct HybridQRConfiguration: Sendable, Equatable {
  /// Number of assigned tunnel-domain identifiers understood by this client.
  /// `HybridSession` currently requires the pinned value `2`.
  public let assignedTunnelServerDomainCount: UInt32
  /// Optional Unix epoch timestamp encoded in the bootstrap.
  public let timestamp: UInt32?
  /// Whether state-assisted transactions may be retained by the client.
  /// `HybridSession` rejects `true` until pairing and revocation ship.
  public let supportsLinking: Bool?
  /// Non-binding hint used by the scanning device for early UI.
  /// The current `HybridSession.getInfo` slice requires `getAssertion`.
  public let requestType: HybridRequestType
  /// Explicit channel list, or `nil` for the specified WebSocket default.
  /// `HybridSession` currently rejects any channel other than WebSocket.
  public let transferChannels: [HybridTransferChannel]?

  /// Creates non-secret QR configuration.
  public init(
    assignedTunnelServerDomainCount: UInt32 = 2,
    timestamp: UInt32? = nil,
    supportsLinking: Bool? = false,
    requestType: HybridRequestType,
    transferChannels: [HybridTransferChannel]? = nil
  ) {
    self.assignedTunnelServerDomainCount = assignedTunnelServerDomainCount
    self.timestamp = timestamp
    self.supportsLinking = supportsLinking
    self.requestType = requestType
    self.transferChannels = transferChannels
  }
}

/// A generated QR bootstrap retained only inside its owning session. Secret
/// material never crosses the module boundary.
struct HybridQRBootstrap: Sendable {
  /// Canonical uppercase `FIDO:/` URI for consumer-owned presentation.
  let uri: String

  let identityPrivateKey: Data
  let qrSecret: Data
}

enum HybridQRCode {
  /// Generates fresh P-256 identity and QR-secret material and returns the
  /// canonical FIDO URI. Randomness is injectable for authoritative vectors.
  static func generate(
    configuration: HybridQRConfiguration,
    randomSource: any HybridRandomSource = SystemHybridRandomSource()
  ) throws -> HybridQRBootstrap {
    if let channels = configuration.transferChannels {
      guard !channels.isEmpty, Set(channels).count == channels.count else {
        throw HybridProtocolError.invalidConfiguration
      }
    }

    let identity = try HybridCryptography.privateKey(randomSource: randomSource)
    let secret = try randomSource.randomBytes(count: 16)
    guard secret.count == 16 else {
      throw HybridProtocolError.invalidRandomness
    }

    var entries = [
      CBORMapEntry(
        key: .unsigned(0),
        value: .byteString(identity.publicKey.compressedRepresentation)
      ),
      CBORMapEntry(key: .unsigned(1), value: .byteString(secret)),
      CBORMapEntry(
        key: .unsigned(2),
        value: .unsigned(configuration.assignedTunnelServerDomainCount)
      ),
      CBORMapEntry(
        key: .unsigned(5),
        value: .textString(configuration.requestType.rawValue)
      ),
    ]
    if let timestamp = configuration.timestamp {
      entries.append(CBORMapEntry(key: .unsigned(3), value: .unsigned(timestamp)))
    }
    if let supportsLinking = configuration.supportsLinking {
      entries.append(CBORMapEntry(key: .unsigned(4), value: .boolean(supportsLinking)))
    }
    if let channels = configuration.transferChannels {
      entries.append(
        CBORMapEntry(
          key: .unsigned(6),
          value: .array(channels.map { .unsigned($0.rawValue) })
        )
      )
    }

    let encoded = try CanonicalCBOR.encode(.map(entries))
    let uri = "FIDO:/" + DigitEncoding.encode(encoded)
    return HybridQRBootstrap(
      uri: uri,
      identityPrivateKey: identity.rawRepresentation,
      qrSecret: secret
    )
  }
}

struct ParsedHybridQRCode: Sendable, Equatable {
  let compressedPublicKey: Data
  let qrSecret: Data
  let assignedTunnelServerDomainCount: UInt32
  let timestamp: UInt32?
  let supportsLinking: Bool?
  let requestType: HybridRequestType
  let transferChannels: [HybridTransferChannel]?
}

extension HybridQRCode {
  static func parse(_ uri: String) throws -> ParsedHybridQRCode {
    guard uri.hasPrefix("FIDO:/") else {
      throw HybridProtocolError.invalidQRPayload
    }
    let rawDigits = uri.utf8.dropFirst(6)
    guard rawDigits.count <= DigitEncoding.maximumDigitCount,
      rawDigits.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 })
    else {
      throw HybridProtocolError.invalidQRPayload
    }
    let digits = String(uri.dropFirst(6))
    let bytes = try DigitEncoding.decode(digits)
    let value: CBORValue
    do {
      value = try CanonicalCBOR.decode(bytes)
    } catch {
      throw HybridProtocolError.invalidQRPayload
    }

    guard
      case .byteString(let compressedPublicKey)? = value.value(forUnsignedKey: 0),
      compressedPublicKey.count == 33,
      (try? P256.KeyAgreement.PublicKey(compressedRepresentation: compressedPublicKey)) != nil,
      case .byteString(let qrSecret)? = value.value(forUnsignedKey: 1),
      qrSecret.count == 16
    else {
      throw HybridProtocolError.invalidQRPayload
    }

    let assignedDomains: UInt32
    if let rawAssignedDomains = value.value(forUnsignedKey: 2) {
      guard case .unsigned(let count) = rawAssignedDomains else {
        throw HybridProtocolError.invalidQRPayload
      }
      assignedDomains = count
    } else {
      assignedDomains = 0
    }

    let timestamp: UInt32?
    if let rawTimestamp = value.value(forUnsignedKey: 3) {
      guard case .unsigned(let value) = rawTimestamp else {
        throw HybridProtocolError.invalidQRPayload
      }
      timestamp = value
    } else {
      timestamp = nil
    }

    let supportsLinking: Bool?
    if let rawSupportsLinking = value.value(forUnsignedKey: 4) {
      guard case .boolean(let value) = rawSupportsLinking else {
        throw HybridProtocolError.invalidQRPayload
      }
      supportsLinking = value
    } else {
      supportsLinking = nil
    }

    let requestType: HybridRequestType
    if let rawRequestType = value.value(forUnsignedKey: 5) {
      guard case .textString(let string) = rawRequestType else {
        throw HybridProtocolError.invalidQRPayload
      }
      requestType = HybridRequestType(rawValue: string) ?? .getAssertion
    } else {
      requestType = .getAssertion
    }

    let transferChannels: [HybridTransferChannel]?
    if let rawChannels = value.value(forUnsignedKey: 6) {
      guard case .array(let values) = rawChannels, !values.isEmpty else {
        throw HybridProtocolError.invalidQRPayload
      }
      var channels: [HybridTransferChannel] = []
      for value in values {
        guard case .unsigned(let rawValue) = value,
          let channel = HybridTransferChannel(rawValue: rawValue),
          !channels.contains(channel)
        else {
          throw HybridProtocolError.invalidQRPayload
        }
        channels.append(channel)
      }
      transferChannels = channels
    } else {
      transferChannels = nil
    }

    return ParsedHybridQRCode(
      compressedPublicKey: compressedPublicKey,
      qrSecret: qrSecret,
      assignedTunnelServerDomainCount: assignedDomains,
      timestamp: timestamp,
      supportsLinking: supportsLinking,
      requestType: requestType,
      transferChannels: transferChannels
    )
  }
}

enum DigitEncoding {
  private static let chunkSize = 7
  private static let chunkDigits = 17
  private static let widths = [0, 3, 5, 8, 10, 13, 15, 17]
  static let maximumDigitCount = 2_487

  static func encode(_ data: Data) -> String {
    var normalized = Data()
    normalized.append(data)
    var result = ""
    result.reserveCapacity(((normalized.count + chunkSize - 1) / chunkSize) * chunkDigits)
    var offset = 0
    while offset < normalized.count {
      let count = min(chunkSize, normalized.count - offset)
      var value: UInt64 = 0
      for index in 0..<count {
        value |= UInt64(normalized[offset + index]) << UInt64(index * 8)
      }
      let digits = String(value)
      result += String(repeating: "0", count: widths[count] - digits.count)
      result += digits
      offset += count
    }
    return result
  }

  static func decode(_ digits: String) throws -> Data {
    guard digits.utf8.count <= maximumDigitCount,
      digits.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 })
    else {
      throw HybridProtocolError.invalidQRPayload
    }
    var result = Data()
    var remaining = digits[...]
    while remaining.count >= chunkDigits {
      let end = remaining.index(remaining.startIndex, offsetBy: chunkDigits)
      let chunk = remaining[..<end]
      try append(chunk: chunk, byteCount: chunkSize, to: &result)
      remaining = remaining[end...]
    }

    if !remaining.isEmpty {
      let byteCount: Int
      switch remaining.count {
      case 3: byteCount = 1
      case 5: byteCount = 2
      case 8: byteCount = 3
      case 10: byteCount = 4
      case 13: byteCount = 5
      case 15: byteCount = 6
      default: throw HybridProtocolError.invalidQRPayload
      }
      try append(chunk: remaining, byteCount: byteCount, to: &result)
    }
    return result
  }

  private static func append(
    chunk: Substring,
    byteCount: Int,
    to result: inout Data
  ) throws {
    guard let value = UInt64(chunk), value >> UInt64(byteCount * 8) == 0 else {
      throw HybridProtocolError.invalidQRPayload
    }
    for index in 0..<byteCount {
      result.append(UInt8((value >> UInt64(index * 8)) & 0xff))
    }
  }
}
