// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license retained in
// THIRD_PARTY_NOTICES.md.

import Foundation

/// Validated `authenticatorGetInfo` capabilities with the complete canonical
/// response retained for forward-compatible inspection.
public struct AuthenticatorInfo: Sendable, Equatable {
  /// CTAP protocol versions advertised by the authenticator.
  public let versions: [String]
  /// Authenticator extension identifiers.
  public let extensions: [String]
  /// The authenticator's 16-byte AAGUID.
  public let aaguid: Data
  /// Boolean CTAP option identifiers.
  public let options: [String: Bool]
  /// Optional maximum CTAP message size.
  public let maximumMessageSize: UInt32?
  /// Supported PIN/UV protocol versions in authenticator preference order.
  public let pinUVAuthProtocols: [UInt32]
  /// Complete validated response, including unknown forward-compatible fields.
  public let rawResponse: CBORValue
}

enum AuthenticatorInfoParser {
  static func parse(response: CTAPResponse) throws -> AuthenticatorInfo {
    guard response.status == 0 else {
      throw HybridProtocolError.ctapStatus(response.status)
    }
    return try parse(payload: response.payload)
  }

  static func parse(payload: Data) throws -> AuthenticatorInfo {
    let raw: CBORValue
    do {
      raw = try CanonicalCBOR.decode(payload)
    } catch {
      throw HybridProtocolError.invalidAuthenticatorInfo
    }
    guard case .map = raw else {
      throw HybridProtocolError.invalidAuthenticatorInfo
    }

    let versions = try stringArray(raw.value(forUnsignedKey: 1), required: true)
    guard !versions.isEmpty,
      case .byteString(let aaguid)? = raw.value(forUnsignedKey: 3),
      aaguid.count == 16
    else {
      throw HybridProtocolError.invalidAuthenticatorInfo
    }

    let extensions = try stringArray(raw.value(forUnsignedKey: 2), required: false)
    let options = try booleanMap(raw.value(forUnsignedKey: 4))

    let maximumMessageSize: UInt32?
    if let rawMaximum = raw.value(forUnsignedKey: 5) {
      guard case .unsigned(let value) = rawMaximum, value > 0 else {
        throw HybridProtocolError.invalidAuthenticatorInfo
      }
      maximumMessageSize = value
    } else {
      maximumMessageSize = nil
    }

    let pinUVAuthProtocols = try unsignedArray(raw.value(forUnsignedKey: 6))
    return AuthenticatorInfo(
      versions: versions,
      extensions: extensions,
      aaguid: aaguid,
      options: options,
      maximumMessageSize: maximumMessageSize,
      pinUVAuthProtocols: pinUVAuthProtocols,
      rawResponse: raw
    )
  }

  private static func stringArray(
    _ value: CBORValue?,
    required: Bool
  ) throws -> [String] {
    guard let value else {
      if required {
        throw HybridProtocolError.invalidAuthenticatorInfo
      }
      return []
    }
    guard case .array(let values) = value else {
      throw HybridProtocolError.invalidAuthenticatorInfo
    }
    var strings: [String] = []
    strings.reserveCapacity(values.count)
    for value in values {
      guard case .textString(let string) = value, !string.isEmpty,
        !strings.contains(string)
      else {
        throw HybridProtocolError.invalidAuthenticatorInfo
      }
      strings.append(string)
    }
    return strings
  }

  private static func booleanMap(_ value: CBORValue?) throws -> [String: Bool] {
    guard let value else {
      return [:]
    }
    guard case .map(let entries) = value else {
      throw HybridProtocolError.invalidAuthenticatorInfo
    }
    var options: [String: Bool] = [:]
    for entry in entries {
      guard case .textString(let key) = entry.key,
        case .boolean(let value) = entry.value,
        options.updateValue(value, forKey: key) == nil
      else {
        throw HybridProtocolError.invalidAuthenticatorInfo
      }
    }
    return options
  }

  private static func unsignedArray(_ value: CBORValue?) throws -> [UInt32] {
    guard let value else {
      return []
    }
    guard case .array(let values) = value else {
      throw HybridProtocolError.invalidAuthenticatorInfo
    }
    var integers: [UInt32] = []
    integers.reserveCapacity(values.count)
    for value in values {
      guard case .unsigned(let integer) = value, !integers.contains(integer) else {
        throw HybridProtocolError.invalidAuthenticatorInfo
      }
      integers.append(integer)
    }
    return integers
  }
}
