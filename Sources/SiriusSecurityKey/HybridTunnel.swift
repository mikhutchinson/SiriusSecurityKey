// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// retained in THIRD_PARTY_NOTICES.md.

import Foundation

public protocol HybridBinaryChannel: Sendable {
  /// Sends one complete binary application message.
  func send(_ data: Data) async throws
  /// Receives one complete binary application message.
  func receive() async throws -> Data
  /// Terminates the channel. Cancellation is idempotent.
  func cancel() async
}

/// Injectable WebSocket boundary. Implementations must complete only after the
/// requested subprotocol has been selected.
public protocol HybridWebSocketConnector: Sendable {
  /// Opens a bounded WebSocket and verifies the selected subprotocol before
  /// returning a channel.
  func connect(
    to url: URL,
    subprotocol: String,
    maximumMessageSize: Int
  ) async throws -> any HybridBinaryChannel
}

/// Secret-free tunnel failure categories.
public enum HybridTunnelError: Error, Sendable, Equatable {
  case connectionFailed
  case connectionClosed
  case sendFailed
  case receiveFailed
  case insecureRedirect
}

struct HybridTunnelEndpoint: Sendable, Equatable {
  static let subprotocolName = "fido.cable"
  static let maximumMessageSize = 1 << 20

  let url: URL
  let subprotocolName: String
  let maximumMessageSize: Int
}

enum HybridTunnelRouting {
  static func endpoint(
    match: HybridProximityMatch,
    bootstrap: HybridQRBootstrap
  ) throws -> HybridTunnelEndpoint {
    guard match.routingID.count == 3 else {
      throw HybridProtocolError.invalidAdvertisement
    }
    let tunnelID = try HybridCryptography.derive(
      secret: bootstrap.qrSecret,
      purpose: .tunnelID,
      outputByteCount: 16
    )
    let path = "/cable/connect/\(match.routingID.lowercaseHex)/\(tunnelID.lowercaseHex)"
    var components = URLComponents()
    components.scheme = "wss"
    components.host = match.tunnelServerDomain.host
    components.path = path
    guard let url = components.url,
      url.scheme == "wss",
      url.host == match.tunnelServerDomain.host,
      url.user == nil,
      url.password == nil,
      url.query == nil,
      url.fragment == nil
    else {
      throw HybridProtocolError.invalidTunnelURL
    }
    return HybridTunnelEndpoint(
      url: url,
      subprotocolName: HybridTunnelEndpoint.subprotocolName,
      maximumMessageSize: HybridTunnelEndpoint.maximumMessageSize
    )
  }
}

extension Data {
  fileprivate var lowercaseHex: String {
    let alphabet = Array("0123456789abcdef".utf8)
    var result = [UInt8]()
    result.reserveCapacity(count * 2)
    for byte in self {
      result.append(alphabet[Int(byte >> 4)])
      result.append(alphabet[Int(byte & 0x0f)])
    }
    return String(decoding: result, as: UTF8.self)
  }
}
