// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// retained in THIRD_PARTY_NOTICES.md.

import CryptoKit
import Foundation

public struct HybridBluetoothAdvertisement: Sendable, Equatable {
  /// Advertised FIDO service UUID.
  public let serviceUUID: UUID
  /// Bounded service-data bytes for that UUID.
  public let serviceData: Data

  /// Creates a service-data observation without peripheral identity metadata.
  public init(serviceUUID: UUID, serviceData: Data) {
    self.serviceUUID = serviceUUID
    var normalizedServiceData = Data()
    normalizedServiceData.append(serviceData)
    self.serviceData = normalizedServiceData
  }
}

/// Platform boundary for bounded BLE service-data discovery.
public protocol HybridBluetoothScanner: Sendable {
  /// Begins a single bounded service-data stream for `serviceUUID`.
  func scan(
    serviceUUID: UUID
  ) async throws -> AsyncThrowingStream<HybridBluetoothAdvertisement, any Error>

  /// Stops scanning and finishes the active stream.
  func stop() async
}

/// Secret-free Bluetooth availability and permission categories.
public enum HybridBluetoothError: Error, Sendable, Equatable {
  case alreadyScanning
  case permissionDenied
  case unavailable
  case poweredOff
  case resetting
  case scanFailed
}

enum HybridProximityState: String, Sendable {
  case idle
  case scanning
  case matched
  case failed
  case cancelled
}

public protocol HybridSleeper: Sendable {
  /// Suspends on a monotonic clock for the requested duration.
  func sleep(for duration: Duration) async throws
}

/// Production monotonic sleeper used for protocol deadlines.
public struct ContinuousHybridSleeper: HybridSleeper {
  /// Creates a continuous-clock sleeper.
  public init() {}

  /// Suspends using `ContinuousClock`.
  public func sleep(for duration: Duration) async throws {
    try await ContinuousClock().sleep(for: duration)
  }
}

struct HybridProximityMatch: Sendable, Equatable {
  let plaintext: Data
  let nonce: Data
  let routingID: Data
  let tunnelServerDomain: HybridTunnelServerDomain
}

/// Actor-owned, single-use proof-of-proximity state machine.
actor HybridProximityDiscovery {
  static let serviceUUID = UUID(
    uuid: (
      0x00, 0x00, 0xff, 0xf9, 0x00, 0x00, 0x10, 0x00,
      0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb
    )
  )

  private(set) var state: HybridProximityState = .idle

  init() {}

  func awaitMatch(
    bootstrap: HybridQRBootstrap,
    scanner: any HybridBluetoothScanner,
    timeout: Duration,
    sleeper: any HybridSleeper = ContinuousHybridSleeper()
  ) async throws -> HybridProximityMatch {
    guard state == .idle, timeout > .zero else {
      throw HybridProtocolError.invalidConfiguration
    }
    state = .scanning

    let eidKey = try HybridCryptography.derive(
      secret: bootstrap.qrSecret,
      purpose: .eidKey,
      outputByteCount: 64
    )
    let stream: AsyncThrowingStream<HybridBluetoothAdvertisement, any Error>
    do {
      stream = try await scanner.scan(serviceUUID: Self.serviceUUID)
    } catch is CancellationError {
      state = .cancelled
      throw HybridProtocolError.cancelled
    } catch {
      state = .failed
      throw error
    }

    do {
      let match = try await withThrowingTaskGroup(of: HybridProximityMatch.self) { group in
        group.addTask {
          for try await advertisement in stream {
            try Task.checkCancellation()
            if let match = try Self.match(advertisement, eidKey: eidKey) {
              return match
            }
          }
          try Task.checkCancellation()
          throw HybridBluetoothError.scanFailed
        }
        group.addTask {
          try await sleeper.sleep(for: timeout)
          throw HybridProtocolError.timeout
        }

        guard let first = try await group.next() else {
          throw HybridBluetoothError.scanFailed
        }
        group.cancelAll()
        return first
      }
      await scanner.stop()
      state = .matched
      return match
    } catch is CancellationError {
      await scanner.stop()
      state = .cancelled
      throw HybridProtocolError.cancelled
    } catch {
      await scanner.stop()
      state = .failed
      throw error
    }
  }

  private static func match(
    _ advertisement: HybridBluetoothAdvertisement,
    eidKey: Data
  ) throws -> HybridProximityMatch? {
    guard advertisement.serviceUUID == serviceUUID,
      advertisement.serviceData.count >= 20,
      eidKey.count == 64
    else {
      return nil
    }

    let candidate = advertisement.serviceData.prefix(20)
    let ciphertext = Data(candidate.prefix(16))
    let tag = Data(candidate.suffix(4))
    let encryptionKey = Data(eidKey.prefix(32))
    let authenticationKey = Data(eidKey.suffix(32))
    let expectedTag = Data(
      HybridCryptography.hmacSHA256(key: authenticationKey, message: ciphertext).prefix(4)
    )
    guard constantTimeEqual(tag, expectedTag) else {
      return nil
    }

    let plaintext = try HybridCryptography.decryptAES256Block(
      ciphertext,
      key: encryptionKey
    )
    guard plaintext.count == 16, plaintext[0] == 0 else {
      return nil
    }

    let domainValue = UInt16(plaintext[14]) | UInt16(plaintext[15]) << 8
    let domain: HybridTunnelServerDomain
    do {
      domain = try HybridTunnelServerDomain(rawValue: domainValue)
    } catch {
      return nil
    }

    return HybridProximityMatch(
      plaintext: plaintext,
      nonce: plaintext.subdata(in: 1..<11),
      routingID: plaintext.subdata(in: 11..<14),
      tunnelServerDomain: domain
    )
  }
}

private func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
  guard lhs.count == rhs.count else {
    return false
  }
  var difference: UInt8 = 0
  for (lhsByte, rhsByte) in zip(lhs, rhs) {
    difference |= lhsByte ^ rhsByte
  }
  return difference == 0
}

/// A validated assigned or hashed PXP tunnel-server identifier.
struct HybridTunnelServerDomain: Sendable, Equatable, Hashable {
  let rawValue: UInt16

  init(rawValue: UInt16) throws {
    guard rawValue < 2 || rawValue >= 256 else {
      throw HybridProtocolError.unknownTunnelDomain
    }
    self.rawValue = rawValue
  }

  var host: String {
    switch rawValue {
    case 0:
      return "cable.ua5v.com"
    case 1:
      return "cable.auth.com"
    default:
      return Self.hashedHost(for: rawValue)
    }
  }

  private static func hashedHost(for value: UInt16) -> String {
    var input = Data("caBLEv2 tunnel server domain".utf8)
    input.append(UInt8(value & 0xff))
    input.append(UInt8((value >> 8) & 0xff))
    input.append(0)
    let digest = ProtocolCryptography.sha256(input)
    var encoded: UInt64 = 0
    for index in 0..<8 {
      encoded |= UInt64(digest[index]) << UInt64(index * 8)
    }

    let topLevelDomains = ["com", "org", "net", "info"]
    let topLevelDomain = topLevelDomains[Int(encoded & 3)]
    encoded >>= 2
    let alphabet = Array("abcdefghijklmnopqrstuvwxyz234567".utf8)
    var label = ""
    while encoded != 0 {
      label.append(Character(UnicodeScalar(alphabet[Int(encoded & 31)])))
      encoded >>= 5
    }
    return "cable.\(label).\(topLevelDomain)"
  }
}
