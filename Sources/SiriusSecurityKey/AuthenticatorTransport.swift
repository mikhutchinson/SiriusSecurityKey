import Foundation

/// A CTAP command and its encoded payload.
///
/// This type deliberately does not interpret CBOR. Transport implementations
/// preserve the command byte and payload exactly across the authenticator
/// boundary.
public struct CTAPRequest: Sendable, Equatable {
  public let command: UInt8
  public let payload: Data

  public init(command: UInt8, payload: Data = Data()) {
    self.command = command
    self.payload = payload
  }

  public init(encoded: Data) throws {
    guard let command = encoded.first else {
      throw CTAPFramingError.missingCommand
    }
    self.command = command
    self.payload = encoded.dropFirst()
  }

  public var encoded: Data {
    var data = Data([command])
    data.append(payload)
    return data
  }
}

/// A CTAP status byte and its encoded response payload.
public struct CTAPResponse: Sendable, Equatable {
  public let status: UInt8
  public let payload: Data

  public init(status: UInt8, payload: Data = Data()) {
    self.status = status
    self.payload = payload
  }

  public init(encoded: Data) throws {
    guard let status = encoded.first else {
      throw CTAPFramingError.missingStatus
    }
    self.status = status
    self.payload = encoded.dropFirst()
  }

  public var encoded: Data {
    var data = Data([status])
    data.append(payload)
    return data
  }
}

public enum CTAPFramingError: Error, Sendable, Equatable {
  case missingCommand
  case missingStatus
}

public enum AuthenticatorTransportKind: String, Sendable, CaseIterable {
  case platform
  case usb
  case nfc
  case bluetooth
  case hybrid
}

/// The transport boundary shared by platform, roaming, and hybrid
/// authenticators.
public protocol AuthenticatorTransport: Sendable {
  var kind: AuthenticatorTransportKind { get }

  func transact(_ request: CTAPRequest) async throws -> CTAPResponse
  func cancel() async
}
