// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// retained in THIRD_PARTY_NOTICES.md.

import CommonCrypto
import CryptoKit
import Foundation
import Security

/// Injectable source of cryptographically secure random bytes.
public protocol HybridRandomSource: Sendable {
  /// Returns exactly `count` fresh bytes or throws without returning partial
  /// output.
  func randomBytes(count: Int) throws -> Data
}

/// The operating-system CSPRNG used by production hybrid sessions.
public struct SystemHybridRandomSource: HybridRandomSource {
  /// Creates an operating-system random source.
  public init() {}

  /// Reads from `SecRandomCopyBytes`.
  public func randomBytes(count: Int) throws -> Data {
    guard count >= 0 else {
      throw HybridProtocolError.invalidConfiguration
    }
    var data = Data(count: count)
    let status = data.withUnsafeMutableBytes { buffer in
      guard let baseAddress = buffer.baseAddress else {
        return count == 0 ? errSecSuccess : errSecParam
      }
      return SecRandomCopyBytes(kSecRandomDefault, count, baseAddress)
    }
    guard status == errSecSuccess else {
      throw HybridProtocolError.invalidRandomness
    }
    return data
  }
}

enum HybridKeyPurpose: UInt32, Sendable {
  case eidKey = 1
  case tunnelID = 2
  case psk = 3
}

enum HybridCryptography {
  static func derive(
    secret: Data,
    salt: Data = Data(),
    purpose: HybridKeyPurpose,
    outputByteCount: Int
  ) throws -> Data {
    guard !secret.isEmpty, outputByteCount > 0 else {
      throw HybridProtocolError.invalidKeyMaterial
    }
    let purposeBytes = Data([
      UInt8(purpose.rawValue & 0xff),
      UInt8((purpose.rawValue >> 8) & 0xff),
      UInt8((purpose.rawValue >> 16) & 0xff),
      UInt8((purpose.rawValue >> 24) & 0xff),
    ])
    let key = HKDF<SHA256>.deriveKey(
      inputKeyMaterial: SymmetricKey(data: secret),
      salt: salt,
      info: purposeBytes,
      outputByteCount: outputByteCount
    )
    return key.data
  }

  static func hkdfSHA256(
    inputKeyMaterial: Data,
    salt: Data,
    info: Data = Data(),
    outputByteCount: Int
  ) throws -> Data {
    guard outputByteCount > 0 else {
      throw HybridProtocolError.invalidConfiguration
    }
    let key = HKDF<SHA256>.deriveKey(
      inputKeyMaterial: SymmetricKey(data: inputKeyMaterial),
      salt: salt,
      info: info,
      outputByteCount: outputByteCount
    )
    return key.data
  }

  static func sealAES256GCM(
    plaintext: Data,
    key: Data,
    nonce: Data,
    authenticatedData: Data
  ) throws -> Data {
    guard key.count == 32, nonce.count == 12 else {
      throw HybridProtocolError.invalidKeyMaterial
    }
    let sealed = try AES.GCM.seal(
      plaintext,
      using: SymmetricKey(data: key),
      nonce: AES.GCM.Nonce(data: nonce),
      authenticating: authenticatedData
    )
    var result = Data()
    result.append(sealed.ciphertext)
    result.append(sealed.tag)
    return result
  }

  static func openAES256GCM(
    ciphertextAndTag: Data,
    key: Data,
    nonce: Data,
    authenticatedData: Data
  ) throws -> Data {
    guard key.count == 32, nonce.count == 12, ciphertextAndTag.count >= 16 else {
      throw HybridProtocolError.invalidKeyMaterial
    }
    let ciphertext = ciphertextAndTag.dropLast(16)
    let tag = ciphertextAndTag.suffix(16)
    let box = try AES.GCM.SealedBox(
      nonce: AES.GCM.Nonce(data: nonce),
      ciphertext: ciphertext,
      tag: tag
    )
    let plaintext = try AES.GCM.open(
      box,
      using: SymmetricKey(data: key),
      authenticating: authenticatedData
    )
    var normalized = Data()
    normalized.append(plaintext)
    return normalized
  }

  static func hmacSHA256(key: Data, message: Data) -> Data {
    Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
  }

  static func sha256(_ data: Data) -> Data {
    Data(SHA256.hash(data: data))
  }

  static func decryptAES256Block(_ block: Data, key: Data) throws -> Data {
    try cryptAES256Block(block, key: key, operation: CCOperation(kCCDecrypt))
  }

  static func encryptAES256Block(_ block: Data, key: Data) throws -> Data {
    try cryptAES256Block(block, key: key, operation: CCOperation(kCCEncrypt))
  }

  private static func cryptAES256Block(
    _ block: Data,
    key: Data,
    operation: CCOperation
  ) throws -> Data {
    guard block.count == kCCBlockSizeAES128, key.count == kCCKeySizeAES256 else {
      throw HybridProtocolError.invalidKeyMaterial
    }

    var output = Data(count: kCCBlockSizeAES128)
    var outputLength = 0
    let outputCapacity = output.count
    let status: CCCryptorStatus = output.withUnsafeMutableBytes { outputBuffer in
      block.withUnsafeBytes { blockBuffer in
        key.withUnsafeBytes { keyBuffer in
          CCCrypt(
            operation,
            CCAlgorithm(kCCAlgorithmAES),
            CCOptions(kCCOptionECBMode),
            keyBuffer.baseAddress,
            key.count,
            nil,
            blockBuffer.baseAddress,
            block.count,
            outputBuffer.baseAddress,
            outputCapacity,
            &outputLength
          )
        }
      }
    }
    guard status == kCCSuccess, outputLength == kCCBlockSizeAES128 else {
      throw HybridProtocolError.invalidAdvertisement
    }
    return output
  }

  static func privateKey(
    randomSource: any HybridRandomSource,
    maximumAttempts: Int = 128
  ) throws -> P256.KeyAgreement.PrivateKey {
    guard maximumAttempts > 0 else {
      throw HybridProtocolError.invalidConfiguration
    }
    for _ in 0..<maximumAttempts {
      let candidate = try randomSource.randomBytes(count: 32)
      guard candidate.count == 32 else {
        throw HybridProtocolError.invalidRandomness
      }
      if let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: candidate) {
        return key
      }
    }
    throw HybridProtocolError.invalidRandomness
  }
}

extension SymmetricKey {
  fileprivate var data: Data {
    withUnsafeBytes { Data($0) }
  }
}

extension SharedSecret {
  var data: Data {
    withUnsafeBytes { Data($0) }
  }
}
