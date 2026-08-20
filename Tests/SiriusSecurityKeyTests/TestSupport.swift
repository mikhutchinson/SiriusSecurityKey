import Foundation

@testable import SiriusSecurityKey

final class SequenceRandomSource: HybridRandomSource, @unchecked Sendable {
  private let lock = NSLock()
  private var chunks: [Data]

  init(_ chunks: [Data]) {
    self.chunks = chunks
  }

  func randomBytes(count: Int) throws -> Data {
    lock.lock()
    defer { lock.unlock() }
    guard !chunks.isEmpty else {
      throw HybridProtocolError.invalidRandomness
    }
    let chunk = chunks.removeFirst()
    guard chunk.count == count else {
      throw HybridProtocolError.invalidRandomness
    }
    return chunk
  }
}

extension Data {
  init(testHex string: String) {
    var result = Data()
    var index = string.startIndex
    while index < string.endIndex {
      let next = string.index(index, offsetBy: 2)
      if let byte = UInt8(string[index..<next], radix: 16) {
        result.append(byte)
      }
      index = next
    }
    self = result
  }

  var testHex: String {
    map { String(format: "%02x", $0) }.joined()
  }
}

enum TestVectors {
  static func value(_ key: String) throws -> String {
    guard
      let url = Bundle.module.url(
        forResource: "hybrid-vectors",
        withExtension: "json"
      )
    else {
      throw HybridProtocolError.invalidConfiguration
    }
    let object = try JSONSerialization.jsonObject(with: Data(contentsOf: url))
    guard let dictionary = object as? [String: String], let value = dictionary[key] else {
      throw HybridProtocolError.invalidConfiguration
    }
    return value
  }
}
