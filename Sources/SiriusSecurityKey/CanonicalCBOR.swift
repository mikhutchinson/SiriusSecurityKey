import Foundation

/// A bounded subset of CBOR used by CTAP 2 and the FIDO Proximity Exchange
/// Protocol.
///
/// Tags, indefinite-length values, floating-point values, and integers outside
/// CTAP's 32-bit canonical range are intentionally not represented.
public indirect enum CBORValue: Sendable, Equatable {
  case unsigned(UInt32)
  case negative(Int64)
  case byteString(Data)
  case textString(String)
  case array([CBORValue])
  case map([CBORMapEntry])
  case boolean(Bool)
  case null

  /// Returns the value associated with an unsigned-integer map key.
  public func value(forUnsignedKey key: UInt32) -> CBORValue? {
    guard case .map(let entries) = self else {
      return nil
    }
    return entries.first { $0.key == .unsigned(key) }?.value
  }
}

/// A CBOR map entry. Encoders canonicalize entry order and reject duplicate
/// keys; decoders require the input to already be in canonical order.
public struct CBORMapEntry: Sendable, Equatable {
  public let key: CBORValue
  public let value: CBORValue

  public init(key: CBORValue, value: CBORValue) {
    self.key = key
    self.value = value
  }
}

/// Resource limits applied before allocating for attacker-controlled CBOR.
public struct CBORLimits: Sendable, Equatable {
  public let maximumMessageSize: Int
  public let maximumNestingDepth: Int
  public let maximumCollectionCount: Int
  public let maximumStringSize: Int
  public let maximumTotalItems: Int

  public init(
    maximumMessageSize: Int = 1024,
    maximumNestingDepth: Int = 4,
    maximumCollectionCount: Int = 128,
    maximumStringSize: Int = 1024,
    maximumTotalItems: Int = 256
  ) {
    self.maximumMessageSize = maximumMessageSize
    self.maximumNestingDepth = maximumNestingDepth
    self.maximumCollectionCount = maximumCollectionCount
    self.maximumStringSize = maximumStringSize
    self.maximumTotalItems = maximumTotalItems
  }

  fileprivate var isValid: Bool {
    maximumMessageSize > 0 && maximumNestingDepth > 0
      && maximumCollectionCount > 0 && maximumStringSize >= 0
      && maximumTotalItems > 0
  }
}

public enum CBORError: Error, Sendable, Equatable {
  case invalidLimits
  case messageTooLarge
  case truncated
  case trailingData
  case nonCanonicalInteger
  case nonCanonicalLength
  case nonCanonicalMapOrder
  case duplicateMapKey
  case indefiniteLength
  case forbiddenTag
  case unsupportedSimpleValue
  case unsupportedFloatingPoint
  case integerOutOfRange
  case invalidNegativeInteger
  case invalidUTF8
  case invalidMapKey
  case nestingTooDeep
  case collectionTooLarge
  case stringTooLarge
  case tooManyItems
}

/// CTAP 2 canonical CBOR encoding and strict decoding.
public enum CanonicalCBOR {
  /// Encodes a value using CTAP 2 canonical ordering and shortest forms.
  public static func encode(
    _ value: CBORValue,
    limits: CBORLimits = CBORLimits()
  ) throws -> Data {
    guard limits.isValid else {
      throw CBORError.invalidLimits
    }

    var encoder = Encoder(limits: limits)
    try encoder.encode(value, containerDepth: 0)
    return encoder.output
  }

  /// Decodes exactly one canonical, bounded value and rejects trailing bytes.
  public static func decode(
    _ data: Data,
    limits: CBORLimits = CBORLimits()
  ) throws -> CBORValue {
    guard limits.isValid else {
      throw CBORError.invalidLimits
    }
    guard data.count <= limits.maximumMessageSize else {
      throw CBORError.messageTooLarge
    }

    var normalized = Data()
    normalized.append(data)
    var decoder = Decoder(data: normalized, limits: limits)
    let value = try decoder.decode(containerDepth: 0)
    guard decoder.isAtEnd else {
      throw CBORError.trailingData
    }
    return value
  }
}

extension CanonicalCBOR {
  fileprivate struct Encoder {
    let limits: CBORLimits
    var output = Data()
    var totalItems = 0

    mutating func encode(_ value: CBORValue, containerDepth: Int) throws {
      totalItems += 1
      guard totalItems <= limits.maximumTotalItems else {
        throw CBORError.tooManyItems
      }

      switch value {
      case .unsigned(let integer):
        try appendArgument(majorType: 0, value: integer)

      case .negative(let integer):
        guard integer < 0 else {
          throw CBORError.invalidNegativeInteger
        }
        let encoded = UInt64(-(integer + 1))
        guard encoded <= UInt32.max else {
          throw CBORError.integerOutOfRange
        }
        try appendArgument(majorType: 1, value: UInt32(encoded))

      case .byteString(let bytes):
        guard bytes.count <= limits.maximumStringSize else {
          throw CBORError.stringTooLarge
        }
        try appendLength(majorType: 2, count: bytes.count)
        try append(bytes)

      case .textString(let string):
        let bytes = Data(string.utf8)
        guard bytes.count <= limits.maximumStringSize else {
          throw CBORError.stringTooLarge
        }
        try appendLength(majorType: 3, count: bytes.count)
        try append(bytes)

      case .array(let values):
        try enterContainer(depth: containerDepth, count: values.count)
        try appendLength(majorType: 4, count: values.count)
        for element in values {
          try encode(element, containerDepth: containerDepth + 1)
        }

      case .map(let entries):
        try enterContainer(depth: containerDepth, count: entries.count)
        var ordered: [(Data, CBORValue)] = []
        ordered.reserveCapacity(entries.count)
        for entry in entries {
          let encodedKey = try encodeMapKey(entry.key)
          ordered.append((encodedKey, entry.value))
        }
        ordered.sort { canonicalKeyPrecedes($0.0, $1.0) }
        if ordered.count > 1 {
          for index in 1..<ordered.count where ordered[index - 1].0 == ordered[index].0 {
            throw CBORError.duplicateMapKey
          }
        }

        try appendLength(majorType: 5, count: entries.count)
        for (key, mapValue) in ordered {
          totalItems += 1
          guard totalItems <= limits.maximumTotalItems else {
            throw CBORError.tooManyItems
          }
          try append(key)
          try encode(mapValue, containerDepth: containerDepth + 1)
        }

      case .boolean(let boolean):
        try append(Data([boolean ? 0xf5 : 0xf4]))

      case .null:
        try append(Data([0xf6]))
      }
    }

    private mutating func enterContainer(depth: Int, count: Int) throws {
      guard depth + 1 <= limits.maximumNestingDepth else {
        throw CBORError.nestingTooDeep
      }
      guard count <= limits.maximumCollectionCount else {
        throw CBORError.collectionTooLarge
      }
    }

    private func encodeMapKey(_ key: CBORValue) throws -> Data {
      var bytes = Data()
      switch key {
      case .unsigned(let value):
        appendArgument(majorType: 0, value: value, to: &bytes)
      case .negative(let value):
        guard value < 0 else {
          throw CBORError.invalidNegativeInteger
        }
        let encoded = UInt64(-(value + 1))
        guard encoded <= UInt32.max else {
          throw CBORError.integerOutOfRange
        }
        appendArgument(majorType: 1, value: UInt32(encoded), to: &bytes)
      case .byteString(let value):
        guard value.count <= limits.maximumStringSize else {
          throw CBORError.stringTooLarge
        }
        try appendLength(majorType: 2, count: value.count, to: &bytes)
        bytes.append(value)
      case .textString(let value):
        let valueBytes = Data(value.utf8)
        guard valueBytes.count <= limits.maximumStringSize else {
          throw CBORError.stringTooLarge
        }
        try appendLength(majorType: 3, count: valueBytes.count, to: &bytes)
        bytes.append(valueBytes)
      case .boolean(let value):
        bytes.append(value ? 0xf5 : 0xf4)
      case .null:
        bytes.append(0xf6)
      case .array, .map:
        throw CBORError.invalidMapKey
      }
      return bytes
    }

    private mutating func appendLength(majorType: UInt8, count: Int) throws {
      guard count >= 0, let value = UInt32(exactly: count) else {
        throw CBORError.integerOutOfRange
      }
      try appendArgument(majorType: majorType, value: value)
    }

    private func appendLength(majorType: UInt8, count: Int, to data: inout Data) throws {
      guard count >= 0, let value = UInt32(exactly: count) else {
        throw CBORError.integerOutOfRange
      }
      appendArgument(majorType: majorType, value: value, to: &data)
    }

    private mutating func appendArgument(majorType: UInt8, value: UInt32) throws {
      var bytes = Data()
      appendArgument(majorType: majorType, value: value, to: &bytes)
      try append(bytes)
    }

    private func appendArgument(majorType: UInt8, value: UInt32, to data: inout Data) {
      let prefix = majorType << 5
      switch value {
      case 0...23:
        data.append(prefix | UInt8(value))
      case 24...UInt32(UInt8.max):
        data.append(prefix | 24)
        data.append(UInt8(value))
      case 256...UInt32(UInt16.max):
        data.append(prefix | 25)
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
      default:
        data.append(prefix | 26)
        data.append(UInt8((value >> 24) & 0xff))
        data.append(UInt8((value >> 16) & 0xff))
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
      }
    }

    private mutating func append(_ data: Data) throws {
      guard output.count <= limits.maximumMessageSize - data.count else {
        throw CBORError.messageTooLarge
      }
      output.append(data)
    }
  }

  fileprivate struct Decoder {
    let data: Data
    let limits: CBORLimits
    var index = 0
    var totalItems = 0

    var isAtEnd: Bool { index == data.count }

    mutating func decode(containerDepth: Int) throws -> CBORValue {
      totalItems += 1
      guard totalItems <= limits.maximumTotalItems else {
        throw CBORError.tooManyItems
      }

      let initial = try readByte()
      let majorType = initial >> 5
      let additional = initial & 0x1f

      switch majorType {
      case 0:
        return .unsigned(try readArgument(additional, length: false))

      case 1:
        let encoded = try readArgument(additional, length: false)
        return .negative(-1 - Int64(encoded))

      case 2:
        let count = try readCount(additional)
        guard count <= limits.maximumStringSize else {
          throw CBORError.stringTooLarge
        }
        return .byteString(try readData(count: count))

      case 3:
        let count = try readCount(additional)
        guard count <= limits.maximumStringSize else {
          throw CBORError.stringTooLarge
        }
        let bytes = try readData(count: count)
        guard let string = String(data: bytes, encoding: .utf8) else {
          throw CBORError.invalidUTF8
        }
        return .textString(string)

      case 4:
        let count = try readContainerCount(additional, depth: containerDepth)
        var values: [CBORValue] = []
        values.reserveCapacity(count)
        for _ in 0..<count {
          values.append(try decode(containerDepth: containerDepth + 1))
        }
        return .array(values)

      case 5:
        let count = try readContainerCount(additional, depth: containerDepth)
        var entries: [CBORMapEntry] = []
        entries.reserveCapacity(count)
        var previousKey: Data?
        for _ in 0..<count {
          let keyStart = index
          let key = try decode(containerDepth: containerDepth + 1)
          guard key.isPermittedMapKey else {
            throw CBORError.invalidMapKey
          }
          let keyBytes = data.subdata(in: keyStart..<index)
          if let previousKey {
            if previousKey == keyBytes {
              throw CBORError.duplicateMapKey
            }
            guard canonicalKeyPrecedes(previousKey, keyBytes) else {
              throw CBORError.nonCanonicalMapOrder
            }
          }
          previousKey = keyBytes
          let value = try decode(containerDepth: containerDepth + 1)
          entries.append(CBORMapEntry(key: key, value: value))
        }
        return .map(entries)

      case 6:
        throw CBORError.forbiddenTag

      case 7:
        switch additional {
        case 20:
          return .boolean(false)
        case 21:
          return .boolean(true)
        case 22:
          return .null
        case 25, 26, 27:
          throw CBORError.unsupportedFloatingPoint
        case 31:
          throw CBORError.indefiniteLength
        default:
          throw CBORError.unsupportedSimpleValue
        }

      default:
        throw CBORError.unsupportedSimpleValue
      }
    }

    private mutating func readContainerCount(_ additional: UInt8, depth: Int) throws -> Int {
      guard depth + 1 <= limits.maximumNestingDepth else {
        throw CBORError.nestingTooDeep
      }
      let count = try readCount(additional)
      guard count <= limits.maximumCollectionCount else {
        throw CBORError.collectionTooLarge
      }
      return count
    }

    private mutating func readCount(_ additional: UInt8) throws -> Int {
      let value = try readArgument(additional, length: true)
      guard let count = Int(exactly: value) else {
        throw CBORError.integerOutOfRange
      }
      return count
    }

    private mutating func readArgument(_ additional: UInt8, length: Bool) throws -> UInt32 {
      switch additional {
      case 0...23:
        return UInt32(additional)
      case 24:
        let value = UInt32(try readByte())
        guard value >= 24 else {
          throw length ? CBORError.nonCanonicalLength : CBORError.nonCanonicalInteger
        }
        return value
      case 25:
        let value = UInt32(try readByte()) << 8 | UInt32(try readByte())
        guard value > UInt8.max else {
          throw length ? CBORError.nonCanonicalLength : CBORError.nonCanonicalInteger
        }
        return value
      case 26:
        let value =
          UInt32(try readByte()) << 24 | UInt32(try readByte()) << 16
          | UInt32(try readByte()) << 8 | UInt32(try readByte())
        guard value > UInt16.max else {
          throw length ? CBORError.nonCanonicalLength : CBORError.nonCanonicalInteger
        }
        return value
      case 27:
        throw CBORError.integerOutOfRange
      case 31:
        throw CBORError.indefiniteLength
      default:
        throw CBORError.unsupportedSimpleValue
      }
    }

    private mutating func readByte() throws -> UInt8 {
      guard index < data.count else {
        throw CBORError.truncated
      }
      let byte = data[index]
      index += 1
      return byte
    }

    private mutating func readData(count: Int) throws -> Data {
      guard count >= 0, index <= data.count - count else {
        throw CBORError.truncated
      }
      let result = data.subdata(in: index..<(index + count))
      index += count
      return result
    }
  }

  fileprivate static func canonicalKeyPrecedes(_ lhs: Data, _ rhs: Data) -> Bool {
    guard let lhsFirst = lhs.first, let rhsFirst = rhs.first else {
      return lhs.count < rhs.count
    }
    let lhsMajor = lhsFirst >> 5
    let rhsMajor = rhsFirst >> 5
    if lhsMajor != rhsMajor {
      return lhsMajor < rhsMajor
    }
    if lhs.count != rhs.count {
      return lhs.count < rhs.count
    }
    return lhs.lexicographicallyPrecedes(rhs)
  }
}

extension CBORValue {
  fileprivate var isPermittedMapKey: Bool {
    switch self {
    case .unsigned, .negative, .byteString, .textString, .boolean, .null:
      return true
    case .array, .map:
      return false
    }
  }
}
