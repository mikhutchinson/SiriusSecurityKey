import Foundation
import Testing

@testable import SiriusSecurityKey

@Test("Canonical CBOR sorts keys and uses shortest encodings")
func canonicalCBORSortsAndMinimizes() throws {
  let value = CBORValue.map([
    CBORMapEntry(key: .unsigned(24), value: .boolean(false)),
    CBORMapEntry(key: .unsigned(1), value: .boolean(true)),
  ])
  let encoded = try CanonicalCBOR.encode(value)

  #expect(encoded == Data(testHex: "a201f51818f4"))
  #expect(
    try CanonicalCBOR.decode(encoded)
      == .map([
        CBORMapEntry(key: .unsigned(1), value: .boolean(true)),
        CBORMapEntry(key: .unsigned(24), value: .boolean(false)),
      ])
  )
  #expect(try CanonicalCBOR.encode(.map([])) == Data([0xa0]))
  #expect(try CanonicalCBOR.decode(Data([0xa0])) == .map([]))
}

@Test(
  "Canonical CBOR rejects malformed encodings",
  arguments: [
    (Data(testHex: "1817"), CBORError.nonCanonicalInteger),
    (Data(testHex: "18"), CBORError.truncated),
    (Data(testHex: "a201f401f5"), CBORError.duplicateMapKey),
    (Data(testHex: "a202f401f5"), CBORError.nonCanonicalMapOrder),
    (Data(testHex: "c000"), CBORError.forbiddenTag),
    (Data(testHex: "9fff"), CBORError.indefiniteLength),
    (Data(testHex: "61ff"), CBORError.invalidUTF8),
    (Data(testHex: "1b0000000100000000"), CBORError.integerOutOfRange),
    (Data(testHex: "0000"), CBORError.trailingData),
  ]
)
func canonicalCBORRejectsMalformed(input: Data, expected: CBORError) {
  #expect(throws: expected) {
    try CanonicalCBOR.decode(input)
  }
}

@Test("Canonical CBOR deterministic mutation campaign is round-trip exact")
func canonicalCBORMutationCampaign() throws {
  var generator = XorShift64(state: 0x5353_4b43_424f_5231)
  for _ in 0..<10_000 {
    let count = Int(generator.next() % 129)
    var bytes = Data()
    bytes.reserveCapacity(count)
    for _ in 0..<count {
      bytes.append(UInt8(truncatingIfNeeded: generator.next()))
    }
    if let decoded = try? CanonicalCBOR.decode(
      bytes,
      limits: CBORLimits(
        maximumMessageSize: 128,
        maximumNestingDepth: 4,
        maximumCollectionCount: 32,
        maximumStringSize: 128,
        maximumTotalItems: 64
      )
    ) {
      #expect(
        try CanonicalCBOR.encode(
          decoded,
          limits: CBORLimits(
            maximumMessageSize: 128,
            maximumNestingDepth: 4,
            maximumCollectionCount: 32,
            maximumStringSize: 128,
            maximumTotalItems: 64
          )
        ) == bytes
      )
    }
  }
}

private struct XorShift64 {
  var state: UInt64

  mutating func next() -> UInt64 {
    state ^= state << 13
    state ^= state >> 7
    state ^= state << 17
    return state
  }
}

@Test("Canonical CBOR enforces depth, item, string, and message bounds")
func canonicalCBOREnforcesBounds() throws {
  let depthFour = Data(testHex: "8181818100")
  #expect(
    try CanonicalCBOR.decode(depthFour)
      == .array([.array([.array([.array([.unsigned(0)])])])])
  )

  #expect(throws: CBORError.nestingTooDeep) {
    try CanonicalCBOR.decode(Data(testHex: "818181818100"))
  }
  #expect(throws: CBORError.messageTooLarge) {
    try CanonicalCBOR.decode(Data(repeating: 0, count: 1025))
  }
  #expect(throws: CBORError.stringTooLarge) {
    try CanonicalCBOR.encode(
      .byteString(Data(repeating: 0, count: 17)),
      limits: CBORLimits(maximumStringSize: 16)
    )
  }
  #expect(throws: CBORError.tooManyItems) {
    try CanonicalCBOR.decode(
      Data(testHex: "83010203"),
      limits: CBORLimits(maximumTotalItems: 3)
    )
  }
}

@Test("Canonical CBOR rejects duplicate output keys and invalid negatives")
func canonicalCBOREncoderRejectsInvalidValues() {
  #expect(throws: CBORError.duplicateMapKey) {
    try CanonicalCBOR.encode(
      .map([
        CBORMapEntry(key: .unsigned(1), value: .null),
        CBORMapEntry(key: .unsigned(1), value: .boolean(true)),
      ])
    )
  }
  #expect(throws: CBORError.invalidNegativeInteger) {
    try CanonicalCBOR.encode(.negative(0))
  }
  #expect(throws: CBORError.integerOutOfRange) {
    try CanonicalCBOR.encode(.negative(-4_294_967_297))
  }
}
