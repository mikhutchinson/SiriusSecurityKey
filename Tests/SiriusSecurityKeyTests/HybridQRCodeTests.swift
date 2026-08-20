import CryptoKit
import Foundation
import Testing

@testable import SiriusSecurityKey

@Test("PXP digit encoding matches Chromium's retained protocol vector")
func digitEncodingChromiumVector() throws {
  let bytes = Data([0x61, 0x62, 0xff])
  #expect(DigitEncoding.encode(bytes) == "16736865")
  #expect(try DigitEncoding.decode("16736865") == bytes)
}

@Test("PXP digit decoding rejects impossible inputs")
func digitEncodingRejectsInvalidInputs() {
  for invalid in [
    "a",
    "١٢٣",
    "999",
    "0",
    "0000",
    String(repeating: "9", count: 17),
    String(repeating: "0", count: DigitEncoding.maximumDigitCount + 1),
  ] {
    #expect(throws: HybridProtocolError.invalidQRPayload) {
      try DigitEncoding.decode(invalid)
    }
  }
}

@Test("Generated FIDO URI is canonical and retains exact bootstrap fields")
func generatedQRCodeRoundTrips() throws {
  let identity = Data(repeating: 1, count: 32)
  let secret = Data(repeating: 0xa5, count: 16)
  let random = SequenceRandomSource([identity, secret])
  let bootstrap = try HybridQRCode.generate(
    configuration: HybridQRConfiguration(
      timestamp: 1_700_000_000,
      supportsLinking: false,
      requestType: .makeCredential,
      transferChannels: [.webSocket]
    ),
    randomSource: random
  )
  let decoded = try HybridQRCode.parse(bootstrap.uri)
  let key = try P256.KeyAgreement.PrivateKey(rawRepresentation: identity)

  #expect(bootstrap.uri.hasPrefix("FIDO:/"))
  #expect(decoded.compressedPublicKey == key.publicKey.compressedRepresentation)
  #expect(decoded.qrSecret == secret)
  #expect(decoded.assignedTunnelServerDomainCount == 2)
  #expect(decoded.timestamp == 1_700_000_000)
  #expect(decoded.supportsLinking == false)
  #expect(decoded.requestType == .makeCredential)
  #expect(decoded.transferChannels == [.webSocket])
  #expect(bootstrap.uri == (try TestVectors.value("qr_uri")))
}

@Test("QR parser accepts the pinned Chromium public-key vector")
func qrParserAcceptsChromiumPointVector() throws {
  let point = Data(testHex: "03364c15eec34331d2865757421d497e569e1eba6cff9a69d32e90f19e7f6fd15e")
  let cbor = try CanonicalCBOR.encode(
    .map([
      CBORMapEntry(key: .unsigned(0), value: .byteString(point)),
      CBORMapEntry(key: .unsigned(1), value: .byteString(Data(repeating: 0, count: 16))),
    ])
  )
  let decoded = try HybridQRCode.parse("FIDO:/" + DigitEncoding.encode(cbor))

  #expect(decoded.compressedPublicKey == point)
  #expect(decoded.requestType == .getAssertion)
  #expect(decoded.assignedTunnelServerDomainCount == 0)
}

@Test("QR parser rejects noncanonical scheme, points, and field types")
func qrParserRejectsMalformedValues() throws {
  let validPoint = try P256.KeyAgreement.PrivateKey(
    rawRepresentation: Data(repeating: 1, count: 32)
  ).publicKey.compressedRepresentation
  let invalidPoint = Data(repeating: 0, count: 33)
  let secret = Data(repeating: 0, count: 16)

  let invalidInputs = try [
    "fido:/000",
    "FIDO://000",
    "FIDO:/"
      + DigitEncoding.encode(
        CanonicalCBOR.encode(
          .map([
            CBORMapEntry(key: .unsigned(0), value: .byteString(invalidPoint)),
            CBORMapEntry(key: .unsigned(1), value: .byteString(secret)),
          ])
        )
      ),
    "FIDO:/"
      + DigitEncoding.encode(
        CanonicalCBOR.encode(
          .map([
            CBORMapEntry(key: .unsigned(0), value: .byteString(validPoint)),
            CBORMapEntry(key: .unsigned(1), value: .unsigned(1)),
          ])
        )
      ),
  ]
  for input in invalidInputs {
    #expect(throws: HybridProtocolError.invalidQRPayload) {
      try HybridQRCode.parse(input)
    }
  }
}

@Test("QR generation rejects duplicate or empty transport sets")
func qrGenerationRejectsInvalidChannels() {
  let random = SequenceRandomSource([])
  for channels: [HybridTransferChannel] in [[], [.webSocket, .webSocket]] {
    #expect(throws: HybridProtocolError.invalidConfiguration) {
      try HybridQRCode.generate(
        configuration: HybridQRConfiguration(
          requestType: .getAssertion,
          transferChannels: channels
        ),
        randomSource: random
      )
    }
  }
}

@Test("QR parser rejects every truncation of the retained canonical vector")
func qrParserRejectsTruncations() throws {
  let uri = try TestVectors.value("qr_uri")
  let digits = String(uri.dropFirst(6))
  for length in 0..<digits.count {
    let end = digits.index(digits.startIndex, offsetBy: length)
    let truncated = "FIDO:/" + digits[..<end]
    #expect(throws: (any Error).self) {
      try HybridQRCode.parse(truncated)
    }
  }
}
