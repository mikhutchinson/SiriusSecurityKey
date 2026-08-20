import Foundation
import Testing

@testable import SiriusSecurityKey

@Test("authenticatorGetInfo validates required fields and preserves unknown fields")
func authenticatorInfoParsesCanonicalResponse() throws {
  let payload = try makeGetInfoPayload()
  let response = CTAPResponse(status: 0, payload: payload)
  let info = try AuthenticatorInfoParser.parse(response: response)

  #expect(info.versions == ["FIDO_2_0", "FIDO_2_1"])
  #expect(info.extensions == ["prf"])
  #expect(info.aaguid == Data(repeating: 0, count: 16))
  #expect(info.options == ["rk": true, "uv": true])
  #expect(info.maximumMessageSize == 1200)
  #expect(info.pinUVAuthProtocols == [2, 1])
  #expect(info.maximumCredentialCountInList == 64)
  #expect(info.maximumCredentialIDLength == 1024)
  #expect(info.transports == ["hybrid", "internal"])
  #expect(info.rawResponse.value(forUnsignedKey: 99) == .textString("future"))
}

@Test("authenticatorGetInfo retains CTAP status and rejects malformed required fields")
func authenticatorInfoRejectsInvalidResponses() throws {
  #expect(throws: HybridProtocolError.ctapStatus(0x2e)) {
    try AuthenticatorInfoParser.parse(
      response: CTAPResponse(status: 0x2e, payload: Data())
    )
  }
  let missingAAGUID = try CanonicalCBOR.encode(
    .map([
      CBORMapEntry(
        key: .unsigned(1),
        value: .array([.textString("FIDO_2_0")])
      )
    ])
  )
  #expect(throws: HybridProtocolError.invalidAuthenticatorInfo) {
    try AuthenticatorInfoParser.parse(payload: missingAAGUID)
  }
}

func makeGetInfoPayload() throws -> Data {
  try CanonicalCBOR.encode(
    .map([
      CBORMapEntry(
        key: .unsigned(1),
        value: .array([.textString("FIDO_2_0"), .textString("FIDO_2_1")])
      ),
      CBORMapEntry(
        key: .unsigned(2),
        value: .array([.textString("prf")])
      ),
      CBORMapEntry(
        key: .unsigned(3),
        value: .byteString(Data(repeating: 0, count: 16))
      ),
      CBORMapEntry(
        key: .unsigned(4),
        value: .map([
          CBORMapEntry(key: .textString("rk"), value: .boolean(true)),
          CBORMapEntry(key: .textString("uv"), value: .boolean(true)),
        ])
      ),
      CBORMapEntry(key: .unsigned(5), value: .unsigned(1200)),
      CBORMapEntry(
        key: .unsigned(6),
        value: .array([.unsigned(2), .unsigned(1)])
      ),
      CBORMapEntry(key: .unsigned(7), value: .unsigned(64)),
      CBORMapEntry(key: .unsigned(8), value: .unsigned(1024)),
      CBORMapEntry(
        key: .unsigned(9),
        value: .array([.textString("hybrid"), .textString("internal")])
      ),
      CBORMapEntry(key: .unsigned(99), value: .textString("future")),
    ])
  )
}
