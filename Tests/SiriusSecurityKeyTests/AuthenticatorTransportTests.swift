import Foundation
import Testing

@testable import SiriusSecurityKey

@Test("CTAP request framing preserves command and payload bytes")
func requestFramingRoundTrip() throws {
  let encoded = Data([0x02, 0xa1, 0x01, 0x02])
  let request = try CTAPRequest(encoded: encoded)

  #expect(request.command == 0x02)
  #expect(request.payload == Data([0xa1, 0x01, 0x02]))
  #expect(request.encoded == encoded)
}

@Test("CTAP response framing preserves status and payload bytes")
func responseFramingRoundTrip() throws {
  let encoded = Data([0x00, 0xa1, 0x01, 0x02])
  let response = try CTAPResponse(encoded: encoded)

  #expect(response.status == 0x00)
  #expect(response.payload == Data([0xa1, 0x01, 0x02]))
  #expect(response.encoded == encoded)
}

@Test("Empty CTAP frames fail closed")
func emptyFramesFailClosed() {
  #expect(throws: CTAPFramingError.missingCommand) {
    try CTAPRequest(encoded: Data())
  }
  #expect(throws: CTAPFramingError.missingStatus) {
    try CTAPResponse(encoded: Data())
  }
}
