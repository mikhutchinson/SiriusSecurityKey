import AppKit
import CoreImage
import Foundation
import SiriusSecurityKey

struct TerminalIntentAuthorizer: WebAuthnUserIntentAuthorizer {
  func authorize(_ request: WebAuthnUserIntentRequest) async throws {
    print(
      "intent_required origin=\(request.origin.serialized) rp=\(request.relyingPartyID) discoverable=\(request.isDiscoverable) uv=\(request.userVerification.rawValue)"
    )
    print("Type YES to authorize this immutable ceremony:")
    guard readLine() == "YES" else {
      throw WebAuthnError.userIntentDenied
    }
  }
}

struct TerminalAccountSelector: WebAuthnAccountSelector {
  func selectAccount(from candidates: [WebAuthnAccountCandidate]) async throws -> Int {
    print("account_selection_required count=\(candidates.count)")
    print("Enter the zero-based account index shown on your trusted UI:")
    guard let line = readLine(), let index = Int(line), candidates.indices.contains(index)
    else {
      throw WebAuthnError.invalidAccountSelection
    }
    return index
  }
}

enum QRCodePresenter {
  static func present(_ value: String) async throws -> URL {
    guard let filter = CIFilter(name: "CIQRCodeGenerator") else {
      throw ControlledRPError.transportFailure
    }
    filter.setValue(Data(value.utf8), forKey: "inputMessage")
    filter.setValue("L", forKey: "inputCorrectionLevel")
    guard
      let image = filter.outputImage?.transformed(
        by: CGAffineTransform(scaleX: 8, y: 8)
      )
    else {
      throw ControlledRPError.transportFailure
    }
    let context = CIContext(options: [.useSoftwareRenderer: false])
    guard let cgImage = context.createCGImage(image, from: image.extent) else {
      throw ControlledRPError.transportFailure
    }
    let representation = NSBitmapImageRep(cgImage: cgImage)
    guard let png = representation.representation(using: .png, properties: [:]) else {
      throw ControlledRPError.transportFailure
    }
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
      "SiriusSecurityKey-ControlledRP-\(UUID().uuidString)",
      isDirectory: true
    )
    try FileManager.default.createDirectory(
      at: directory,
      withIntermediateDirectories: false
    )
    let file = directory.appendingPathComponent("cross-device-qr.png")
    try png.write(to: file, options: [.atomic])
    let opened = await MainActor.run {
      NSWorkspace.shared.open(file)
    }
    guard opened else {
      try? FileManager.default.removeItem(at: directory)
      throw ControlledRPError.transportFailure
    }
    return directory
  }
}

struct ControlledRPAPI: Sendable {
  let server: URL

  func requestAssertionOptions(
    mode: String,
    deviceLabel: String
  ) async throws -> AssertionOptionsResponse {
    try await post(
      path: "assertion/options",
      request: AssertionOptionsRequest(mode: mode, deviceLabel: deviceLabel),
      response: AssertionOptionsResponse.self
    )
  }

  func verifyAssertion(
    ceremonyID: String,
    assertion: WebAuthnAssertion
  ) async throws -> AssertionReceipt {
    let submission = assertion.submission
    return try await post(
      path: "assertion/finish",
      request: AssertionFinishRequest(
        ceremonyID: ceremonyID,
        credentialID: Base64URL.encode(submission.credentialID),
        clientDataJSON: Base64URL.encode(submission.clientDataJSON),
        authenticatorData: Base64URL.encode(submission.authenticatorData),
        signature: Base64URL.encode(submission.signature),
        userHandle: submission.userHandle.map(Base64URL.encode)
      ),
      response: AssertionReceipt.self
    )
  }

  private func post<Request: Encodable, Response: Decodable>(
    path: String,
    request: Request,
    response: Response.Type
  ) async throws -> Response {
    guard let url = URL(string: path, relativeTo: server)?.absoluteURL,
      url.scheme == "https" || (url.scheme == "http" && url.host == "localhost")
    else {
      throw ControlledRPError.invalidArguments
    }
    var urlRequest = URLRequest(url: url)
    urlRequest.httpMethod = "POST"
    urlRequest.setValue("application/json", forHTTPHeaderField: "content-type")
    urlRequest.httpBody = try JSONEncoder.controlledRP.encode(request)
    urlRequest.timeoutInterval = 30
    let configuration = URLSessionConfiguration.ephemeral
    configuration.waitsForConnectivity = false
    let session = URLSession(configuration: configuration)
    defer { session.invalidateAndCancel() }
    let (data, rawResponse) = try await session.data(for: urlRequest)
    guard let httpResponse = rawResponse as? HTTPURLResponse,
      httpResponse.statusCode == 200,
      data.count <= 128 << 10
    else {
      throw ControlledRPError.serverVerificationFailed
    }
    return try JSONDecoder().decode(response, from: data)
  }
}

enum AssertionRunner {
  static func run(
    server: URL,
    mode: String,
    deviceLabel: String,
    wireProfile: HybridWireProfile
  ) async throws {
    let api = ControlledRPAPI(server: server)
    let options = try await api.requestAssertionOptions(
      mode: mode,
      deviceLabel: deviceLabel
    )
    let origin = try WebAuthnOrigin(options.origin)
    let challenge = try Base64URL.decode(options.challenge, maximumBytes: 1_024)
    let descriptors = try options.allowCredentials.map { encoded in
      try WebAuthnCredentialDescriptor(
        id: Base64URL.decode(encoded, maximumBytes: 1_024),
        transports: [.hybrid]
      )
    }
    let ceremony = try await ValidatedWebAuthnAssertionCeremony.authorize(
      WebAuthnAssertionRequest(
        origin: origin,
        relyingPartyID: options.relyingPartyID,
        challenge: challenge,
        allowCredentials: descriptors,
        userVerification: .required
      ),
      using: TerminalIntentAuthorizer()
    )
    let session = try HybridSession(
      qrConfiguration: HybridQRConfiguration(requestType: .getAssertion),
      wireProfile: wireProfile
    )
    let temporaryQRDirectory = try await QRCodePresenter.present(session.qrURI)
    defer {
      try? FileManager.default.removeItem(at: temporaryQRDirectory)
    }
    print("qr_presented profile=\(wireProfile.rawValue) mode=\(mode)")
    let assertion = try await session.getAssertion(
      ceremony: ceremony,
      scanner: CoreBluetoothHybridScanner(),
      accountSelector: mode == "discoverable" ? TerminalAccountSelector() : nil,
      proximityTimeout: .seconds(120),
      accountSelectionTimeout: .seconds(120)
    )
    print("hybrid_assertion_validated")
    let receipt = try await api.verifyAssertion(
      ceremonyID: options.ceremonyID,
      assertion: assertion
    )
    guard receipt.verified, receipt.mode == mode,
      receipt.declaredDeviceLabel == deviceLabel
    else {
      throw ControlledRPError.serverVerificationFailed
    }
    print(
      "server_verification_complete receipt=\(receipt.receiptID) mode=\(receipt.mode) counter_advanced=\(receipt.counterAdvanced)"
    )
  }
}
