import Foundation
import Network

struct HTTPRequest: Sendable {
  let method: String
  let path: String
  let headers: [String: String]
  let body: Data
}

struct HTTPResponse: Sendable {
  let status: Int
  let reason: String
  let contentType: String
  let body: Data

  static func json<T: Encodable>(_ value: T) throws -> HTTPResponse {
    HTTPResponse(
      status: 200,
      reason: "OK",
      contentType: "application/json; charset=utf-8",
      body: try JSONEncoder.controlledRP.encode(value)
    )
  }

  static let badRequest = HTTPResponse(
    status: 400,
    reason: "Bad Request",
    contentType: "application/json; charset=utf-8",
    body: Data(#"{"error":"request_rejected"}"#.utf8)
  )

  static let notFound = HTTPResponse(
    status: 404,
    reason: "Not Found",
    contentType: "application/json; charset=utf-8",
    body: Data(#"{"error":"not_found"}"#.utf8)
  )
}

final class ControlledRPHTTPServer: @unchecked Sendable {
  private static let maximumRequestBytes = 256 << 10
  private let state: ControlledRPState
  private let expectedAuthority: String
  private let queue = DispatchQueue(label: "org.siriussecuritykey.controlled-rp")
  private var listener: NWListener?

  init(state: ControlledRPState, expectedAuthority: String) {
    self.state = state
    self.expectedAuthority = expectedAuthority.lowercased()
  }

  func run(port: UInt16) async throws {
    guard let networkPort = NWEndpoint.Port(rawValue: port) else {
      throw ControlledRPError.invalidArguments
    }
    let listener = try NWListener(using: .tcp, on: networkPort)
    self.listener = listener

    try await withCheckedThrowingContinuation { continuation in
      let gate = ListenerReadyGate(continuation: continuation)
      listener.stateUpdateHandler = { state in
        switch state {
        case .ready:
          gate.succeed()
        case .failed:
          gate.fail()
        default:
          break
        }
      }
      listener.newConnectionHandler = { [weak self] connection in
        self?.accept(connection)
      }
      listener.start(queue: queue)
    }

    print("controlled_rp_ready port=\(port)")
    while !Task.isCancelled {
      try await ContinuousClock().sleep(for: .seconds(3_600))
    }
  }

  private func accept(_ connection: NWConnection) {
    connection.start(queue: queue)
    receive(connection, accumulated: Data())
  }

  private func receive(_ connection: NWConnection, accumulated: Data) {
    connection.receive(
      minimumIncompleteLength: 1,
      maximumLength: 32 << 10
    ) { [weak self] content, _, isComplete, error in
      guard let self else {
        connection.cancel()
        return
      }
      var bytes = accumulated
      if let content {
        guard bytes.count <= Self.maximumRequestBytes - content.count else {
          self.send(.badRequest, on: connection)
          return
        }
        bytes.append(content)
      }
      if let request = try? self.parseCompleteRequest(bytes) {
        Task {
          let response = await self.route(request)
          self.send(response, on: connection)
        }
        return
      }
      if error != nil || isComplete || bytes.count >= Self.maximumRequestBytes {
        self.send(.badRequest, on: connection)
        return
      }
      self.receive(connection, accumulated: bytes)
    }
  }

  private func parseCompleteRequest(_ data: Data) throws -> HTTPRequest? {
    let delimiter = Data("\r\n\r\n".utf8)
    guard let headerRange = data.range(of: delimiter) else {
      return nil
    }
    guard headerRange.lowerBound <= 16 << 10,
      let headerText = String(
        data: data.subdata(in: 0..<headerRange.lowerBound),
        encoding: .utf8
      )
    else {
      throw ControlledRPError.invalidRequest
    }
    let lines = headerText.components(separatedBy: "\r\n")
    guard let requestLine = lines.first else {
      throw ControlledRPError.invalidRequest
    }
    let requestParts = requestLine.split(separator: " ")
    guard requestParts.count == 3, requestParts[2] == "HTTP/1.1",
      requestParts[0] == "GET" || requestParts[0] == "POST",
      requestParts[1].utf8.count <= 256
    else {
      throw ControlledRPError.invalidRequest
    }
    var headers: [String: String] = [:]
    for line in lines.dropFirst() {
      guard let colon = line.firstIndex(of: ":") else {
        throw ControlledRPError.invalidRequest
      }
      let name = line[..<colon].lowercased()
      let value = line[line.index(after: colon)...]
        .trimmingCharacters(in: .whitespaces)
      guard !name.isEmpty, value.utf8.count <= 4_096,
        headers.updateValue(value, forKey: name) == nil
      else {
        throw ControlledRPError.invalidRequest
      }
    }
    guard headers["host"]?.lowercased() == expectedAuthority,
      headers["transfer-encoding"] == nil
    else {
      throw ControlledRPError.invalidRequest
    }
    let contentLength: Int
    if let rawLength = headers["content-length"] {
      guard let parsed = Int(rawLength), parsed >= 0, parsed <= 128 << 10 else {
        throw ControlledRPError.invalidRequest
      }
      contentLength = parsed
    } else {
      contentLength = 0
    }
    let bodyStart = headerRange.upperBound
    guard data.count >= bodyStart + contentLength else {
      return nil
    }
    guard data.count == bodyStart + contentLength else {
      throw ControlledRPError.invalidRequest
    }
    return HTTPRequest(
      method: String(requestParts[0]),
      path: String(requestParts[1]),
      headers: headers,
      body: data.subdata(in: bodyStart..<data.count)
    )
  }

  private func route(_ request: HTTPRequest) async -> HTTPResponse {
    do {
      if request.method == "POST" {
        guard
          request.headers["content-type"]?.lowercased()
            .hasPrefix("application/json") == true
        else {
          return .badRequest
        }
      }
      switch (request.method, request.path) {
      case ("GET", "/"):
        return HTTPResponse(
          status: 200,
          reason: "OK",
          contentType: "text/html; charset=utf-8",
          body: Data(RegistrationPage.html.utf8)
        )
      case ("POST", "/register/options"):
        return try await .json(
          state.registrationOptions(
            try JSONDecoder().decode(RegistrationOptionsRequest.self, from: request.body)
          )
        )
      case ("POST", "/register/finish"):
        return try await .json(
          state.finishRegistration(
            try JSONDecoder().decode(RegistrationFinishRequest.self, from: request.body)
          )
        )
      case ("POST", "/assertion/options"):
        return try await .json(
          state.assertionOptions(
            try JSONDecoder().decode(AssertionOptionsRequest.self, from: request.body)
          )
        )
      case ("POST", "/assertion/finish"):
        return try await .json(
          state.finishAssertion(
            try JSONDecoder().decode(AssertionFinishRequest.self, from: request.body)
          )
        )
      default:
        return .notFound
      }
    } catch {
      return .badRequest
    }
  }

  private func send(_ response: HTTPResponse, on connection: NWConnection) {
    var bytes = Data(
      "HTTP/1.1 \(response.status) \(response.reason)\r\n"
        .appending("content-type: \(response.contentType)\r\n")
        .appending("content-length: \(response.body.count)\r\n")
        .appending("cache-control: no-store\r\n")
        .appending("x-content-type-options: nosniff\r\n")
        .appending(
          "content-security-policy: default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'\r\n"
        )
        .appending("connection: close\r\n\r\n")
        .utf8
    )
    bytes.append(response.body)
    connection.send(
      content: bytes,
      completion: .contentProcessed { _ in
        connection.cancel()
      })
  }
}

private final class ListenerReadyGate: @unchecked Sendable {
  private let lock = NSLock()
  private var continuation: CheckedContinuation<Void, any Error>?

  init(continuation: CheckedContinuation<Void, any Error>) {
    self.continuation = continuation
  }

  func succeed() {
    resolve(.success(()))
  }

  func fail() {
    resolve(.failure(ControlledRPError.transportFailure))
  }

  private func resolve(_ result: Result<Void, any Error>) {
    lock.lock()
    let pending = continuation
    continuation = nil
    lock.unlock()
    guard let pending else { return }
    switch result {
    case .success:
      pending.resume()
    case .failure(let error):
      pending.resume(throwing: error)
    }
  }
}
