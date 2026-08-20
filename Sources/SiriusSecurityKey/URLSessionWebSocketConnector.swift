// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license retained in
// THIRD_PARTY_NOTICES.md.

import Foundation

/// URLSession-backed PXP WebSocket connector with strict binary framing,
/// subprotocol verification, downgrade-resistant redirects, and bounded
/// incoming messages.
public struct URLSessionHybridWebSocketConnector: HybridWebSocketConnector {
  /// Creates an ephemeral-session connector.
  public init() {}

  /// Opens and validates a binary WebSocket connection.
  public func connect(
    to url: URL,
    subprotocol: String,
    maximumMessageSize: Int
  ) async throws -> any HybridBinaryChannel {
    guard url.scheme?.lowercased() == "wss", url.host != nil,
      url.user == nil, url.password == nil,
      !subprotocol.isEmpty, maximumMessageSize > 0
    else {
      throw HybridProtocolError.invalidTunnelURL
    }

    let delegate = HybridWebSocketDelegate(expectedSubprotocol: subprotocol)
    let configuration = URLSessionConfiguration.ephemeral
    configuration.waitsForConnectivity = false
    configuration.timeoutIntervalForRequest = 30
    configuration.timeoutIntervalForResource = 120
    let session = URLSession(
      configuration: configuration,
      delegate: delegate,
      delegateQueue: nil
    )
    let task = session.webSocketTask(with: url, protocols: [subprotocol])
    task.maximumMessageSize = maximumMessageSize
    task.resume()

    do {
      try await withTaskCancellationHandler {
        try await delegate.waitUntilOpen()
      } onCancel: {
        delegate.cancelPendingOpen()
        task.cancel(with: .goingAway, reason: nil)
        session.invalidateAndCancel()
      }
    } catch {
      task.cancel(with: .protocolError, reason: nil)
      session.invalidateAndCancel()
      throw error
    }

    return URLSessionHybridBinaryChannel(
      session: session,
      task: task,
      maximumMessageSize: maximumMessageSize
    )
  }
}

final class HybridWebSocketDelegate: NSObject, URLSessionWebSocketDelegate,
  @unchecked Sendable
{
  private enum State {
    case pending
    case waiting(CheckedContinuation<Void, any Error>)
    case opened
    case failed(any Error)
  }

  private let expectedSubprotocol: String
  private let lock = NSLock()
  private var state: State = .pending

  init(expectedSubprotocol: String) {
    self.expectedSubprotocol = expectedSubprotocol
  }

  func waitUntilOpen() async throws {
    try await withCheckedThrowingContinuation { continuation in
      register(continuation)
    }
  }

  func cancelPendingOpen() {
    resolve(.failure(CancellationError()))
  }

  private func register(_ continuation: CheckedContinuation<Void, any Error>) {
    lock.lock()
    switch state {
    case .pending:
      state = .waiting(continuation)
      lock.unlock()
    case .opened:
      lock.unlock()
      continuation.resume()
    case .failed(let error):
      lock.unlock()
      continuation.resume(throwing: error)
    case .waiting:
      lock.unlock()
      continuation.resume(throwing: HybridTunnelError.connectionFailed)
    }
  }

  private func resolve(_ result: Result<Void, any Error>) {
    lock.lock()
    let waiting: CheckedContinuation<Void, any Error>?
    switch state {
    case .pending:
      state = result.isSuccess ? .opened : .failed(result.error)
      waiting = nil
    case .waiting(let continuation):
      state = result.isSuccess ? .opened : .failed(result.error)
      waiting = continuation
    case .opened, .failed:
      waiting = nil
    }
    lock.unlock()

    guard let waiting else {
      return
    }
    switch result {
    case .success:
      waiting.resume()
    case .failure(let error):
      waiting.resume(throwing: error)
    }
  }

  func urlSession(
    _ session: URLSession,
    webSocketTask: URLSessionWebSocketTask,
    didOpenWithProtocol protocol: String?
  ) {
    guard `protocol` == expectedSubprotocol else {
      resolve(.failure(HybridProtocolError.invalidWebSocketSubprotocol))
      webSocketTask.cancel(with: .protocolError, reason: nil)
      return
    }
    resolve(.success(()))
  }

  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    didCompleteWithError error: (any Error)?
  ) {
    resolve(.failure(HybridTunnelError.connectionFailed))
  }

  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse,
    newRequest request: URLRequest,
    completionHandler: @escaping (URLRequest?) -> Void
  ) {
    guard request.url?.scheme?.lowercased() == "wss", request.url?.host != nil,
      request.url?.user == nil, request.url?.password == nil
    else {
      completionHandler(nil)
      resolve(.failure(HybridTunnelError.insecureRedirect))
      return
    }
    completionHandler(request)
  }
}

private actor URLSessionHybridBinaryChannel: HybridBinaryChannel {
  private let session: URLSession
  private let task: URLSessionWebSocketTask
  private let maximumMessageSize: Int
  private var closed = false

  init(
    session: URLSession,
    task: URLSessionWebSocketTask,
    maximumMessageSize: Int
  ) {
    self.session = session
    self.task = task
    self.maximumMessageSize = maximumMessageSize
  }

  func send(_ data: Data) async throws {
    guard !closed, data.count <= maximumMessageSize else {
      throw data.count > maximumMessageSize
        ? HybridProtocolError.messageTooLarge : HybridTunnelError.connectionClosed
    }
    do {
      try await task.send(.data(data))
    } catch {
      close()
      throw HybridTunnelError.sendFailed
    }
  }

  func receive() async throws -> Data {
    guard !closed else {
      throw HybridTunnelError.connectionClosed
    }
    do {
      let message = try await task.receive()
      switch message {
      case .data(let data):
        guard data.count <= maximumMessageSize else {
          close()
          throw HybridProtocolError.messageTooLarge
        }
        return data
      case .string:
        close()
        throw HybridProtocolError.nonBinaryWebSocketMessage
      @unknown default:
        close()
        throw HybridTunnelError.receiveFailed
      }
    } catch let error as HybridProtocolError {
      throw error
    } catch {
      close()
      throw HybridTunnelError.receiveFailed
    }
  }

  func cancel() async {
    close()
  }

  private func close() {
    guard !closed else {
      return
    }
    closed = true
    task.cancel(with: .goingAway, reason: nil)
    session.invalidateAndCancel()
  }
}

extension Result where Success == Void, Failure == any Error {
  fileprivate var isSuccess: Bool {
    if case .success = self {
      return true
    }
    return false
  }

  fileprivate var error: any Error {
    if case .failure(let error) = self {
      return error
    }
    return HybridTunnelError.connectionFailed
  }
}
