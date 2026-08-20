@preconcurrency import CoreBluetooth
import Foundation

/// CoreBluetooth service-data scanner for PXP proof-of-proximity adverts.
///
/// The adapter exposes only the bounded service payload needed by the protocol;
/// peripheral names and identifiers never enter the protocol core.
public final class CoreBluetoothHybridScanner: NSObject, HybridBluetoothScanner,
  @unchecked Sendable
{
  private typealias Continuation =
    AsyncThrowingStream<HybridBluetoothAdvertisement, any Error>.Continuation

  private let lock = NSLock()
  private let queue = DispatchQueue(label: "org.siriussecuritykey.hybrid-bluetooth")
  private var manager: CBCentralManager?
  private var continuation: Continuation?
  private var targetService: CBUUID?
  private var scanning = false

  public override init() {
    super.init()
    manager = CBCentralManager(
      delegate: self,
      queue: queue,
      options: [CBCentralManagerOptionShowPowerAlertKey: false]
    )
  }

  public func scan(
    serviceUUID: UUID
  ) async throws -> AsyncThrowingStream<HybridBluetoothAdvertisement, any Error> {
    let stream = try prepareStream(serviceUUID: serviceUUID)
    queue.async { [weak self] in
      self?.startIfPossible()
    }
    return stream
  }

  private func prepareStream(
    serviceUUID: UUID
  ) throws -> AsyncThrowingStream<HybridBluetoothAdvertisement, any Error> {
    lock.lock()
    guard continuation == nil else {
      lock.unlock()
      throw HybridBluetoothError.alreadyScanning
    }

    var streamContinuation: Continuation?
    let stream = AsyncThrowingStream<HybridBluetoothAdvertisement, any Error> {
      streamContinuation = $0
    }
    guard let streamContinuation else {
      lock.unlock()
      throw HybridBluetoothError.scanFailed
    }
    streamContinuation.onTermination = { [weak self] _ in
      self?.requestStop()
    }
    continuation = streamContinuation
    targetService = CBUUID(string: serviceUUID.uuidString)
    lock.unlock()
    return stream
  }

  public func stop() async {
    await withCheckedContinuation { continuation in
      queue.async { [weak self] in
        self?.stopAndFinish()
        continuation.resume()
      }
    }
  }

  private func requestStop() {
    queue.async { [weak self] in
      self?.stopAndFinish()
    }
  }

  private func startIfPossible() {
    guard let manager else {
      finish(throwing: HybridBluetoothError.unavailable)
      return
    }
    switch manager.state {
    case .poweredOn:
      lock.lock()
      if scanning {
        lock.unlock()
        return
      }
      let service = targetService
      scanning = service != nil
      lock.unlock()
      guard let service else {
        finish(throwing: HybridBluetoothError.scanFailed)
        return
      }
      manager.scanForPeripherals(
        withServices: [service],
        options: [CBCentralManagerScanOptionAllowDuplicatesKey: true]
      )
    case .unauthorized:
      finish(throwing: HybridBluetoothError.permissionDenied)
    case .unsupported:
      finish(throwing: HybridBluetoothError.unavailable)
    case .poweredOff:
      finish(throwing: HybridBluetoothError.poweredOff)
    case .resetting:
      finish(throwing: HybridBluetoothError.resetting)
    case .unknown:
      break
    @unknown default:
      finish(throwing: HybridBluetoothError.unavailable)
    }
  }

  private func stopAndFinish() {
    manager?.stopScan()
    lock.lock()
    scanning = false
    targetService = nil
    let currentContinuation = continuation
    continuation = nil
    lock.unlock()
    currentContinuation?.finish()
  }

  private func finish(throwing error: any Error) {
    manager?.stopScan()
    lock.lock()
    scanning = false
    targetService = nil
    let currentContinuation = continuation
    continuation = nil
    lock.unlock()
    currentContinuation?.finish(throwing: error)
  }
}

extension CoreBluetoothHybridScanner: CBCentralManagerDelegate {
  public func centralManagerDidUpdateState(_ central: CBCentralManager) {
    startIfPossible()
  }

  public func centralManager(
    _ central: CBCentralManager,
    didDiscover peripheral: CBPeripheral,
    advertisementData: [String: Any],
    rssi: NSNumber
  ) {
    lock.lock()
    let service = targetService
    let currentContinuation = continuation
    let isScanning = scanning
    lock.unlock()

    guard isScanning, let service, let currentContinuation,
      let serviceData = advertisementData[CBAdvertisementDataServiceDataKey]
        as? [CBUUID: Data],
      let data = serviceData[service]
    else {
      return
    }

    currentContinuation.yield(
      HybridBluetoothAdvertisement(
        serviceUUID: HybridProximityDiscovery.serviceUUID,
        serviceData: data
      )
    )
  }
}
