import Foundation
import CoreBluetooth

/// Speaks the GATT protocol defined by hardware/firmware/PhysicalKeyDevice/PhysicalKeyDevice.ino.
/// UUIDs below must stay byte-for-byte identical to the firmware's #define block — there's
/// no negotiation, just a fixed contract both sides hardcode.
///
/// NOT TESTED ON HARDWARE. This compiles and type-checks, but there is no ESP32 board
/// paired with any iPhone anywhere — nothing here has ever actually talked to the firmware.
/// The firmware side (compiled, not flashed — see hardware/README.md) and this client were
/// written from the same protocol spec, not verified against each other by running both.
/// The one thing NOT blind here: the Ed25519 signature format both sides produce/expect
/// was proven compatible with the backend independently, in both mobile/ios-crypto-poc and
/// hardware/firmware-crypto-poc — what's unverified is specifically the Bluetooth transport
/// connecting them, not the cryptography.
final class DeviceBluetoothManager: NSObject, ObservableObject {
    enum ConnectionError: Error {
        case bluetoothUnavailable
        case scanTimedOut
        case serviceNotFound
        case characteristicNotFound
        case notConnected
        case peripheralDisconnected
    }

    private static let serviceUUID = CBUUID(string: "b16a3c00-2c1e-4a7a-9b7a-0a1c2d3e4f50")
    private static let publicKeyCharUUID = CBUUID(string: "b16a3c01-2c1e-4a7a-9b7a-0a1c2d3e4f50")
    private static let deviceIdCharUUID = CBUUID(string: "b16a3c02-2c1e-4a7a-9b7a-0a1c2d3e4f50")
    private static let challengeCharUUID = CBUUID(string: "b16a3c03-2c1e-4a7a-9b7a-0a1c2d3e4f50")
    private static let signatureCharUUID = CBUUID(string: "b16a3c04-2c1e-4a7a-9b7a-0a1c2d3e4f50")

    struct DeviceIdentity {
        let deviceId: String
        let publicKeyB64: String
    }

    private var centralManager: CBCentralManager!
    private var peripheral: CBPeripheral?

    private var publicKeyCharacteristic: CBCharacteristic?
    private var deviceIdCharacteristic: CBCharacteristic?
    private var challengeCharacteristic: CBCharacteristic?
    private var signatureCharacteristic: CBCharacteristic?

    // CoreBluetooth is delegate-callback based; these bridge that to async/await. Each is
    // consumed exactly once per operation and nilled out immediately to avoid a delegate
    // callback firing twice and resuming an already-resumed continuation (which crashes).
    private var connectContinuation: CheckedContinuation<DeviceIdentity, Error>?
    private var signContinuation: CheckedContinuation<String, Error>?

    override init() {
        super.init()
        centralManager = CBCentralManager(delegate: self, queue: nil)
    }

    /// Scans for a PhysicalKey device, connects, discovers the service/characteristics, and
    /// reads back its public key + device ID. Times out after 15s if nothing is found —
    /// untested how realistic that window is without hardware to measure against.
    func connectToDevice() async throws -> DeviceIdentity {
        guard centralManager.state == .poweredOn else {
            throw ConnectionError.bluetoothUnavailable
        }

        return try await withCheckedThrowingContinuation { continuation in
            self.connectContinuation = continuation
            self.centralManager.scanForPeripherals(withServices: [Self.serviceUUID], options: nil)

            DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [weak self] in
                guard let self, let pending = self.connectContinuation else { return }
                self.connectContinuation = nil
                self.centralManager.stopScan()
                pending.resume(throwing: ConnectionError.scanTimedOut)
            }
        }
    }

    /// Writes `challenge` to the device's challenge characteristic and waits for the
    /// resulting signature on the notify characteristic, matching
    /// ChallengeWriteCallback::onWrite in the firmware, which signs synchronously on write
    /// and immediately notifies. Returns the signature base64-encoded, ready to send to
    /// the backend as `deviceSignature`.
    func sign(challenge: String) async throws -> String {
        guard let peripheral, let challengeCharacteristic, let signatureCharacteristic else {
            throw ConnectionError.notConnected
        }

        return try await withCheckedThrowingContinuation { continuation in
            self.signContinuation = continuation
            peripheral.setNotifyValue(true, for: signatureCharacteristic)
            peripheral.writeValue(Data(challenge.utf8), for: challengeCharacteristic, type: .withResponse)
        }
    }

    func disconnect() {
        if let peripheral {
            centralManager.cancelPeripheralConnection(peripheral)
        }
        peripheral = nil
        publicKeyCharacteristic = nil
        deviceIdCharacteristic = nil
        challengeCharacteristic = nil
        signatureCharacteristic = nil
    }
}

extension DeviceBluetoothManager: CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        // Nothing to do here proactively — connectToDevice() checks .poweredOn itself
        // before scanning, since a scan call before Bluetooth is ready is a no-op.
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral, advertisementData: [String: Any], rssi: NSNumber) {
        central.stopScan()
        self.peripheral = peripheral
        peripheral.delegate = self
        central.connect(peripheral, options: nil)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        peripheral.discoverServices([Self.serviceUUID])
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        let pending = connectContinuation
        connectContinuation = nil
        pending?.resume(throwing: error ?? ConnectionError.peripheralDisconnected)
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        if let pending = connectContinuation {
            connectContinuation = nil
            pending.resume(throwing: error ?? ConnectionError.peripheralDisconnected)
        }
        if let pending = signContinuation {
            signContinuation = nil
            pending.resume(throwing: error ?? ConnectionError.peripheralDisconnected)
        }
    }
}

extension DeviceBluetoothManager: CBPeripheralDelegate {
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard let service = peripheral.services?.first(where: { $0.uuid == Self.serviceUUID }) else {
            let pending = connectContinuation
            connectContinuation = nil
            pending?.resume(throwing: error ?? ConnectionError.serviceNotFound)
            return
        }
        peripheral.discoverCharacteristics(
            [Self.publicKeyCharUUID, Self.deviceIdCharUUID, Self.challengeCharUUID, Self.signatureCharUUID],
            for: service
        )
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard let characteristics = service.characteristics else {
            let pending = connectContinuation
            connectContinuation = nil
            pending?.resume(throwing: error ?? ConnectionError.characteristicNotFound)
            return
        }

        for characteristic in characteristics {
            switch characteristic.uuid {
            case Self.publicKeyCharUUID: publicKeyCharacteristic = characteristic
            case Self.deviceIdCharUUID: deviceIdCharacteristic = characteristic
            case Self.challengeCharUUID: challengeCharacteristic = characteristic
            case Self.signatureCharUUID: signatureCharacteristic = characteristic
            default: break
            }
        }

        guard let publicKeyCharacteristic, let deviceIdCharacteristic else {
            let pending = connectContinuation
            connectContinuation = nil
            pending?.resume(throwing: ConnectionError.characteristicNotFound)
            return
        }

        peripheral.readValue(for: publicKeyCharacteristic)
        peripheral.readValue(for: deviceIdCharacteristic)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        if let error {
            if characteristic.uuid == Self.signatureCharUUID {
                let pending = signContinuation
                signContinuation = nil
                pending?.resume(throwing: error)
            } else {
                let pending = connectContinuation
                connectContinuation = nil
                pending?.resume(throwing: error)
            }
            return
        }

        guard let data = characteristic.value else { return }

        switch characteristic.uuid {
        case Self.publicKeyCharUUID, Self.deviceIdCharUUID:
            completeConnectIfReady()
        case Self.signatureCharUUID:
            let pending = signContinuation
            signContinuation = nil
            pending?.resume(returning: data.base64EncodedString())
        default:
            break
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        // The actual signature arrives via didUpdateValueFor's notify, once the firmware
        // finishes signing — this write acknowledgment on its own doesn't resolve anything.
        if let error, characteristic.uuid == Self.challengeCharUUID {
            let pending = signContinuation
            signContinuation = nil
            pending?.resume(throwing: error)
        }
    }

    private func completeConnectIfReady() {
        guard let pending = connectContinuation,
              let publicKeyCharacteristic, let deviceIdCharacteristic,
              let publicKeyData = publicKeyCharacteristic.value,
              let deviceIdData = deviceIdCharacteristic.value,
              let deviceId = String(data: deviceIdData, encoding: .utf8) else {
            return
        }
        connectContinuation = nil
        pending.resume(returning: DeviceIdentity(deviceId: deviceId, publicKeyB64: publicKeyData.base64EncodedString()))
    }
}
