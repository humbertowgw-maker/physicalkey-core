// PhysicalKey IoT key fob firmware — ESP32, Arduino core.
//
// Holds an Ed25519 identity (generated once on first boot, persisted in NVS flash) and
// exposes it over BLE so a paired phone can complete the "device" stage of the
// PhysicalKey auth flow: read this device's public key + deviceId once (for backend
// registration), then for each auth attempt, write the backend-issued challenge string
// and read back a signature.
//
// The Ed25519 implementation (Rhys Weatherley's arduinolibs "Crypto" library) and its
// exact raw-key/signature format were verified compatible with the live backend in
// ../firmware-crypto-poc — this sketch uses the identical Ed25519::derivePublicKey() /
// Ed25519::sign() calls, so that compatibility carries over directly. What ISN'T
// verified yet: this file has only been compiled against the ESP32 toolchain (no
// physical board attached to this dev machine to actually flash and run it) — see
// ../../mobile/ios/README.md for how the phone side handles the same "compiled but not
// hardware-tested" situation, and README.md in this directory for what's left.

#include <Ed25519.h>
#include <Preferences.h>
#include <esp_system.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>

// Custom 128-bit UUIDs for the PhysicalKey device GATT service. Generated once for this
// project; any BLE UUID generator would do, these just need to be stable and unique.
#define SERVICE_UUID           "b16a3c00-2c1e-4a7a-9b7a-0a1c2d3e4f50"
#define CHAR_PUBLIC_KEY_UUID   "b16a3c01-2c1e-4a7a-9b7a-0a1c2d3e4f50" // read: 44-byte raw SPKI DER
#define CHAR_DEVICE_ID_UUID    "b16a3c02-2c1e-4a7a-9b7a-0a1c2d3e4f50" // read: UTF-8 device ID string
#define CHAR_CHALLENGE_UUID    "b16a3c03-2c1e-4a7a-9b7a-0a1c2d3e4f50" // write: UTF-8 challenge string from the backend
#define CHAR_SIGNATURE_UUID    "b16a3c04-2c1e-4a7a-9b7a-0a1c2d3e4f50" // read/notify: 64-byte raw Ed25519 signature

static const uint8_t ED25519_SPKI_PREFIX[12] = {
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
};

Preferences preferences;
uint8_t privateKey[32];
uint8_t publicKey[32];
uint8_t publicKeySPKI[44];
String deviceId;

// Explicit forward declarations — the Arduino IDE/arduino-cli auto-generates these from a
// naive scan of the file, which gets confused by the BLECharacteristicCallbacks subclass
// sitting between functions below and produces bogus errors. Declaring these ourselves
// sidesteps that entirely.
void loadOrCreateIdentity();
void setupBLE();

BLECharacteristic *signatureCharacteristic;

// Loads the stored identity, or generates and persists a new one on first boot. This is
// deliberately a one-time operation per physical device: re-generating a key for a
// deviceId the backend has already registered is correctly rejected by the backend's
// trust-on-first-use check (a hijack-looking key swap), so this must never silently
// regenerate on every boot.
void loadOrCreateIdentity() {
    preferences.begin("physicalkey", false);

    size_t storedLen = preferences.getBytesLength("privkey");
    if (storedLen == 32) {
        preferences.getBytes("privkey", privateKey, 32);
        Serial.println("Loaded existing identity from flash.");
    } else {
        // Real hardware TRNG, not the Crypto library's software RNG class (which expects
        // application-registered noise sources) — esp_fill_random() is backed by the
        // ESP32's actual hardware random number generator.
        esp_fill_random(privateKey, 32);
        preferences.putBytes("privkey", privateKey, 32);
        Serial.println("Generated new identity and saved to flash.");
    }

    Ed25519::derivePublicKey(publicKey, privateKey);
    memcpy(publicKeySPKI, ED25519_SPKI_PREFIX, 12);
    memcpy(publicKeySPKI + 12, publicKey, 32);

    // Chip-derived, not random — a real hardware-unique identifier, matching the
    // "unique hardware ID" requirement from the product spec, unlike the phone app's
    // randomly generated per-install UUID.
    uint64_t chipId = ESP.getEfuseMac();
    char idBuf[32];
    snprintf(idBuf, sizeof(idBuf), "physicalkey-device-%012llx", chipId);
    deviceId = String(idBuf);

    Serial.print("Device ID: ");
    Serial.println(deviceId);
}

class ChallengeWriteCallback : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic *characteristic) override {
        String challenge = characteristic->getValue();
        if (challenge.length() == 0) return;

        Serial.print("Received challenge: ");
        Serial.println(challenge);

        uint8_t signature[64];
        Ed25519::sign(signature, privateKey, publicKey,
                       challenge.c_str(), challenge.length());

        signatureCharacteristic->setValue(signature, 64);
        signatureCharacteristic->notify();

        Serial.println("Signed and notified.");
    }
};

void setupBLE() {
    // Advertised name deliberately short and generic, NOT the full deviceId
    // ("physicalkey-device-<12 hex chars>", 31 bytes on its own) -- combined with our
    // 128-bit custom service UUID (18 bytes with header), that overflows BLE's 31-byte
    // legacy advertising packet. A silently-overflowed/dropped service UUID in the
    // advertisement is exactly what would make a phone's scanForPeripherals(withServices:)
    // filter find nothing. The full unique deviceId is still available via the Device ID
    // characteristic once connected -- it doesn't need to fit in the broadcast itself.
    BLEDevice::init("PhysicalKey");
    BLEServer *server = BLEDevice::createServer();
    BLEService *service = server->createService(SERVICE_UUID);

    BLECharacteristic *publicKeyCharacteristic = service->createCharacteristic(
        CHAR_PUBLIC_KEY_UUID, BLECharacteristic::PROPERTY_READ);
    publicKeyCharacteristic->setValue(publicKeySPKI, 44);

    BLECharacteristic *deviceIdCharacteristic = service->createCharacteristic(
        CHAR_DEVICE_ID_UUID, BLECharacteristic::PROPERTY_READ);
    deviceIdCharacteristic->setValue(deviceId.c_str());

    BLECharacteristic *challengeCharacteristic = service->createCharacteristic(
        CHAR_CHALLENGE_UUID, BLECharacteristic::PROPERTY_WRITE);
    challengeCharacteristic->setCallbacks(new ChallengeWriteCallback());

    signatureCharacteristic = service->createCharacteristic(
        CHAR_SIGNATURE_UUID,
        BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_NOTIFY);
    signatureCharacteristic->addDescriptor(new BLE2902());

    service->start();

    BLEAdvertising *advertising = BLEDevice::getAdvertising();
    advertising->addServiceUUID(SERVICE_UUID);
    advertising->setScanResponse(true);
    // Standard fix for a separate, well-documented ESP32-Arduino-BLE + iOS compatibility
    // issue where iOS rejects/struggles with the connection interval the ESP32 defaults to.
    advertising->setMinPreferred(0x06);
    advertising->setMinPreferred(0x12);
    BLEDevice::startAdvertising();

    Serial.println("BLE advertising started.");
}

void setup() {
    Serial.begin(115200);
    delay(500);

    loadOrCreateIdentity();
    setupBLE();
}

void loop() {
    delay(1000);
}
