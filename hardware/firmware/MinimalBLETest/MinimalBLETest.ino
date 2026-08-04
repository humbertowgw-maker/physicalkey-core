// Isolation test v2: same as before, but WITHOUT Serial.begin() at all, to test
// whether the crash we found is actually happening right at Serial.begin()/UART
// setup, before BLE code is ever reached.
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>

#define SERVICE_UUID "b16a3c00-2c1e-4a7a-9b7a-0a1c2d3e4f50"

void setup() {
    BLEDevice::init("PhysicalKey");
    BLEServer *server = BLEDevice::createServer();
    BLEService *service = server->createService(SERVICE_UUID);
    service->start();

    BLEAdvertising *advertising = BLEDevice::getAdvertising();
    advertising->addServiceUUID(SERVICE_UUID);
    advertising->setScanResponse(true);
    BLEDevice::startAdvertising();
}

void loop() {
    delay(1000);
}
