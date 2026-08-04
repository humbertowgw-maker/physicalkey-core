// Ed25519 device identity: generated once on first boot, persisted in NVS flash.
// Ported from the Arduino version (../../firmware/PhysicalKeyDevice) after that core
// proved incapable of running at all on this board's ESP32-D0WD-V3 (revision v3.1)
// silicon — see ../README.md for the investigation. The crypto itself (Rhys Weatherley's
// arduinolibs "Crypto" library, vendored into ../components/ed25519) is untouched and
// already verified against the live backend in ../../firmware-crypto-poc.
#pragma once

#include <cstddef>
#include <cstdint>

extern uint8_t g_privateKey[32];
extern uint8_t g_publicKey[32];
extern uint8_t g_publicKeySPKI[44];
extern char g_deviceId[40];
extern size_t g_deviceIdLen;

// Loads the stored identity from NVS, or generates and persists a new one on first
// boot. Deliberately a one-time operation per physical device — regenerating a key for
// a deviceId the backend has already registered is correctly rejected by the backend's
// trust-on-first-use check.
void loadOrCreateIdentity();
