// Minimal RNGClass implementation satisfying the linker for RNG symbols that
// Ed25519.cpp/Curve25519.cpp reference in code paths this firmware never calls
// (Ed25519::generatePrivateKey, Curve25519::dh1) — identity generation here goes
// through esp_fill_random() directly (see identity.cpp), not through this library's
// RNG class. This just backs the symbol with the real ESP32 hardware RNG in case
// anything does reach it, rather than leaving it undefined.
#include "RNG.h"
#include "esp_random.h"

RNGClass::RNGClass() {}
RNGClass::~RNGClass() {}

void RNGClass::rand(uint8_t *data, size_t len) {
    esp_fill_random(data, len);
}

RNGClass RNG;
