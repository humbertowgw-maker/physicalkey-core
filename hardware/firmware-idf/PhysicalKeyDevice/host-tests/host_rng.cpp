// Host-only stand-in for rng_esp32.cpp's RNGClass — Curve25519::dh1() reaches the global
// `RNG` object internally to generate its own ephemeral private key, so linking a host
// test requires *some* RNGClass instance to exist. Uses the real libc CSPRNG
// (arc4random_buf, available on macOS/BSD; glibc's getrandom(2) equivalent would be
// needed on Linux) — good enough for a correctness test, since these tests check
// protocol properties (agreement, continuity, weak-point rejection) that hold for any
// valid random key, not specific key values. Never linked into the real firmware build
// (main/CMakeLists.txt doesn't reference this file) — the real board keeps using
// rng_esp32.cpp's genuine ESP32 hardware RNG.
#include "RNG.h"
#include <cstdlib>

RNGClass::RNGClass() {}
RNGClass::~RNGClass() {}

void RNGClass::rand(uint8_t *data, size_t len) {
    arc4random_buf(data, len);
}

RNGClass RNG;
