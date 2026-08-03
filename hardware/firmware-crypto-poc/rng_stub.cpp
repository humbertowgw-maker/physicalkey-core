// Minimal stub satisfying the linker for RNG symbols that Ed25519.cpp/Curve25519.cpp
// reference in code paths this PoC never actually calls (generatePrivateKey, dh1) — this
// test supplies its own private key bytes and only exercises derivePublicKey()/sign(),
// which are pure math with no RNG dependency. Not a reimplementation of the library's real
// RNG (which does proper entropy-source mixing for use on actual hardware); this just
// exists so the linker has something to point at.
#include "RNG.h"
#include <cstdio>

RNGClass::RNGClass() {}
RNGClass::~RNGClass() {}

void RNGClass::rand(uint8_t *data, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(data, 1, len, f);
        fclose(f);
    }
}

RNGClass RNG;
