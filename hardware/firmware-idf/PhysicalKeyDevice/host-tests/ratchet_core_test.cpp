// Host-side test for ratchet_core.cpp — compiles and runs natively on the dev machine,
// no ESP32 or ESP-IDF toolchain needed. Links the exact same ratchet_core.cpp and
// Curve25519/SHA512/Hash/BigNumberUtil/Crypto sources that ship on the real board (plus
// host_rng.cpp, a test-only stand-in for the real board's hardware-RNG-backed RNG
// global — see that file's comment); nothing here is a reimplementation the firmware
// could silently drift away from.
//
// Build & run:
//   cd hardware/firmware-idf/PhysicalKeyDevice/host-tests
//   ./run.sh
//
// What this actually proves, that a compile-clean `idf.py build` doesn't:
//   1. The device and phone sides of the X25519 exchange genuinely agree on the same
//      shared secret — computed two independent ways (once inside ratchet_derive, once
//      by this test simulating the phone side), not just "some bytes came out."
//   2. The continuity proof (deviceProof) and the forward-chained nextProof are exactly
//      the HMAC-SHA512 values the protocol doc in ratchet.h says they should be.
//   3. A known weak/invalid X25519 point is correctly rejected rather than silently
//      producing a bogus "shared secret."
#include <cassert>
#include <cstdio>
#include <cstring>
#include <cstdint>

#include "Curve25519.h"
#include "Hash.h"
#include "SHA512.h"
#include "ratchet_core.h"

static int failures = 0;

#define CHECK(cond, msg) do { \
    if (cond) { printf("  ok   %s\n", msg); } \
    else { printf("  FAIL %s (%s:%d)\n", msg, __FILE__, __LINE__); failures++; } \
} while (0)

static void fillDeterministic(uint8_t *buf, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(seed + i * 7);
}

// Independently re-derives what ratchet_derive() should have computed, using the SAME
// hmac<SHA512> the production code uses (this is the real library call, not a
// reimplementation) but driven by this test's own independently-known shared secret —
// the point is cross-checking ratchet_derive()'s *result* against a second, separately
// computed path to the same value, not just calling the function once and trusting it.
static void expectedNextProof(const uint8_t sharedSecret[32], uint8_t out[32]) {
    static const char *ctx = "physicalkey-ratchet-next-v1";
    hmac<SHA512>(out, 32, sharedSecret, 32, ctx, strlen(ctx));
}

int main() {
    int suiteFailuresBefore;

    // ---- Test 1: device and phone genuinely agree on the same X25519 shared secret ----
    printf("X25519 agreement + nextProof derivation\n");
    suiteFailuresBefore = failures;
    {
        uint8_t phonePrivate[32];
        fillDeterministic(phonePrivate, 32, 0x11);
        uint8_t phonePublic[32];
        memcpy(phonePublic, phonePrivate, 32);
        Curve25519::dh1(phonePublic, phonePrivate); // clamps in place, derives phonePublic

        RatchetExchangeResult result;
        uint8_t priorProofUnused[32] = {0};
        uint8_t rcUnused[16] = {0};
        bool ok = ratchet_derive(phonePublic, priorProofUnused, false, rcUnused, &result);
        CHECK(ok, "ratchet_derive succeeds for a real, valid phone public key");
        CHECK(result.status == 0, "status is 0 (bootstrap) when hadPriorState is false");

        // Independently compute the phone side's view of the shared secret: X25519(phonePrivate, deviceReturnedPublicKey).
        uint8_t phoneSideSecret[32];
        memcpy(phoneSideSecret, result.devicePublicKey, 32);
        bool phoneOk = Curve25519::dh2(phoneSideSecret, phonePrivate);
        CHECK(phoneOk, "phone side's independent X25519 computation also succeeds");

        uint8_t expected[32];
        expectedNextProof(phoneSideSecret, expected);
        CHECK(memcmp(expected, result.nextProof, 32) == 0,
              "nextProof matches HMAC-SHA512(independently-computed shared secret, context) — proves both sides really agree");
    }
    printf(failures == suiteFailuresBefore ? "  PASS\n\n" : "  SUITE HAD FAILURES\n\n");

    // ---- Test 2: continuity — session 2's deviceProof matches session 1's nextProof ----
    printf("Continuity proof across two sessions\n");
    suiteFailuresBefore = failures;
    {
        uint8_t phonePrivate[32];
        fillDeterministic(phonePrivate, 32, 0x22);
        uint8_t phonePublic[32];
        memcpy(phonePublic, phonePrivate, 32);
        Curve25519::dh1(phonePublic, phonePrivate);

        RatchetExchangeResult session1;
        uint8_t noPrior[32] = {0};
        uint8_t noRc[16] = {0};
        bool ok1 = ratchet_derive(phonePublic, noPrior, false, noRc, &session1);
        CHECK(ok1, "session 1 (bootstrap) succeeds");

        uint8_t rc[16];
        fillDeterministic(rc, 16, 0x55);
        RatchetExchangeResult session2;
        bool ok2 = ratchet_derive(phonePublic, session1.nextProof, true, rc, &session2);
        CHECK(ok2, "session 2 (continuity) succeeds");
        CHECK(session2.status == 1, "status is 1 (continuity) when hadPriorState is true");
        CHECK(memcmp(session2.rc, rc, 16) == 0, "rc is passed through into the result unchanged");

        uint8_t expectedDeviceProof[64];
        hmac<SHA512>(expectedDeviceProof, 64, session1.nextProof, 32, rc, 16);
        CHECK(memcmp(expectedDeviceProof, session2.deviceProof, 64) == 0,
              "deviceProof == HMAC-SHA512(priorNextProof, rc), matching ratchet.h's documented contract");
    }
    printf(failures == suiteFailuresBefore ? "  PASS\n\n" : "  SUITE HAD FAILURES\n\n");

    // ---- Test 3: a known-weak X25519 point is rejected, not silently accepted ----
    printf("Weak point rejection\n");
    suiteFailuresBefore = failures;
    {
        uint8_t allZeroPhonePublic[32] = {0}; // documented weak point (cr.yp.to/ecdh.html)
        RatchetExchangeResult result;
        uint8_t noPrior[32] = {0};
        uint8_t noRc[16] = {0};
        bool ok = ratchet_derive(allZeroPhonePublic, noPrior, false, noRc, &result);
        CHECK(!ok, "an all-zero (known weak) phone public key is rejected, not silently accepted");
    }
    printf(failures == suiteFailuresBefore ? "  PASS\n\n" : "  SUITE HAD FAILURES\n\n");

    if (failures == 0) {
        printf("All checks passed.\n");
        return 0;
    }
    printf("%d check(s) failed.\n", failures);
    return 1;
}
