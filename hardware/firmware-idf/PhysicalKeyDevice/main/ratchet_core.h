// Pure computational core of the session-ratchet, split out of ratchet.cpp so it can be
// compiled and tested on the host (no ESP-IDF, no NVS, no esp_random) — see
// host-tests/ratchet_core_test.cpp. Zero ESP-IDF headers included here on purpose; if
// this file ever needs one, it no longer belongs in this split.
#pragma once

#include <cstdint>
#include "ratchet.h"

// Everything ratchet_run_exchange() does except the NVS load/store — pushed to the
// caller as plain byte-array parameters, which is what makes this testable without real
// hardware. Same X25519 + HMAC-SHA512 math as production, not a reimplementation the
// test could drift from.
//
// No devicePrivateKey parameter: Curve25519::dh1() generates and clamps its own
// ephemeral private key internally via the global RNG (ESP32 hardware RNG in
// production, a host-only stand-in in host-tests) and ignores whatever's in its output
// buffer on entry — an earlier version of this code called esp_fill_random() on that
// buffer first, which dh1() then silently discarded. Removed as dead work, found while
// writing host-tests/ratchet_core_test.cpp.
//
// priorProof / hadPriorState: what NVS held before this call, or hadPriorState=false if
//   nothing was stored yet (first-ever session, or a board that was just erased).
// rc: 16 random bytes for this session's HMAC nonce, only used when hadPriorState is
//   true — pass anything (even zeros) when hadPriorState is false, matching production's
//   own bootstrap-branch behavior of not touching this field.
//
// Returns false only if the X25519 exchange itself failed (a weak/invalid point) — same
// contract as ratchet_run_exchange().
bool ratchet_derive(
    const uint8_t phonePublicKey[32],
    const uint8_t priorProof[32],
    bool hadPriorState,
    const uint8_t rc[16],
    RatchetExchangeResult *out
);
