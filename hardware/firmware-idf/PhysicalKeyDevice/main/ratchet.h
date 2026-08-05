// Session-ratchet continuity check: an ephemeral X25519 exchange every session, chained
// forward via an HMAC-SHA512-derived proof, so a cloned long-term identity key goes stale
// the moment the real phone+device pair completes one more real session. Deliberately
// independent of identity.h's long-term Ed25519 key: this uses a fresh ephemeral X25519
// keypair every session and only ever persists a small derived proof, never a private
// key, to NVS.
#pragma once

#include <cstdint>

// 32-byte ephemeral X25519 public key this session, exposed via the RatchetPubKey/
// RatchetResponse GATT characteristics (see gatt_svr.cpp).
struct RatchetExchangeResult {
    uint8_t devicePublicKey[32];
    uint8_t rc[16];             // random nonce for this session's HMAC proof, unused if bootstrap
    uint8_t deviceProof[64];    // HMAC-SHA512(priorNextProof, rc) — zeroed if bootstrap
    uint8_t status;             // 0 = bootstrap (no prior stored state), 1 = has prior state
};

// Runs the device side of one ratchet exchange: generates a fresh ephemeral keypair,
// computes the X25519 shared secret with the phone's ephemeral public key, and — if a
// prior session's proof is stored in NVS — computes deviceProof over a fresh random
// nonce so the phone can independently verify continuity. Always advances the stored
// ratchet state forward (overwrites whatever was in NVS with this session's derived
// proof) regardless of whether prior state existed, which is what makes it a ratchet
// rather than a static shared value. Returns false only if the X25519 exchange itself
// failed (a weak/invalid point) — in that case no ratchet state is touched, so a single
// glitched exchange can't disrupt the chain a real session already established.
bool ratchet_run_exchange(const uint8_t phonePublicKey[32], RatchetExchangeResult *out);
