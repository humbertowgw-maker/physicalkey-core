#include "ratchet_core.h"

#include <cstring>

#include "Curve25519.h"
#include "Hash.h"
#include "SHA512.h"

// Fixed context string, not a secret — HMAC-SHA512 over an already-high-entropy X25519
// shared secret is a lightweight, sufficient KDF here (equivalent in spirit to
// HKDF-Expand alone, appropriate when the input keying material already has full
// entropy, which a 256-bit ECDH output does). Must match ratchet.cpp's copy exactly —
// there is deliberately only one copy of this string now, in ratchet_core.cpp, since
// ratchet.cpp no longer needs its own.
static const char *NEXT_PROOF_CONTEXT = "physicalkey-ratchet-next-v1";

bool ratchet_derive(
    const uint8_t phonePublicKey[32],
    const uint8_t priorProof[32],
    bool hadPriorState,
    const uint8_t rc[16],
    RatchetExchangeResult *out
) {
    // dh1 generates and clamps its own ephemeral private key into devicePrivateKey via
    // the global RNG, ignoring whatever (if anything) was there on entry — the buffer
    // only needs to exist so dh1 has somewhere to write it for dh2 to read back below.
    uint8_t devicePrivateKey[32];
    Curve25519::dh1(out->devicePublicKey, devicePrivateKey);

    uint8_t sharedSecret[32];
    memcpy(sharedSecret, phonePublicKey, 32);
    // dh2 overwrites sharedSecret with the X25519 result; returns false on a weak point.
    bool ok = Curve25519::dh2(sharedSecret, devicePrivateKey);
    memset(devicePrivateKey, 0, sizeof(devicePrivateKey)); // ephemeral — never persisted

    if (!ok) {
        memset(sharedSecret, 0, sizeof(sharedSecret));
        return false;
    }

    if (hadPriorState) {
        memcpy(out->rc, rc, sizeof(out->rc));
        hmac<SHA512>(out->deviceProof, sizeof(out->deviceProof), priorProof, 32, out->rc, sizeof(out->rc));
        out->status = 1;
    } else {
        memset(out->rc, 0, sizeof(out->rc));
        memset(out->deviceProof, 0, sizeof(out->deviceProof));
        out->status = 0;
    }

    uint8_t nextProof[32];
    hmac<SHA512>(nextProof, sizeof(nextProof), sharedSecret, sizeof(sharedSecret), NEXT_PROOF_CONTEXT, strlen(NEXT_PROOF_CONTEXT));
    memset(sharedSecret, 0, sizeof(sharedSecret));
    memcpy(out->nextProof, nextProof, sizeof(nextProof));

    return true;
}
