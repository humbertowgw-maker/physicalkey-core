// PhysicalKey BLE GATT service — ESP-IDF/NimBLE port of ../../firmware/PhysicalKeyDevice's
// Arduino BLEServer service. Same 128-bit UUIDs, same characteristic layout, same
// challenge -> Ed25519 sign -> notify flow. See identity.h for the key material and
// ../README.md for why this exists as a separate ESP-IDF build rather than a fix to the
// Arduino sketch.
#include "gatt_svr.h"

#include <cstring>

#include "esp_log.h"
#include "host/ble_hs.h"
#include "host/ble_uuid.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#include "mbedtls/sha256.h"

#include "Ed25519.h"
#include "identity.h"
#include "ratchet.h"

static const char *TAG = "gatt_svr";

// Fixed context string for the ratchet attestation signature (see access_ratchet_pubkey
// below), not a secret — same role as ratchet.cpp's own NEXT_PROOF_CONTEXT, just domain-
// separating this signed message from anything else this Ed25519 key ever signs.
static const char *RATCHET_ATTEST_CONTEXT = "physicalkey-ratchet-attest-v1";

// Same 5 UUIDs as the Arduino firmware (b16a3c00.. through b16a3c04.., base
// 2c1e-4a7a-9b7a-0a1c2d3e4f50), reversed into NimBLE's little-endian byte order.
// Only the 4th byte of the first group varies between them (0x00..0x04).
#define PK_UUID128(id_byte) \
    0x50, 0x4f, 0x3e, 0x2d, 0x1c, 0x0a, 0x7a, 0x9b, 0x7a, 0x4a, 0x1e, 0x2c, id_byte, 0x3c, 0x6a, 0xb1

static const ble_uuid128_t svc_uuid =
    BLE_UUID128_INIT(PK_UUID128(0x00));
static const ble_uuid128_t chr_public_key_uuid =
    BLE_UUID128_INIT(PK_UUID128(0x01));
static const ble_uuid128_t chr_device_id_uuid =
    BLE_UUID128_INIT(PK_UUID128(0x02));
static const ble_uuid128_t chr_challenge_uuid =
    BLE_UUID128_INIT(PK_UUID128(0x03));
static const ble_uuid128_t chr_signature_uuid =
    BLE_UUID128_INIT(PK_UUID128(0x04));
static const ble_uuid128_t chr_ratchet_pubkey_uuid =
    BLE_UUID128_INIT(PK_UUID128(0x05));
static const ble_uuid128_t chr_ratchet_response_uuid =
    BLE_UUID128_INIT(PK_UUID128(0x06));

static uint16_t signature_val_handle;
static uint8_t signature[64];

// The most recently-written Challenge value this connection, and its length — cached so the
// ratchet attestation (access_ratchet_pubkey below) can bind its signature to the same
// backend challenge the primary deviceSignature already covers. Cleared on disconnect
// (gatt_svr_clear_challenge_cache, called from main.cpp) so a captured attestation from one
// connection can never be replayed as if it belonged to another.
static uint8_t g_lastChallenge[256];
static size_t g_lastChallengeLen = 0;

static uint16_t ratchet_response_val_handle;
// Wire layout: devicePublicKey(32) || rc(16) || deviceProof(64) || nextProof(32) ||
// status(1) || ratchetSig(64) = 209 bytes. ratchetSig is this device's existing Ed25519
// identity key signing RATCHET_ATTEST_CONTEXT || SHA256(challenge) || everything before it
// in this buffer — the backend independently verifies it (see backend/auth/ratchet.js)
// instead of trusting whatever the phone app reports. Larger than the default 23-byte ATT
// MTU, same as it already was at 113 bytes — see main.cpp's explicit
// ble_att_set_preferred_mtu() call, raised specifically to give this room.
static uint8_t ratchet_response_wire[32 + 16 + 64 + 32 + 1 + 64];

static int access_public_key(uint16_t conn_handle, uint16_t attr_handle,
                              struct ble_gatt_access_ctxt *ctxt, void *arg) {
    int rc = os_mbuf_append(ctxt->om, g_publicKeySPKI, sizeof(g_publicKeySPKI));
    return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
}

static int access_device_id(uint16_t conn_handle, uint16_t attr_handle,
                             struct ble_gatt_access_ctxt *ctxt, void *arg) {
    int rc = os_mbuf_append(ctxt->om, g_deviceId, g_deviceIdLen);
    return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
}

static int access_challenge(uint16_t conn_handle, uint16_t attr_handle,
                             struct ble_gatt_access_ctxt *ctxt, void *arg) {
    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    uint16_t challenge_len = OS_MBUF_PKTLEN(ctxt->om);
    static uint8_t challenge[256];
    if (challenge_len == 0 || challenge_len > sizeof(challenge)) {
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }

    uint16_t copied = 0;
    int rc = ble_hs_mbuf_to_flat(ctxt->om, challenge, sizeof(challenge), &copied);
    if (rc != 0) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    ESP_LOGI(TAG, "Received challenge (%d bytes)", copied);

    Ed25519::sign(signature, g_privateKey, g_publicKey, challenge, copied);

    // Cache this exact challenge so a subsequent ratchet exchange this connection can bind
    // its attestation signature to it (see access_ratchet_pubkey and
    // gatt_svr_clear_challenge_cache).
    memcpy(g_lastChallenge, challenge, copied);
    g_lastChallengeLen = copied;

    // Notify any subscribed central (mirrors the Arduino version's explicit
    // signatureCharacteristic->notify() call after setValue()).
    ble_gatts_chr_updated(signature_val_handle);

    ESP_LOGI(TAG, "Signed and notified.");
    return 0;
}

void gatt_svr_clear_challenge_cache(void) {
    g_lastChallengeLen = 0;
}

static int access_signature(uint16_t conn_handle, uint16_t attr_handle,
                             struct ble_gatt_access_ctxt *ctxt, void *arg) {
    int rc = os_mbuf_append(ctxt->om, signature, sizeof(signature));
    return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
}

// Phone writes its fresh 32-byte X25519 ephemeral public key here; the device runs its
// half of the exchange synchronously (same write-triggers-computation pattern as
// access_challenge above), signs the result with its existing Ed25519 identity key so the
// backend can independently verify it, and makes the whole attestation available via
// RatchetResponse's notify, same as Challenge -> Signature.
static int access_ratchet_pubkey(uint16_t conn_handle, uint16_t attr_handle,
                                  struct ble_gatt_access_ctxt *ctxt, void *arg) {
    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
        return BLE_ATT_ERR_UNLIKELY;
    }
    if (OS_MBUF_PKTLEN(ctxt->om) != 32) {
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }
    if (g_lastChallengeLen == 0) {
        // Enforces the same order the app already uses (sign(challenge:) before
        // runRatchetExchange in AuthViewModel.connectAndAuthenticateDevice) — without a
        // cached challenge there's nothing for the attestation signature to bind to.
        ESP_LOGW(TAG, "Ratchet exchange attempted before a challenge was signed this connection.");
        return BLE_ATT_ERR_UNLIKELY;
    }

    uint8_t phonePublicKey[32];
    uint16_t copied = 0;
    if (ble_hs_mbuf_to_flat(ctxt->om, phonePublicKey, sizeof(phonePublicKey), &copied) != 0 || copied != 32) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    RatchetExchangeResult result;
    if (!ratchet_run_exchange(phonePublicKey, &result)) {
        // X25519 failure (weak point) — extremely unlikely with a random ephemeral key,
        // but fail closed: don't publish a response for this attempt. The phone will see
        // a stale/zeroed characteristic and can retry the whole connection.
        return BLE_ATT_ERR_UNLIKELY;
    }

    // RATCHET_ATTEST_CONTEXT || SHA256(challenge) || devicePublicKey || rc || deviceProof ||
    // nextProof || status — must match backend/auth/ratchet.js's message construction
    // exactly, byte for byte.
    uint8_t challengeHash[32];
    mbedtls_sha256(g_lastChallenge, g_lastChallengeLen, challengeHash, 0 /* SHA-256, not SHA-224 */);

    uint8_t attestMsg[strlen(RATCHET_ATTEST_CONTEXT) + 32 + 32 + 16 + 64 + 32 + 1];
    uint8_t *m = attestMsg;
    memcpy(m, RATCHET_ATTEST_CONTEXT, strlen(RATCHET_ATTEST_CONTEXT)); m += strlen(RATCHET_ATTEST_CONTEXT);
    memcpy(m, challengeHash, sizeof(challengeHash)); m += sizeof(challengeHash);
    memcpy(m, result.devicePublicKey, 32); m += 32;
    memcpy(m, result.rc, 16); m += 16;
    memcpy(m, result.deviceProof, 64); m += 64;
    memcpy(m, result.nextProof, 32); m += 32;
    *m = result.status;

    uint8_t ratchetSig[64];
    Ed25519::sign(ratchetSig, g_privateKey, g_publicKey, attestMsg, sizeof(attestMsg));

    uint8_t *w = ratchet_response_wire;
    memcpy(w, result.devicePublicKey, 32); w += 32;
    memcpy(w, result.rc, 16); w += 16;
    memcpy(w, result.deviceProof, 64); w += 64;
    memcpy(w, result.nextProof, 32); w += 32;
    *w = result.status; w += 1;
    memcpy(w, ratchetSig, 64);

    ble_gatts_chr_updated(ratchet_response_val_handle);
    ESP_LOGI(TAG, "Ratchet exchange complete, attested, and notified.");
    return 0;
}

static int access_ratchet_response(uint16_t conn_handle, uint16_t attr_handle,
                                    struct ble_gatt_access_ctxt *ctxt, void *arg) {
    int rc = os_mbuf_append(ctxt->om, ratchet_response_wire, sizeof(ratchet_response_wire));
    return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
}

static const struct ble_gatt_svc_def gatt_svcs[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &svc_uuid.u,
        .characteristics = (struct ble_gatt_chr_def[]){
            // Every characteristic requires an encrypted (post-pairing) link — _ENC flags,
            // not just the base READ/WRITE ones. Before this, any phone in range could
            // read the public key/device ID and, more seriously, write challenges and get
            // real signatures back with zero authentication. Touching any of these now
            // forces the BLE pairing procedure first (see main.cpp's security config and
            // is_already_bonded_to_someone_else()).
            {
                .uuid = &chr_public_key_uuid.u,
                .access_cb = access_public_key,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC,
            },
            {
                .uuid = &chr_device_id_uuid.u,
                .access_cb = access_device_id,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC,
            },
            {
                .uuid = &chr_challenge_uuid.u,
                .access_cb = access_challenge,
                .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_ENC,
            },
            {
                .uuid = &chr_signature_uuid.u,
                .access_cb = access_signature,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC | BLE_GATT_CHR_F_NOTIFY,
                .val_handle = &signature_val_handle,
            },
            {
                .uuid = &chr_ratchet_pubkey_uuid.u,
                .access_cb = access_ratchet_pubkey,
                .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_ENC,
            },
            {
                .uuid = &chr_ratchet_response_uuid.u,
                .access_cb = access_ratchet_response,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC | BLE_GATT_CHR_F_NOTIFY,
                .val_handle = &ratchet_response_val_handle,
            },
            {
                0, // No more characteristics in this service.
            },
        },
    },
    {
        0, // No more services.
    },
};

void gatt_svr_register_cb(struct ble_gatt_register_ctxt *ctxt, void *arg) {
    char buf[BLE_UUID_STR_LEN];
    switch (ctxt->op) {
        case BLE_GATT_REGISTER_OP_SVC:
            ESP_LOGD(TAG, "registered service %s with handle=%d",
                     ble_uuid_to_str(ctxt->svc.svc_def->uuid, buf), ctxt->svc.handle);
            break;
        case BLE_GATT_REGISTER_OP_CHR:
            ESP_LOGD(TAG, "registering characteristic %s with def_handle=%d val_handle=%d",
                     ble_uuid_to_str(ctxt->chr.chr_def->uuid, buf), ctxt->chr.def_handle,
                     ctxt->chr.val_handle);
            break;
        case BLE_GATT_REGISTER_OP_DSC:
            ESP_LOGD(TAG, "registering descriptor %s with handle=%d",
                     ble_uuid_to_str(ctxt->dsc.dsc_def->uuid, buf), ctxt->dsc.handle);
            break;
        default:
            break;
    }
}

const ble_uuid128_t *physicalkey_service_uuid(void) {
    return &svc_uuid;
}

int gatt_svr_init(void) {
    ble_svc_gap_init();
    ble_svc_gatt_init();

    int rc = ble_gatts_count_cfg(gatt_svcs);
    if (rc != 0) {
        return rc;
    }

    rc = ble_gatts_add_svcs(gatt_svcs);
    if (rc != 0) {
        return rc;
    }

    return 0;
}
