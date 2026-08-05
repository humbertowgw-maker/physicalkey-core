#include "ratchet.h"

#include <cstring>

#include "esp_log.h"
#include "esp_random.h"
#include "nvs.h"

#include "Curve25519.h"
#include "Hash.h"
#include "SHA512.h"

static const char *TAG = "ratchet";
static const char *NVS_NAMESPACE = "physicalkey";
static const char *NVS_KEY = "ratchet_next";

// Fixed context string, not a secret — HMAC-SHA512 over an already-high-entropy X25519
// shared secret is a lightweight, sufficient KDF here (equivalent in spirit to
// HKDF-Expand alone, appropriate when the input keying material already has full
// entropy, which a 256-bit ECDH output does).
static const char *NEXT_PROOF_CONTEXT = "physicalkey-ratchet-next-v1";

static bool load_prior_proof(uint8_t out[32]) {
    nvs_handle_t handle;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle) != ESP_OK) {
        return false; // namespace not created yet == nothing stored yet, not an error
    }
    size_t len = 32;
    esp_err_t err = nvs_get_blob(handle, NVS_KEY, out, &len);
    nvs_close(handle);
    return err == ESP_OK && len == 32;
}

static void store_next_proof(const uint8_t proof[32]) {
    nvs_handle_t handle;
    ESP_ERROR_CHECK(nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle));
    ESP_ERROR_CHECK(nvs_set_blob(handle, NVS_KEY, proof, 32));
    ESP_ERROR_CHECK(nvs_commit(handle));
    nvs_close(handle);
}

bool ratchet_run_exchange(const uint8_t phonePublicKey[32], RatchetExchangeResult *out) {
    uint8_t devicePrivateKey[32];
    esp_fill_random(devicePrivateKey, sizeof(devicePrivateKey));
    // dh1 clamps devicePrivateKey in place and writes the corresponding public key.
    Curve25519::dh1(out->devicePublicKey, devicePrivateKey);

    uint8_t sharedSecret[32];
    memcpy(sharedSecret, phonePublicKey, 32);
    // dh2 overwrites sharedSecret with the X25519 result; returns false on a weak point.
    bool ok = Curve25519::dh2(sharedSecret, devicePrivateKey);
    memset(devicePrivateKey, 0, sizeof(devicePrivateKey)); // ephemeral — never persisted

    if (!ok) {
        ESP_LOGW(TAG, "X25519 exchange failed (weak point) — leaving ratchet state untouched");
        memset(sharedSecret, 0, sizeof(sharedSecret));
        return false;
    }

    uint8_t priorProof[32];
    bool hadPriorState = load_prior_proof(priorProof);

    if (hadPriorState) {
        esp_fill_random(out->rc, sizeof(out->rc));
        hmac<SHA512>(out->deviceProof, sizeof(out->deviceProof), priorProof, sizeof(priorProof), out->rc, sizeof(out->rc));
        out->status = 1;
        ESP_LOGI(TAG, "Ratchet exchange: prior state found, offering proof");
    } else {
        memset(out->rc, 0, sizeof(out->rc));
        memset(out->deviceProof, 0, sizeof(out->deviceProof));
        out->status = 0;
        ESP_LOGI(TAG, "Ratchet exchange: no prior state (bootstrap)");
    }

    uint8_t nextProof[32];
    hmac<SHA512>(nextProof, sizeof(nextProof), sharedSecret, sizeof(sharedSecret), NEXT_PROOF_CONTEXT, strlen(NEXT_PROOF_CONTEXT));
    memset(sharedSecret, 0, sizeof(sharedSecret));

    store_next_proof(nextProof);
    ESP_LOGI(TAG, "Ratchet state advanced for the next session.");

    return true;
}
