#include "ratchet.h"
#include "ratchet_core.h"

#include <cstring>

#include "esp_log.h"
#include "esp_random.h"
#include "nvs.h"

static const char *TAG = "ratchet";
static const char *NVS_NAMESPACE = "physicalkey";
static const char *NVS_KEY = "ratchet_next";

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

// Thin hardware-facing wrapper: real ESP32 randomness in, real NVS persistence out. All
// the actual X25519/HMAC math this used to contain directly now lives in ratchet_core.cpp
// — a pure function with no ESP-IDF dependency, so it can be compiled and tested on the
// host (see host-tests/). This function's own job is now just wiring hardware to that.
bool ratchet_run_exchange(const uint8_t phonePublicKey[32], RatchetExchangeResult *out) {
    uint8_t priorProof[32];
    bool hadPriorState = load_prior_proof(priorProof);

    uint8_t rc[16];
    if (hadPriorState) {
        esp_fill_random(rc, sizeof(rc));
    } else {
        memset(rc, 0, sizeof(rc));
    }

    bool ok = ratchet_derive(phonePublicKey, priorProof, hadPriorState, rc, out);

    if (!ok) {
        ESP_LOGW(TAG, "X25519 exchange failed (weak point) — leaving ratchet state untouched");
        return false;
    }

    if (hadPriorState) {
        ESP_LOGI(TAG, "Ratchet exchange: prior state found, offering proof");
    } else {
        ESP_LOGI(TAG, "Ratchet exchange: no prior state (bootstrap)");
    }

    store_next_proof(out->nextProof);
    ESP_LOGI(TAG, "Ratchet state advanced for the next session.");

    return true;
}
