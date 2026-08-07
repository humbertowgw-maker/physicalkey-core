#include "pairing.h"

#include "esp_log.h"
#include "esp_random.h"
#include "nvs.h"

static const char *TAG = "pairing";

uint32_t loadOrCreatePairingPasskey() {
    nvs_handle_t handle;
    ESP_ERROR_CHECK(nvs_open("physicalkey", NVS_READWRITE, &handle));

    uint32_t passkey = 0;
    esp_err_t err = nvs_get_u32(handle, "passkey", &passkey);

    if (err == ESP_OK && passkey <= 999999) {
        ESP_LOGI(TAG, "Loaded existing pairing passkey from flash.");
    } else {
        // BLE passkeys are a 6-digit decimal number, 000000-999999. esp_fill_random()
        // then modulo keeps every value in range; the tiny bias from 2^32 not being an
        // exact multiple of 1,000,000 doesn't matter here — this is a label value, not
        // cryptographic key material in its own right.
        uint32_t raw;
        esp_fill_random(&raw, sizeof(raw));
        passkey = raw % 1000000u;
        ESP_ERROR_CHECK(nvs_set_u32(handle, "passkey", passkey));
        ESP_ERROR_CHECK(nvs_commit(handle));

        // Deliberately loud and hard to miss during `idf.py flash monitor` — this is the
        // ONE moment this value is ever visible. Write it on the unit before it ships;
        // there is no admin endpoint or log that recovers it later by design.
        ESP_LOGW(TAG, "========================================");
        ESP_LOGW(TAG, "  NEW PAIRING PASSKEY: %06lu", (unsigned long)passkey);
        ESP_LOGW(TAG, "  Write this on the unit before shipping.");
        ESP_LOGW(TAG, "========================================");
    }

    nvs_close(handle);
    return passkey;
}
