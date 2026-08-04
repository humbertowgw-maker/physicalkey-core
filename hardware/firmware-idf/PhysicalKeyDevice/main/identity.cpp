#include "identity.h"

#include <cstdio>
#include <cstring>

#include "esp_log.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "nvs.h"

#include "Ed25519.h"

static const char *TAG = "identity";

static const uint8_t ED25519_SPKI_PREFIX[12] = {
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
};

uint8_t g_privateKey[32];
uint8_t g_publicKey[32];
uint8_t g_publicKeySPKI[44];
char g_deviceId[40];
size_t g_deviceIdLen;

void loadOrCreateIdentity() {
    nvs_handle_t handle;
    ESP_ERROR_CHECK(nvs_open("physicalkey", NVS_READWRITE, &handle));

    size_t storedLen = sizeof(g_privateKey);
    esp_err_t err = nvs_get_blob(handle, "privkey", g_privateKey, &storedLen);

    if (err == ESP_OK && storedLen == sizeof(g_privateKey)) {
        ESP_LOGI(TAG, "Loaded existing identity from flash.");
    } else {
        // Real hardware TRNG, matching the Arduino version's use of esp_fill_random()
        // rather than the Crypto library's software RNG class (which expects
        // application-registered noise sources).
        esp_fill_random(g_privateKey, sizeof(g_privateKey));
        ESP_ERROR_CHECK(nvs_set_blob(handle, "privkey", g_privateKey, sizeof(g_privateKey)));
        ESP_ERROR_CHECK(nvs_commit(handle));
        ESP_LOGI(TAG, "Generated new identity and saved to flash.");
    }
    nvs_close(handle);

    Ed25519::derivePublicKey(g_publicKey, g_privateKey);
    memcpy(g_publicKeySPKI, ED25519_SPKI_PREFIX, 12);
    memcpy(g_publicKeySPKI + 12, g_publicKey, 32);

    // Chip-derived, not random — a real hardware-unique identifier, matching the
    // product spec's "unique hardware ID" requirement.
    uint8_t mac[6];
    ESP_ERROR_CHECK(esp_efuse_mac_get_default(mac));
    int written = snprintf(g_deviceId, sizeof(g_deviceId),
                            "physicalkey-device-%02x%02x%02x%02x%02x%02x",
                            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    g_deviceIdLen = (size_t)written;

    ESP_LOGI(TAG, "Device ID: %s", g_deviceId);
}
