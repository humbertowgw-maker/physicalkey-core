// PhysicalKey IoT key fob firmware — ESP32, ESP-IDF/NimBLE.
//
// This is a from-scratch port of ../../firmware/PhysicalKeyDevice (the Arduino version),
// not a fix to it. That Arduino build never once ran on this hardware — even a completely
// empty setup()/loop() crashed identically on 2 physical boards, both bundled Arduino-ESP32
// core versions, every flash/CPU-frequency combination we tried, and a totally fresh
// isolated toolchain reinstall — while ESP-IDF's own hello_world ran perfectly on the exact
// same board. That, plus a matching unresolved upstream report
// (espressif/arduino-esp32#8349, "ESP32-D0WD-V3 not starting, old ESP32-D0WDQ6 works"),
// points at a real Arduino-core-vs-this-silicon-revision incompatibility, not our code, our
// cables, our power, or this chip being defective. See ../README.md for the full
// investigation. Building directly on ESP-IDF sidesteps the broken layer entirely.
//
// Holds an Ed25519 identity (generated once on first boot, persisted in NVS flash — see
// identity.cpp) and exposes it over BLE (see gatt_svr.cpp) so a paired phone can complete
// the "device" stage of the PhysicalKey auth flow: read this device's public key + deviceId
// once (for backend registration), then for each auth attempt, write the backend-issued
// challenge and read back a signature. Same GATT UUIDs, same wire format, same Ed25519
// library as the Arduino version, so the phone app (../../mobile/ios) needs no changes.

#include <cstring>

#include "esp_log.h"
#include "nvs_flash.h"

#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "host/ble_store.h"
#include "services/gap/ble_svc_gap.h"
#include "store/config/ble_store_config.h"

#include "host/ble_uuid.h"
#include "gatt_svr.h"
#include "identity.h"

static const char *TAG = "physicalkey";
static uint8_t own_addr_type;

static void start_advertising(void);

// This board bonds with exactly one phone, permanently, matching the same
// trust-on-first-use model already used for backend device registration and the phone's
// own deviceId: the first phone to pair with a freshly-flashed board owns it from then on.
// Any other peer that completes a connection gets immediately dropped, before it can even
// attempt pairing — so a second phone can't silently steal/share a board that's already
// claimed. Compares peer *identity* addresses (not the connection address), which is why
// IRK exchange is requested in the security config below — iOS centrals normally connect
// with a rotating resolvable private address, and without the IRK, NimBLE couldn't tell
// two connections from the same already-bonded phone apart from a stranger's.
static bool is_already_bonded_to_someone_else(uint16_t conn_handle) {
    ble_addr_t bonded_peer;
    int num_bonded = 0;
    if (ble_store_util_bonded_peers(&bonded_peer, &num_bonded, 1) != 0 || num_bonded == 0) {
        return false; // no existing bond yet — this connection is free to become the first
    }

    struct ble_gap_conn_desc desc;
    if (ble_gap_conn_find(conn_handle, &desc) != 0) {
        return true; // can't identify the peer — fail closed
    }

    return desc.peer_id_addr.type != bonded_peer.type ||
           memcmp(desc.peer_id_addr.val, bonded_peer.val, sizeof(bonded_peer.val)) != 0;
}

static int gap_event_handler(struct ble_gap_event *event, void *arg) {
    switch (event->type) {
        case BLE_GAP_EVENT_CONNECT:
            ESP_LOGI(TAG, "connection %s; status=%d",
                     event->connect.status == 0 ? "established" : "failed",
                     event->connect.status);
            if (event->connect.status != 0) {
                start_advertising();
                return 0;
            }
            if (is_already_bonded_to_someone_else(event->connect.conn_handle)) {
                ESP_LOGW(TAG, "Rejecting connection — this device is already paired with another phone.");
                ble_gap_terminate(event->connect.conn_handle, BLE_ERR_REM_USER_CONN_TERM);
            }
            return 0;

        case BLE_GAP_EVENT_DISCONNECT:
            ESP_LOGI(TAG, "disconnect; reason=%d", event->disconnect.reason);
            start_advertising();
            return 0;

        case BLE_GAP_EVENT_ADV_COMPLETE:
            start_advertising();
            return 0;

        case BLE_GAP_EVENT_SUBSCRIBE:
            ESP_LOGI(TAG, "subscribe event; cur_notify=%d", event->subscribe.cur_notify);
            return 0;

        case BLE_GAP_EVENT_MTU:
            ESP_LOGI(TAG, "mtu update event; mtu=%d", event->mtu.value);
            return 0;

        case BLE_GAP_EVENT_ENC_CHANGE:
            ESP_LOGI(TAG, "encryption change event; status=%d", event->enc_change.status);
            return 0;

        case BLE_GAP_EVENT_REPEAT_PAIRING: {
            // The already-bonded phone is pairing again (e.g. it lost its own copy of the
            // bond — app reinstall, etc.). Since is_already_bonded_to_someone_else() already
            // gates connections to that one phone, this can only be the legitimate owner, so
            // it's safe to drop the stale bond and let pairing proceed rather than reject it.
            struct ble_gap_conn_desc desc;
            if (ble_gap_conn_find(event->repeat_pairing.conn_handle, &desc) == 0) {
                ble_store_util_delete_peer(&desc.peer_id_addr);
            }
            return BLE_GAP_REPEAT_PAIRING_RETRY;
        }

        default:
            return 0;
    }
}

// Advertised name deliberately short and generic, NOT the full deviceId
// ("physicalkey-device-<12 hex chars>") — combined with our 128-bit custom service UUID,
// that would overflow BLE's 31-byte legacy advertising packet (same issue documented in
// the old Arduino firmware). The service UUID goes in the separate scan-response packet
// (its own 31-byte budget) rather than the main packet, which only needs flags + name.
// The full unique deviceId is still available via the Device ID characteristic once
// connected.
static void start_advertising(void) {
    struct ble_hs_adv_fields fields;
    memset(&fields, 0, sizeof(fields));
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;

    const char *name = ble_svc_gap_device_name();
    fields.name = (uint8_t *)name;
    fields.name_len = strlen(name);
    fields.name_is_complete = 1;

    int rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "error setting advertisement data; rc=%d", rc);
        return;
    }

    struct ble_hs_adv_fields rsp_fields;
    memset(&rsp_fields, 0, sizeof(rsp_fields));
    rsp_fields.uuids128 = physicalkey_service_uuid();
    rsp_fields.num_uuids128 = 1;
    rsp_fields.uuids128_is_complete = 1;

    rc = ble_gap_adv_rsp_set_fields(&rsp_fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "error setting scan response data; rc=%d", rc);
        return;
    }

    struct ble_gap_adv_params adv_params;
    memset(&adv_params, 0, sizeof(adv_params));
    adv_params.conn_mode = BLE_GAP_CONN_MODE_UND;
    adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;
    rc = ble_gap_adv_start(own_addr_type, NULL, BLE_HS_FOREVER, &adv_params,
                            gap_event_handler, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "error enabling advertisement; rc=%d", rc);
        return;
    }

    ESP_LOGI(TAG, "BLE advertising started.");
}

static void on_reset(int reason) {
    ESP_LOGE(TAG, "Resetting state; reason=%d", reason);
}

static void on_sync(void) {
    int rc = ble_hs_util_ensure_addr(0);
    assert(rc == 0);

    rc = ble_hs_id_infer_auto(0, &own_addr_type);
    if (rc != 0) {
        ESP_LOGE(TAG, "error determining address type; rc=%d", rc);
        return;
    }

    start_advertising();
}

static void host_task(void *param) {
    nimble_port_run();
    nimble_port_freertos_deinit();
}

extern "C" void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    loadOrCreateIdentity();

    ret = nimble_port_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to init nimble: %d", ret);
        return;
    }

    ble_hs_cfg.reset_cb = on_reset;
    ble_hs_cfg.sync_cb = on_sync;
    ble_hs_cfg.gatts_register_cb = gatt_svr_register_cb;
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;
    // NimBLE's NVS-backed bond store (persists LTKs/IRKs across reboots) — this component
    // only exposes the raw read/write/delete callbacks, no init() wrapper, unlike the
    // convenience one the bleprph example vendors in as a separate local component.
    ble_hs_cfg.store_read_cb = ble_store_config_read;
    ble_hs_cfg.store_write_cb = ble_store_config_write;
    ble_hs_cfg.store_delete_cb = ble_store_config_delete;

    // No display or keyboard on this board, so Just Works is the only pairing method
    // available — it protects against passive eavesdropping and silent drive-by GATT
    // access (the actual gap being closed here), but not against an active
    // machine-in-the-middle at pairing time itself. sm_sc (LE Secure Connections) is what
    // makes that pairing cryptographically strong rather than the old, weaker legacy
    // method; combined with is_already_bonded_to_someone_else() above, a board can only
    // ever be claimed by one phone, once.
    ble_hs_cfg.sm_io_cap = BLE_SM_IO_CAP_NO_IO;
    ble_hs_cfg.sm_bonding = 1;
    ble_hs_cfg.sm_mitm = 0;
    ble_hs_cfg.sm_sc = 1;
    ble_hs_cfg.sm_our_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
    ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;

    int rc = gatt_svr_init();
    assert(rc == 0);

    ble_svc_gap_device_name_set("PhysicalKey");

    nimble_port_freertos_init(host_task);
}
