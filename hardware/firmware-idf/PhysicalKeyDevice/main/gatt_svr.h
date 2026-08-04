#pragma once

#include "host/ble_uuid.h"

struct ble_gatt_register_ctxt;

// Registers the PhysicalKey GATT service (must be called after identity is loaded,
// before ble_hs starts) and initializes the NimBLE GAP/GATT services.
// Returns 0 on success, matching NimBLE's own gatt_svr_init() convention.
int gatt_svr_init(void);

// NimBLE calls this during ble_gatts_start() for each registered svc/chr/dsc.
void gatt_svr_register_cb(struct ble_gatt_register_ctxt *ctxt, void *arg);

// The service UUID, for main.cpp to advertise in the scan-response packet.
const ble_uuid128_t *physicalkey_service_uuid(void);
