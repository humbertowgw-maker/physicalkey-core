// BLE pairing passkey: a 6-digit number unique to this physical unit, generated once on
// first boot and persisted in NVS — same trust-on-first-use-then-permanent pattern as the
// Ed25519 identity in identity.cpp.
//
// Why this exists: Just Works pairing (the previous configuration) encrypts the link but
// proves nothing about *who* you paired with — an attacker's BLE radio in range at the
// exact moment of first pairing could complete the handshake with each side instead of
// letting them complete it with each other. Passkey Entry closes that gap by requiring the
// phone's owner to type in a number that only exists printed on the physical unit itself;
// an attacker relaying the pairing traffic can't also fake knowing that.
//
// This board has no screen, so it can't literally display the passkey NimBLE's
// DISP_ONLY io-capability implies — instead, the value is generated once, logged loudly to
// the serial console on that first boot (see pairing.cpp), and must be written on the
// unit's enclosure/label during provisioning, before it ships. There is deliberately no
// other way to retrieve it later.
#pragma once

#include <cstdint>

// Loads the stored passkey from NVS, or generates and persists a new one (logging it) on
// first boot. Returns a value in [0, 999999].
uint32_t loadOrCreatePairingPasskey();
