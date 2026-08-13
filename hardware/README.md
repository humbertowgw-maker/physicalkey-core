# PhysicalKey IoT Key Fob Firmware

**License: MIT** (see [LICENSE](./LICENSE)) — different from the rest of this repository,
which is Business Source License 1.1. Everything under `hardware/` is fully open: build
your own board, flash it, modify it, sell boards built from it, no restriction.

## Current state: real BLE GATT server, real security, running and verified on physical hardware

- **`firmware-idf/PhysicalKeyDevice/`** — the firmware that's actually running, built
  directly on ESP-IDF (NimBLE), not Arduino. See "Why ESP-IDF, not Arduino" below for why
  this replaced the Arduino build. Verified on all 3 physical boards, end to end, with
  both a Python/`bleak` BLE client and the real iOS app:
  - Boots cleanly, no crash, from a completely fresh flash, and survives reboots.
  - Advertises as `PhysicalKey` with the correct 128-bit service UUID
    (`b16a3c00-2c1e-4a7a-9b7a-0a1c2d3e4f50`) — confirmed via an independent BLE scan.
  - GATT connect + read public key (44-byte SPKI DER) + read device ID + write a
    challenge + receive the 64-byte Ed25519 signature via notify, all worked.
  - The signature was independently verified against the public key using Node's
    `crypto.verify()` (Ed25519) — **cryptographically valid**, not just "bytes came
    back."
  - **Paired with the real iOS app** (`mobile/ios/PhysicalKey/DeviceBluetoothManager.swift`)
    — the full phone ↔ device ↔ backend flow, not just a bleak stand-in.
  - **BLE is locked down**: every characteristic requires an encrypted (paired) link —
    LE Secure Connections with Passkey Entry (this board has no display, so it can't
    literally show a passkey — instead a per-unit passkey is generated once on first
    boot, logged to console, and must be written on the unit's enclosure/label during
    provisioning; NimBLE's `DISP_ONLY` io-capability + `sm_mitm=1` prompts the phone's
    owner to type it in during pairing — see `main/pairing.cpp`). This closes the actual
    gap Just Works had: an attacker relaying the pairing handshake can't also fake
    knowing a number that only exists printed on the physical unit. Each board still
    permanently bonds to the first phone that pairs with it; any other peer's connection
    gets rejected outright. Before any of this, any phone in range could read data and
    trigger real signatures with zero authentication.
  - **Flash encryption (Development Mode) + NVS encryption are enabled.** The Ed25519
    private key is genuinely encrypted at rest now — confirmed via the boot log's
    `NVS partition "nvs" is encrypted.` line, not just assumed from the Kconfig option
    being set. Development Mode means USB/serial reflashing still works normally
    (Release Mode would permanently disable that, and there's no OTA update mechanism
    to fall back on yet). See "Flash + NVS encryption" below for why plain flash
    encryption alone wouldn't have been enough.
  - Device ID is derived from the chip's real eFuse MAC
    (`physicalkey-device-<12 hex chars>`), not randomly generated.

- **`firmware-crypto-poc/`** — a native command-line tool that compiles and *runs* the
  exact Ed25519 library the firmware uses (Rhys Weatherley's arduinolibs `Crypto`
  library, vendored into `firmware-idf/PhysicalKeyDevice/components/ed25519/` — same
  `Ed25519::derivePublicKey()` / `Ed25519::sign()` calls, unmodified) and proves it
  against the **live production backend**. Superseded as the primary proof now that the
  real firmware itself has been verified on hardware, but still useful for quick native
  iteration on the crypto path without a board attached.

- **`firmware/PhysicalKeyDevice/PhysicalKeyDevice.ino`** — the original Arduino build.
  **Kept for reference only — do not use.** See below.

## Why ESP-IDF, not Arduino

The Arduino version never ran on this hardware. Not "BLE didn't work" — nothing did, not
even a completely empty `setup(){}`/`loop(){}`. It crashed identically
(`Guru Meditation Error: Core 1 panic'ed (Double exception)`, `EXCCAUSE: IllegalInstruction`,
fault inside the Xtensa register-window-spill routine `_xt_context_save`, the instant
`setup()` makes its first call) across:

- 2 different physical ESP32 boards
- Arduino-ESP32 core versions 2.0.17 and 3.3.11
- Every flash mode/frequency and CPU frequency combination tried (including the
  conservative DIO/40MHz/80MHz corner)
- A completely fresh, isolated `arduino-cli` install (new data directory, freshly
  downloaded core, untouched by anything else on this Mac) — byte-identical crash,
  ruling out a corrupted local toolchain

Meanwhile, Espressif's own `esp-idf` `hello_world` example ran perfectly on the exact
same board — clean boot, correct chip info (`ESP32-D0WD-V3`, revision v3.1, genuine
silicon per `esptool`), repeated boot cycles, zero crashes. That isolated the fault to
the Arduino core's startup path specifically, not the chip, the board, the cables, the
power, or this Mac's build tools.

This matches a known, unresolved upstream report:
[espressif/arduino-esp32#8349](https://github.com/espressif/arduino-esp32/issues/8349)
("ESP32-D0WD-V3 not starting, old ESP32-D0WDQ6 works"), closed unfixed with a second
independent user confirming the same symptom. Newer ESP32-D0WD-V3 silicon (this board's
revision) appears to be genuinely incompatible with the Arduino-ESP32 core's boot
sequence in a way Espressif never resolved.

Given ESP-IDF itself is proven to work on this exact chip, the firmware was ported
directly to ESP-IDF/NimBLE rather than continuing to chase the Arduino core. Same GATT
UUIDs, same wire protocol, same vendored Ed25519 library — the phone app
(`mobile/ios/PhysicalKey/DeviceBluetoothManager.swift`) needs no changes.

## Flash + NVS encryption

Enabling flash encryption alone does **not** protect the private key — this is a real,
documented ESP-IDF limitation, not an oversight: the NVS partition is specifically
excluded from flash encryption's coverage, so data written via `nvs_set_blob()` (exactly
how `identity.cpp` stores the private key) stays in plaintext regardless of flash
encryption being on. Actually protecting it requires the separate **NVS Encryption**
feature on top.

NVS Encryption needs a key-protection scheme. The obvious choice — deriving keys from the
chip's HMAC peripheral, which doesn't require flash encryption at all — **isn't available
on this hardware**: the original ESP32 (this board's chip) has no HMAC peripheral; that's
S2/S3/C3-and-newer only. The only scheme available here (`NVS_SEC_KEY_PROTECT_USING_FLASH_ENC`)
stores the NVS encryption keys in a dedicated `nvs_keys` partition that's itself protected
by flash encryption — so flash encryption ends up required as a dependency of NVS
encryption on this chip, not because the whole flash needed protecting for its own sake.

Practical fallout of enabling this:
- Custom partition table (`partitions_secure.csv`) adds the `nvs_keys` partition.
- Bootloader grew past the default partition-table offset's size budget (a known,
  common ESP-IDF flash-encryption gotcha) — fixed by moving
  `CONFIG_PARTITION_TABLE_OFFSET` from `0x8000` to `0x10000`.
- Enabling this on an already-flashed board requires a full chip erase first — old
  plaintext NVS entries aren't in the format NVS Encryption expects, so identity and any
  existing BLE bond reset and need re-pairing.
- **The backend also needs telling.** A board's `deviceId` is derived from its fixed
  eFuse MAC, so it stays the same across the erase — but its Ed25519 identity doesn't.
  The backend locks in the first key it ever sees per deviceId (trust-on-first-use) and
  never updates it, so after an erase, re-pairing over Bluetooth will succeed but the
  *backend* auth step will keep failing ("Device verification failed") until that
  deviceId's stale registration is reset — `DELETE /admin/identities/:deviceId` (admin
  auth required). See `SETUP_COMPLETE.md`'s "Trust-on-first-use lockouts" section for
  the full story and exact usage. Same applies to a phone if its Keychain identity ever
  gets recreated.
- **Any phone that had already Bluetooth-paired with a board before the erase needs a
  one-time manual re-pair**, same underlying reason as the backend registration above:
  the erase wipes the board's BLE bond storage (its identity/IRK), so the phone's saved
  pairing key no longer matches. Symptom: pairs, but then fails/needs to be forgotten
  and re-paired once (iOS: Settings → Bluetooth → the device's (i) button → "Forget This
  Device"). One-time only — after that re-pair, reconnecting works normally, no
  recurring issue.
- Development Mode was chosen over Release Mode deliberately: Release Mode additionally
  and permanently disables USB/serial reflashing, which would brick the update path for
  this actively-developed project with no OTA system built yet.

All 3 physical boards now have flash + NVS encryption applied and verified (clean
bring-up, `NVS partition "nvs" is encrypted.` in each boot log, survives a reboot with
identity intact). Each got a fresh identity as part of the required erase, so each needs
(re-)pairing with a phone before use.

## Automated tests

`host-tests/` (added 2026-08-10) — the session-ratchet's real crypto/protocol logic
(`main/ratchet_core.cpp`), compiled and run natively on the dev machine, no board or
ESP-IDF toolchain needed:

```bash
cd hardware/firmware-idf/PhysicalKeyDevice/host-tests
./run.sh
```

Links the exact same vendored `Curve25519.cpp`/`SHA512.cpp`/`Hash.cpp`/`Crypto.cpp` the
real board uses — proves the phone and device sides of the X25519 exchange genuinely
agree on a shared secret, the continuity proof chains correctly across sessions, and a
known-weak X25519 point is rejected. See `host-tests/README.md` for what this can and
can't cover (most of the firmware — BLE, GATT, NVS — still needs real hardware) and a
real small bug it caught while being written (a wasted `esp_fill_random()` call that
`Curve25519::dh1()` was silently discarding).

## What's NOT done yet

- **Boards not yet tested against multiple independent phones as separate real users.**
  Single-bond-per-board enforcement (see above) is verified by code review and by
  confirming a *second* connection attempt gets rejected in principle, but not yet by
  actually pairing two different physical phones against the same board one after another.

## Building it yourself

This firmware and hardware design are MIT-licensed specifically so you can do this — build
a board, verify it yourself, modify it, even sell boards built from it. Everything below is
real and tested against physical hardware, not aspirational.

### What you need

- **An original ESP32 chip** (the `ESP32-D0WD-V3` this project was built and verified
  against, or another ESP32-family board — **not S2/S3/C3**: the NVS encryption scheme this
  firmware uses depends on a key-protection path that's specific to the original ESP32; see
  "Flash + NVS encryption" above for why). Any dev board carrying that chip works — this
  firmware doesn't need anything beyond the bare chip, no extra components wired in.
- *(TODO — Humberto: drop in the actual Alibaba/AliExpress listing and part number you're
  sourcing from once you've picked one, so this is a real link instead of a placeholder.)*
- ESP-IDF v5.3.1 (a multi-GB external toolchain, same as Xcode or Android Studio — not part
  of this repo). `source <path-to-esp-idf>/export.sh` before any `idf.py` command below.

### Flash it

```bash
source <path-to-esp-idf>/export.sh
cd hardware/firmware-idf/PhysicalKeyDevice
idf.py set-target esp32
idf.py -p <your-serial-port> build encrypted-flash monitor
```

**Always `encrypted-flash`, never plain `flash`.** This firmware ships with flash + NVS
encryption on (see "Flash + NVS encryption" above) — plain `idf.py flash` on a chip that
already has (or is enabling) encryption writes a plaintext image the bootloader can't read,
which boot-loops the board (`RTCWDT_RTC_RESET`, repeating `invalid header` errors). It looks
alarming but is recoverable — just re-run with `encrypted-flash`. This has bitten this
project's own team more than once; don't repeat it.

On first boot, the console prints a random 6-digit pairing passkey
(`NEW PAIRING PASSKEY: XXXXXX`) — write that down (and on the physical unit, if you're
building more than one) before you close the serial monitor. You'll need it once, the first
time a phone pairs with this specific board.

### Pairing it with the app — read this before you try

The device generates its own identity (an Ed25519 keypair, derived from and bound to the
chip's real eFuse MAC) the first time it boots — nothing to configure, nothing the app sends
it. The **first phone that ever pairs with a given board becomes its owner**
(trust-on-first-use); pairing is `main/pairing.cpp`'s passkey flow, not "Just Works" — enter
the 6-digit code from the boot log when your phone prompts for it.

If you're pointing the app at **your own self-hosted backend** (see
`backend/SELF_HOSTING.md`), this just works — trust-on-first-use is the default, no
allow-list.

If you're pointing the app at **PhysicalKey's own hosted backend**, know that it runs with
`ENFORCE_DEVICE_ALLOWLIST=true` — a self-built board's `deviceId` (printed in the boot log
as `physicalkey-device-<12 hex chars from your chip's MAC>`) needs to be added to that
allow-list before it can register at all, or pairing will fail with a generic "Device
verification failed" and no further explanation (deliberately generic — see
`auth/device-allowlist.js`'s comments for why). That's an admin action on Humberto's end,
not something you can do yourself against the hosted service.

## Next real steps, in order

1. **Board `...0684c`'s first-ever pairing is confirmed working end-to-end (2026-08-12)** —
   passkey pairing → device signs the backend's challenge → ratchet check → real git
   credentials issued, verified live via the on-device log. The other two boards
   (`...03c9c`, `...00800`) needed re-pairing after the same encryption migration reset
   their bonds — not yet reconfirmed since; don't assume they're paired without checking.
2. **A second, independent phone rejecting a board it was never paired to** — a deliberate
   later test (per Humberto), not an open bug. The single-bond-per-board rejection is
   verified by code review; actually exercising it with two real phones against the same
   board is still open.
