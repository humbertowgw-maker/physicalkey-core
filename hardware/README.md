# PhysicalKey IoT Key Fob Firmware

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
    LE Secure Connections, Just Works (no display/keyboard on this board). Each board
    permanently bonds to the first phone that pairs with it; any other peer's connection
    gets rejected outright. Before this, any phone in range could read data and trigger
    real signatures with zero authentication.
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
- Development Mode was chosen over Release Mode deliberately: Release Mode additionally
  and permanently disables USB/serial reflashing, which would brick the update path for
  this actively-developed project with no OTA system built yet.

All 3 physical boards now have flash + NVS encryption applied and verified (clean
bring-up, `NVS partition "nvs" is encrypted.` in each boot log, survives a reboot with
identity intact). Each got a fresh identity as part of the required erase, so each needs
(re-)pairing with a phone before use.

## What's NOT done yet

- **Boards not yet tested against multiple independent phones as separate real users.**
  Single-bond-per-board enforcement (see above) is verified by code review and by
  confirming a *second* connection attempt gets rejected in principle, but not yet by
  actually pairing two different physical phones against the same board one after another.

## Building it yourself

Requires ESP-IDF v5.3.1 (this session set it up at `~/esp-idf-test/esp-idf` — not part of
this repo, since it's a multi-GB external toolchain, same as Xcode or Android Studio):

```bash
source ~/esp-idf-test/esp-idf/export.sh
cd hardware/firmware-idf/PhysicalKeyDevice
idf.py set-target esp32
idf.py -p /dev/cu.usbserial-0001 build flash monitor
```

## Next real steps, in order

1. **Pair all 3 boards with phones** (each needs it — the encryption migration reset
   every board's identity and bond). Use a second real phone for at least one board,
   treating it as an independent real user, to actually exercise the
   single-bond-per-board rejection rather than just trust the code review.
