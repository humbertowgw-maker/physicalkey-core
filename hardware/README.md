# PhysicalKey IoT Key Fob Firmware

## Current state: real BLE GATT server, running and verified on physical hardware

- **`firmware-idf/PhysicalKeyDevice/`** — the firmware that's actually running, built
  directly on ESP-IDF (NimBLE), not Arduino. See "Why ESP-IDF, not Arduino" below for why
  this replaced the Arduino build. Verified on the physical board, end to end, via a
  Python/`bleak` BLE client standing in for the phone:
  - Boots cleanly, no crash, from a completely fresh flash.
  - Advertises as `PhysicalKey` with the correct 128-bit service UUID
    (`b16a3c00-2c1e-4a7a-9b7a-0a1c2d3e4f50`) — confirmed via an independent BLE scan.
  - GATT connect + read public key (44-byte SPKI DER) + read device ID + write a
    challenge + receive the 64-byte Ed25519 signature via notify, all worked.
  - The signature was independently verified against the public key using Node's
    `crypto.verify()` (Ed25519) — **cryptographically valid**, not just "bytes came
    back."
  - Identity (private key) persists across reboots via NVS, generated once from the
    hardware RNG (`esp_fill_random`), matching the trust-on-first-use model the backend
    expects.
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

## What's NOT done yet

- **Not yet paired with the real iOS app.** Verified against a Python/`bleak` BLE client
  standing in for the phone — the actual `DeviceBluetoothManager.swift` code has never
  connected to a real board. Protocol match is byte-for-byte identical (same UUIDs, same
  read/write/notify semantics), so this should work, but "should" isn't "verified" —
  next real step.
- **Private key is not encrypted at rest.** Stored via NVS in plain form. ESP32 supports
  flash encryption + NVS encryption, but enabling it burns security eFuses — an
  irreversible, physical-device operation requiring your explicit go-ahead on a real
  board, not done blind.
- **No BLE-level pairing/bonding/encryption.** The GATT service currently accepts
  unauthenticated connections. Fine for getting the crypto flow working; not what you'd
  want for a real security product without hardening.
- **Two boards from this session may be running stale test firmware** (`BlinkTest`,
  `MinimalBLETest`, `WiFiRadioTest` — all from the crash investigation) rather than
  `PhysicalKeyDevice` — only the board actively used for the tests above is confirmed
  running the real firmware.

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

1. **Pair with the real iOS app.** Open the app, connect to the board, run the actual
   create-identity + Face ID auth flow end to end (phone ↔ device ↔ backend) — the first
   genuine full-stack test.
2. **Decide on flash encryption** before treating this as anything beyond a working demo.
3. **Add BLE bonding/encryption** if this is going past a demo.
