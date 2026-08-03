# PhysicalKey IoT Key Fob Firmware

## What's actually real here

- **`firmware-crypto-poc/`** — a native command-line tool that compiles and *runs* the
  exact Ed25519 library the firmware uses (Rhys Weatherley's arduinolibs `Crypto`
  library — `Ed25519::derivePublicKey()` / `Ed25519::sign()`, unmodified) and proves it
  against the **live production backend**: real phone + device signatures accepted
  end-to-end, a forged signature correctly rejected. This is the same kind of proof as
  `mobile/ios-crypto-poc` — the thing most likely to be silently wrong (does this specific
  embedded crypto implementation actually produce output the backend accepts?) is verified,
  not assumed. Run it yourself:
  ```bash
  cd hardware/firmware-crypto-poc
  clang++ -std=c++17 -I ~/Documents/Arduino/libraries/Crypto/src main.cpp rng_stub.cpp \
    ~/Documents/Arduino/libraries/Crypto/src/{Ed25519,Curve25519,BigNumberUtil,SHA512,Crypto,Hash}.cpp \
    -o firmware-crypto-poc
  node test-against-backend.js
  ```

- **`firmware/PhysicalKeyDevice/PhysicalKeyDevice.ino`** — the actual ESP32 firmware.
  **Compiles cleanly against the real ESP32 Arduino toolchain** (`arduino-cli compile
  --fqbn esp32:esp32:esp32`, core 3.3.11 — 1.1MB flash / 83%, 41KB RAM / 12%), using real
  APIs: `BLEDevice`/`BLEServer`/`BLECharacteristic` for Bluetooth, `Preferences` for flash
  storage, `esp_fill_random()` for the hardware RNG, `ESP.getEfuseMac()` for a real
  chip-unique device ID, and the same `Ed25519::` calls proven above.

## What's NOT real / not done

- **Never run on physical hardware.** There's no ESP32 board attached to this machine —
  compilation is the strongest verification possible without one. BLE pairing, flash
  persistence across power cycles, and the actual signing-on-write behavior are all
  untested beyond "the code that does this compiles correctly."
- **No phone-side Bluetooth code exists yet.** The iOS app (`mobile/ios/`) doesn't talk
  BLE to anything — `PhysicalKeyAPI.deviceVerify()` there is still a stub. This firmware
  defines the GATT protocol (service/characteristic UUIDs, read/write semantics — see
  comments at the top of the `.ino` file) that the phone app would need to implement
  against, but nothing on the phone side speaks it yet.
- **Private key is not encrypted at rest.** It's stored via `Preferences` (NVS) in plain
  form. ESP32 supports flash encryption + NVS encryption as a hardware feature, but
  enabling it means burning security eFuses — an irreversible, physical-device operation
  I'm not going to do blind without a real board and your explicit go-ahead. Until that's
  set up, anyone with physical/USB access to a flashed device could plausibly extract the
  private key from flash. Worth knowing given the product's "hardware-bound, unbreakable"
  framing — right now that's true against remote/software attackers, not against someone
  who has the physical fob and the right tools.
- **No Bluetooth proximity/pairing security configured** (bonding, encryption, MITM
  protection) — the BLE service currently accepts unauthenticated connections. Fine for
  getting the crypto flow working; not what you'd want for a real security product without
  hardening.

## Environment note (only matters if you recompile this yourself)

Compiling this on this Mac required one fix: the Arduino tooling's bundled `ctags` binary
(used for auto-generating function prototypes) was `x86_64`-only and this is an Apple
Silicon Mac with no Rosetta installed, so it failed outright. Fixed by installing
`universal-ctags` via Homebrew and symlinking it over the broken bundled binary rather than
installing Rosetta system-wide for one small tool. If you hit
`Error during build: fork/exec .../ctags: bad CPU type in executable` on your own machine,
that's the same issue.

## Hardware needed (none of this is done — parts list only)

- An ESP32 dev board (the sketch targets `esp32:esp32:esp32` — a standard "ESP32 Dev
  Module"; any board with that chip should work with minor/no changes)
- USB cable to flash it
- Eventually: enclosure, battery, the rest of the BOM from the original project docs — not
  attempted here, this session only covers firmware code

## Next real steps, in order of what's actually blocking

1. **Get a physical ESP32 board** and flash this (`arduino-cli upload` once a board is
   connected, or via the Arduino IDE) — first point anything here actually runs.
2. **Verify BLE behavior for real**: connect with a generic BLE scanner app (e.g. nRF
   Connect) first, before writing phone app code against it — read the public key and
   device ID characteristics, write a test challenge string, confirm a 64-byte signature
   comes back on the notify characteristic.
3. **Write the phone app's Bluetooth code** (`mobile/ios/`) to actually speak this
   protocol, replacing the current `deviceVerify()` stub.
4. **Decide on flash encryption** before treating this as anything beyond a working demo.
