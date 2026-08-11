# Host-side tests

The firmware's crypto/protocol logic (`main/ratchet_core.cpp`) compiled and run natively
on the dev machine — no ESP32 board, no ESP-IDF toolchain, no simulator. This is the
first automated coverage anywhere in the firmware; everything else has only ever been
verified manually against real hardware (see `../README.md`).

```bash
./run.sh
```

## Why this works, and what it doesn't cover

Most of this firmware genuinely can't be unit tested without either real hardware or
heavy ESP-IDF/NimBLE mocking — `main.cpp`'s BLE stack, `gatt_svr.cpp`'s GATT handlers,
`identity.cpp`/`pairing.cpp`'s NVS-backed key storage. The one meaningful exception is
`ratchet_core.cpp` (split out of `ratchet.cpp` on 2026-08-10 specifically to make this
possible): the actual X25519 + HMAC-SHA512 session-continuity math has zero real
ESP-IDF dependency once the NVS load/store is pushed to the caller as plain byte
parameters. It links directly against the same vendored `Curve25519.cpp`/`SHA512.cpp`/
`Hash.cpp`/`Crypto.cpp` the real board uses — this is the production crypto code
running natively, not a reimplementation the firmware could silently drift away from.

`host_rng.cpp` is the one test-only piece: `Curve25519::dh1()` reaches a global `RNG`
object internally, which on the real board (`rng_esp32.cpp`) is backed by the genuine
ESP32 hardware RNG. This host stand-in uses `arc4random_buf` instead — fine for these
tests, since they check protocol *properties* (two sides agree on the same shared
secret, continuity chains correctly, a known-weak point is rejected) that hold for any
valid random key, not specific values. `main/CMakeLists.txt` never references this file,
so it's never linked into the real firmware build.

## What a passing run actually proves

Confirmed by `ratchet_core_test.cpp`, not assumed:
1. The phone and device sides of the X25519 exchange genuinely agree on the same shared
   secret — computed twice, independently, and compared, not just "some bytes came out."
2. `nextProof` and `deviceProof` are exactly the HMAC-SHA512 values `ratchet.h`'s protocol
   comment documents, not a plausible-looking but wrong derivation.
3. A known weak/invalid X25519 point (the all-zero point, from cr.yp.to/ecdh.html) is
   correctly rejected.

## A real bug found writing this

`Curve25519::dh1()` generates and clamps its own ephemeral private key internally via
the RNG global — it ignores whatever's in its output buffer on entry. The original code
called `esp_fill_random()` on that buffer immediately before calling `dh1()`, which
`dh1()` then silently discarded. Not a security issue (both paths ultimately use the
real ESP32 hardware RNG), but genuinely wasted work — removed as part of the same commit
that added these tests, caught only because writing a real test for this function meant
actually tracing what each parameter does.
