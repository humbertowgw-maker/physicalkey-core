#!/usr/bin/env bash
# Compiles and runs the ratchet_core host test natively — no ESP-IDF, no ESP32, no
# simulator. Links the real production ratchet_core.cpp plus the real vendored
# Curve25519/SHA512/Hash/BigNumberUtil sources; nothing here is reimplemented.
set -euo pipefail
cd "$(dirname "$0")"

MAIN_DIR=../main
ED25519_DIR=../components/ed25519

c++ -std=c++17 -Wall -Wextra \
  -I "$MAIN_DIR" \
  -I "$ED25519_DIR/include" \
  ratchet_core_test.cpp \
  host_rng.cpp \
  "$MAIN_DIR/ratchet_core.cpp" \
  "$ED25519_DIR/Curve25519.cpp" \
  "$ED25519_DIR/SHA512.cpp" \
  "$ED25519_DIR/Hash.cpp" \
  "$ED25519_DIR/BigNumberUtil.cpp" \
  "$ED25519_DIR/Crypto.cpp" \
  -o /tmp/ratchet_core_test

/tmp/ratchet_core_test
