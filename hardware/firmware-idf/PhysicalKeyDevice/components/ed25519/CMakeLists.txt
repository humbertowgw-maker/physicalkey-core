idf_component_register(
    SRCS "Ed25519.cpp" "Curve25519.cpp" "SHA512.cpp" "BigNumberUtil.cpp" "Crypto.cpp" "Hash.cpp" "rng_esp32.cpp"
    INCLUDE_DIRS "include"
    REQUIRES esp_hw_support
)
