idf_component_register(
    SRCS "main.cpp" "identity.cpp" "gatt_svr.cpp" "ratchet.cpp"
    INCLUDE_DIRS "."
    REQUIRES nvs_flash bt esp_hw_support ed25519
)
