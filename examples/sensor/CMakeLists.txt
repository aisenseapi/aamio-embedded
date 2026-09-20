# The aamio core and this example's own logic build as plain C: no ESP-IDF
# headers in either, so both are tested on a host. Only main_esp32.c needs the
# SDK, and it has never been built.
idf_component_register(
    SRCS "../../src/aamio.c" "session.c" "main_esp32.c"
    INCLUDE_DIRS "../../include" "."
    REQUIRES esp_http_client esp-tls nvs_flash
    PRIV_REQUIRES libsodium
)
