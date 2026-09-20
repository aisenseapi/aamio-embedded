/* A sensor on an ESP32 that signs a reading, sends it, and reads what came back.
 *
 * ===========================================================================
 * THIS FILE HAS NEVER BEEN COMPILED OR FLASHED.
 *
 * Everything in it that could be tested without a board was moved to
 * session.c, which is run by test/session_test.c. What is left is the glue to
 * ESP-IDF: Wi-Fi, libsodium and esp_http_client. Treat it as a description of
 * the shape, check it against the SDK you have, and expect to fix names.
 * ===========================================================================
 *
 * What it needs, in idf_component.yml:
 *
 *     dependencies:
 *       espressif/libsodium: "^1.0.20"
 *
 * libsodium is Espressif's own port and supports every target. mbedTLS, which
 * ESP-IDF already bundles, does TLS and sha256 but not Ed25519 signing, which
 * is why the signature comes from libsodium and the transport from mbedTLS.
 *
 * The key. A device's signing key is its identity and should outlive a reboot:
 * keep the seed in NVS, or better in eFuse or the secure element if the board
 * has one. The read key of a thread is a different thing and a short-lived
 * one. Losing it cannot be undone by anyone: the thread stays open and goes on
 * taking messages nobody will ever read, and whoever writes to you sees an
 * ordinary delivery. Keep it across the sleep, or open a new inbox on waking
 * and announce that one.
 */

#include "aamio.h"
#include "session.h"

#include <sodium.h>
#include <string.h>

#include "esp_http_client.h"
#include "esp_log.h"

#define HOST      "https://aamio.at"
#define TAG       "aamio"

/* Small on purpose. A thread can answer with about a megabyte, which is more
 * than this device has; these two headers are what make it fit. Measured: a
 * reading comes back in about 360 bytes, an empty read in 144. */
#define READ_LIMIT      "1"
#define READ_MAX_BYTES  "2000"
#define ANSWER_MAX      1024

/* The reply inbox this device reads. Derived from a read key it keeps; see the
 * note about NVS above. */
static aamio_session session;

/* The signing identity. crypto_sign_keypair fills both; the secret key holds
 * the seed and the public key, as libsodium's Ed25519 does. */
static unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
static unsigned char secret_key[crypto_sign_SECRETKEYBYTES];

static esp_err_t collect(esp_http_client_event_t *event)
{
    static int wrote;

    if (event->event_id == HTTP_EVENT_ON_DATA && event->user_data != NULL) {
        char *into = (char *) event->user_data;
        int room = ANSWER_MAX - 1 - wrote;
        int take = event->data_len < room ? event->data_len : room;

        if (take > 0) {
            memcpy(into + wrote, event->data, (size_t) take);
            wrote += take;
            into[wrote] = '\0';
        }
        /* What did not fit is dropped here and the answer is short: the point
         * of X-Max-Bytes is that this should not happen. If it does, the
         * budget is wrong, not the buffer. */
    } else if (event->event_id == HTTP_EVENT_ON_CONNECTED) {
        wrote = 0;
    }

    return ESP_OK;
}

/* Sends one reading to a partner's write address, signed by this device. */
static int send_reading(const char *to_w, const char *body)
{
    char sign_input[AAMIO_SIGN_INPUT_SIZE];
    unsigned char signature[crypto_sign_BYTES];
    char signature_b64[128];
    char key_b64[64];
    char url[128];
    esp_http_client_handle_t client;
    esp_err_t problem;
    int status;

    /* The exact bytes aamio signs. Signing anything else produces a signature
     * every other client refuses. */
    if (aamio_sign_input(to_w, (const uint8_t *) body, strlen(body), sign_input, sizeof sign_input) != AAMIO_OK) {
        return -1;
    }

    if (crypto_sign_detached(signature, NULL, (const unsigned char *) sign_input,
                             strlen(sign_input), secret_key) != 0) {
        return -1;
    }

    if (aamio_b64url_encode(signature, sizeof signature, signature_b64, sizeof signature_b64) != AAMIO_OK
        || aamio_b64url_encode(public_key, sizeof public_key, key_b64, sizeof key_b64) != AAMIO_OK) {
        return -1;
    }

    snprintf(url, sizeof url, "%s/%.20s", HOST, to_w);

    esp_http_client_config_t config = {
        .url = url,
        .method = HTTP_METHOD_POST,
        .crt_bundle_attach = esp_crt_bundle_attach,  /* verify the certificate; never skip this */
        .timeout_ms = 10000,
    };
    client = esp_http_client_init(&config);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_header(client, "X-Key", key_b64);
    esp_http_client_set_header(client, "X-Sig", signature_b64);
    esp_http_client_set_post_field(client, body, (int) strlen(body));

    problem = esp_http_client_perform(client);
    status = problem == ESP_OK ? esp_http_client_get_status_code(client) : 0;
    esp_http_client_cleanup(client);

    /* 201 is stored, not read and not acted on. 0 is no answer at all, and the
     * message may still have arrived: it is unknown, not failed, and sending
     * it again is a second delivery unless the other side keeps what it has
     * seen. Every refusal carries a fix field saying what to do instead. */
    ESP_LOGI(TAG, "send -> %d", status);

    return status;
}

/* Reads our own inbox, small enough to hold. */
static int read_inbox(char *answer)
{
    char path[64];
    char url[160];
    esp_http_client_handle_t client;
    esp_err_t problem;
    int status;

    if (aamio_session_read_path(&session, path, sizeof path) != AAMIO_OK) {
        return -1;
    }

    snprintf(url, sizeof url, "%s%s", HOST, path);
    answer[0] = '\0';

    esp_http_client_config_t config = {
        .url = url,
        .method = HTTP_METHOD_GET,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .event_handler = collect,
        .user_data = answer,
        .timeout_ms = 30000,   /* longer than the longest long poll */
    };
    client = esp_http_client_init(&config);
    esp_http_client_set_header(client, "X-Read", session.id);
    esp_http_client_set_header(client, "X-Limit", READ_LIMIT);
    esp_http_client_set_header(client, "X-Max-Bytes", READ_MAX_BYTES);

    problem = esp_http_client_perform(client);
    status = problem == ESP_OK ? esp_http_client_get_status_code(client) : 0;
    esp_http_client_cleanup(client);

    return status;
}

void aamio_sensor_round(const char *partner_w, const char *reading)
{
    char answer[ANSWER_MAX];

    send_reading(partner_w, reading);

    for (;;) {
        int carried;

        if (read_inbox(answer) != 200) {
            break;
        }

        carried = aamio_session_take_answer(&session, answer, strlen(answer));

        if (carried < 0) {
            break;
        }

        if (session.gone) {
            /* The thread expired or the service restarted. Whatever opens at
             * this address next counts from one again, so stop reading it and
             * announce a new inbox rather than advertising this one. */
            ESP_LOGW(TAG, "the inbox is gone; open a new one before saying where to reach us");
            break;
        }

        if (session.left_unread != 0) {
            ESP_LOGW(TAG, "seq %ld is %ld bytes, more than this device takes; stepping past it",
                     session.left_unread, session.left_bytes);
        }

        /* Act on what came back here. Verify the signature with
         * crypto_sign_verify_detached over aamio_sign_input of the body and
         * this address before acting: verified in the answer is the service's
         * own finding, not an independent check.
         *
         * And a command is not made safe by arriving: bind it to this device,
         * to a session, and to a deadline this device can actually check, and
         * keep your own record of what has been carried out. A reset moves the
         * service's cursor and gives no permission to do an old command again. */

        if (!session.more) {
            break;   /* nothing left; sleep until the next reading */
        }
    }
}
