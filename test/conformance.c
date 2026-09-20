/* The shared vectors, run through this client.
 *
 * Six of the seven aamio clients carry the same vectors.json byte for byte. A
 * client that passes them opens the envelopes the others write; one that does
 * not is nearly compatible, which is the expensive kind.
 *
 * Ed25519 is not exercised here and is not in this client: it belongs to the
 * platform, where it is already audited. What is exercised is everything that
 * decides which bytes the platform is asked to sign.
 */

#include "../include/aamio.h"
#include "vectors.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;
static int checks = 0;

static void check(int good, const char *what, const char *saw)
{
    checks++;

    if (good) {
        printf("  ok    %s\n", what);
    } else {
        failures++;
        printf("  FAIL  %s%s%s\n", what, saw == NULL ? "" : "  ", saw == NULL ? "" : saw);
    }
}

static void check_text(const char *got, const char *want, const char *what)
{
    check(strcmp(got, want) == 0, what, got);
}

int main(void)
{
    char hex[65];
    char address[AAMIO_ADDRESS_LEN + 1];
    char sign_input[AAMIO_SIGN_INPUT_SIZE];
    char encoded[128];
    uint8_t raw[64];
    size_t wrote = 0;

    printf("aamio-embedded against the shared vectors\n");

    /* ------------------------------------------------------------ sha256 -- */
    aamio_sha256_hex((const uint8_t *) "abc", 3, hex);
    check_text(hex, V_SHA256_ABC, "sha256 of abc");

    /* A body over one block, so the padding path with a second block is used. */
    {
        uint8_t long_input[200];
        char first[65];
        char again[65];
        size_t i;

        for (i = 0; i < sizeof long_input; i++) {
            long_input[i] = (uint8_t) (i & 0xff);
        }

        aamio_sha256_hex(long_input, sizeof long_input, first);
        aamio_sha256_hex(long_input, sizeof long_input, again);
        check(strcmp(first, again) == 0 && strlen(first) == 64, "a body of two hundred bytes hashes, and twice the same", first);
    }

    /* ------------------------------------------------------- derivations -- */
    memset(address, 0, sizeof address);
    check(aamio_address(V_ID, strlen(V_ID), address) == AAMIO_OK, "a read key derives an address", NULL);
    check_text(address, V_W, "and it is the address the other clients derive");

    memset(address, 0, sizeof address);
    check(aamio_scope_address(V_SCOPE_KEY, strlen(V_SCOPE_KEY), address) == AAMIO_OK, "a scope key derives an address", NULL);
    check_text(address, V_SCOPE_ADDRESS, "and a scope address is not the thread address of the same string");

    memset(address, 0, sizeof address);
    aamio_address(V_SCOPE_KEY, strlen(V_SCOPE_KEY), address);
    check_text(address, V_SCOPE_AS_THREAD, "which the vectors pin, so the two derivations cannot be confused");

    check(aamio_sign_input(V_W, (const uint8_t *) V_BODY, strlen(V_BODY), sign_input, sizeof sign_input) == AAMIO_OK,
          "the signing input is built", NULL);
    check_text(sign_input, V_SIGN_INPUT, "and it is the exact string the others sign");

    check(aamio_key_hash(V_A_PUBLIC, strlen(V_A_PUBLIC), hex) == AAMIO_OK, "a public key hashes", NULL);
    check_text(hex, V_A_HASH, "to what a partner keeps in its address book");

    /* --------------------------------------------------------- base64url -- */
    check(aamio_b64url_decode(V_A_PUBLIC, strlen(V_A_PUBLIC), raw, sizeof raw, &wrote) == AAMIO_OK && wrote == 32,
          "a public key decodes to thirty-two bytes", NULL);

    check(aamio_b64url_encode(raw, 32, encoded, sizeof encoded) == AAMIO_OK, "and encodes again", NULL);
    check_text(encoded, V_A_PUBLIC, "to the same string it came from");

    check(aamio_b64url_decode(V_SIGNATURE, strlen(V_SIGNATURE), raw, sizeof raw, &wrote) == AAMIO_OK && wrote == 64,
          "a signature decodes to sixty-four bytes", NULL);

    /* One key is one string. The stray-bit spellings decode to the same bytes
     * and are refused, because an allowlist compares strings and two spellings
     * of one key are two identities. */
    check(aamio_b64url_decode(V_STRAY_KEY, strlen(V_STRAY_KEY), raw, sizeof raw, &wrote) == AAMIO_E_ENCODING,
          "a key with a bit set beyond its bytes is refused", NULL);
    check(aamio_b64url_decode(V_STRAY_SIGNATURE, strlen(V_STRAY_SIGNATURE), raw, sizeof raw, &wrote) == AAMIO_E_ENCODING,
          "and so is a signature", NULL);
    check(aamio_check_key_shape(V_A_PUBLIC, strlen(V_A_PUBLIC)) == AAMIO_OK
          && aamio_check_key_shape(V_STRAY_KEY, strlen(V_STRAY_KEY)) == AAMIO_E_ENCODING,
          "the shape check tells the two apart", NULL);
    check(aamio_check_signature_shape(V_SIGNATURE, strlen(V_SIGNATURE)) == AAMIO_OK
          && aamio_check_signature_shape(V_A_PUBLIC, strlen(V_A_PUBLIC)) == AAMIO_E_LENGTH,
          "and a key is not a signature, which is a length and not an encoding", NULL);

    /* ------------------------------------------------ nothing overruns -- */
    check(aamio_sign_input(V_W, (const uint8_t *) V_BODY, strlen(V_BODY), sign_input, 10) == AAMIO_E_SMALL,
          "a buffer too small is refused rather than filled", NULL);
    check(aamio_b64url_decode(V_A_PUBLIC, strlen(V_A_PUBLIC), raw, 8, &wrote) == AAMIO_E_SMALL,
          "and so is a decode that would not fit", NULL);
    check(aamio_address("short", 5, address) == AAMIO_E_ARG, "a read key under twenty characters is not an address", NULL);
    check(aamio_address("UPPERCASE1234567890abcd", 23, address) == AAMIO_E_ARG, "and neither is one with a letter it may not have", NULL);

    /* --------------------------------------------------- reading answers -- */
    {
        static const char answer[] =
            "{\"w\":\"ohcibx4t22xc6hx22fch\",\"exists\":true,\"created_at\":1789900000,"
            "\"expire_at\":1789900600,\"count\":7,\"allow\":[],\"messages\":[{\"seq\":1,"
            "\"body\":\"{\\\"t\\\":21.4}\",\"verified\":false}],\"next\":1,\"waited\":0,\"more\":true}";
        const char *value = NULL;
        size_t value_len = 0;
        long number = 0;

        check(aamio_json_field(answer, sizeof answer - 1, "w", &value, &value_len) == AAMIO_OK
              && value_len == 20 && memcmp(value, V_W, 20) == 0, "an answer gives up its address without a parser", NULL);
        check(aamio_json_number(answer, sizeof answer - 1, "next", &number) == AAMIO_OK && number == 1,
              "and its cursor", NULL);
        check(aamio_json_number(answer, sizeof answer - 1, "count", &number) == AAMIO_OK && number == 7,
              "and how many the thread holds", NULL);
        check(aamio_json_field(answer, sizeof answer - 1, "more", &value, &value_len) == AAMIO_OK
              && value_len == 4 && memcmp(value, "true", 4) == 0,
              "and whether something was left behind, which is how a small read knows to ask again", NULL);
        /* seq is inside messages, not at the top level: a field this does not
         * find is absent rather than guessed at from somewhere deeper. */
        check(aamio_json_field(answer, sizeof answer - 1, "seq", &value, &value_len) == AAMIO_E_ARG,
              "a nested name is not mistaken for a top level one", NULL);
        check(aamio_json_field(answer, sizeof answer - 1, "too_large", &value, &value_len) == AAMIO_E_ARG,
              "and a field that is not there says so", NULL);
    }

    printf("\nwhat a scope key may be\n");
    {
        char address[AAMIO_ADDRESS_LEN];
        /* Exactly an address in length and in alphabet. The service has refused
         * this since scopes existed -- a key where the address goes, with the
         * derivation in the fix -- because a 20-character string is an address, and
         * deriving a scope from one derives an address from an address. This client
         * took the thread id rule, which starts at 20. Health check and Codex, both
         * on 20 September 2026. */
        check(aamio_scope_address("abcdefghijklmnopqrst", 20, address) == AAMIO_E_ARG,
              "a 20-character scope key is refused: that is an address, not a key", NULL);
        check(aamio_scope_address("abcdefghijklmnopqrstuvwxy", 25, address) == AAMIO_E_ARG,
              "and so is anything under twenty-six", NULL);
        check(aamio_scope_address("abcdefghijklmnopqrstuvwxyz", 26, address) == AAMIO_OK,
              "twenty-six is the shortest one there is", NULL);
    }

    printf("\nwhat a refused decode leaves behind\n");
    {
        uint8_t out[4];
        size_t wrote = 0;

        /* A caller told its call failed has every reason to believe its buffer is
         * untouched. AQ! used to turn 5a5a5a5a into 015a5a5a and then report an
         * encoding error, so the damage was silent in the one place it showed. */
        memset(out, 0x5a, sizeof out);
        check(aamio_b64url_decode("AQ!", 3, out, sizeof out, &wrote) == AAMIO_E_ENCODING,
              "a character that is not base64url is refused", NULL);
        check(out[0] == 0x5a && out[1] == 0x5a && out[2] == 0x5a && out[3] == 0x5a,
              "and not a byte of the caller's buffer was written on the way", NULL);

        memset(out, 0x5a, sizeof out);
        check(aamio_b64url_decode("AQID", 4, out, 2, &wrote) == AAMIO_E_SMALL,
              "a buffer too small is refused", NULL);
        check(out[0] == 0x5a && out[1] == 0x5a,
              "and that one writes nothing either", NULL);

        memset(out, 0x5a, sizeof out);
        wrote = 0;
        check(aamio_b64url_decode("AQID", 4, out, sizeof out, &wrote) == AAMIO_OK
              && wrote == 3 && out[0] == 1 && out[1] == 2 && out[2] == 3,
              "and a string that does decode still decodes", NULL);
    }

    printf("\n%d checks, %d failed\n", checks, failures);

    return failures == 0 ? 0 : 1;
}
