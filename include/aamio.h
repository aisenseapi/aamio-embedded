/* aamio for small devices: the parts that are easy to get subtly wrong.
 *
 * An ESP32 already has TLS and Ed25519 through mbedTLS, and an HTTP client
 * through its SDK. What it does not have is the handful of derivations that
 * decide whether a client is actually compatible or only nearly so: how a
 * write address comes from a read key, which exact bytes get signed, how a
 * public key is encoded, and what a scope address is. Those live here.
 *
 * What this file is not: it is not a transport, it does not sign, and it does
 * not open a socket. Signing and TLS belong to the platform, where they are
 * already audited. Mixing them in would mean shipping crypto nobody reviewed.
 *
 * Everything is checked against testdata/vectors.json, the same file six of
 * the seven aamio clients carry byte for byte. A client that passes it opens
 * the envelopes the others write.
 *
 * Rules this code keeps, because a device has no room to be careless:
 *   - no malloc, ever; every output buffer is the caller's, with its size
 *   - every function returns 0 on success and a negative AAMIO_E_* otherwise
 *   - nothing is written to an output buffer on failure
 *   - no function reads past the length it was given
 *
 * AI SENSE AS, Oslo. Same licence as the other clients.
 */

#ifndef AAMIO_H
#define AAMIO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AAMIO_OK               0
#define AAMIO_E_SMALL         -1  /* the output buffer is too small */
#define AAMIO_E_ARG           -2  /* a null pointer, or a length of zero */
#define AAMIO_E_ENCODING      -3  /* not base64url, or not the canonical form */
#define AAMIO_E_LENGTH        -4  /* the right shape, the wrong number of bytes */

/* A write address is twenty characters, and never NUL terminated by us. */
#define AAMIO_ADDRESS_LEN     20

/* "aamio-v1\n" + 20 + "\n" + 64 hex = 94 characters, plus room for a NUL. */
#define AAMIO_SIGN_INPUT_SIZE 95

/* A read key is 20 to 64 characters of [a-z0-9]; 26 is what the service advises. */
#define AAMIO_ID_MIN          20
#define AAMIO_ID_MAX          64
/* A scope key is longer than an address at its shortest, so the two cannot be
 * confused. The service has refused a 20-character scope key since scopes
 * existed, by name and with the derivation in the fix; this client took one and
 * derived an address from what was already an address. */
#define AAMIO_SCOPE_KEY_MIN   26
#define AAMIO_SCOPE_KEY_MAX   64

/* ---------------------------------------------------------------- sha256 -- */

/* Included because the vectors pin it and a caller should not have to prove
 * its platform agrees. On ESP32 mbedTLS has one too; either passes. */
void aamio_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void aamio_sha256_hex(const uint8_t *data, size_t len, char out[65]);

/* ----------------------------------------------------------- derivations -- */

/* The public write address of a read key: the first twenty characters of
 * lowercase base32 over sha256 of the key, no padding. Anyone may hold the
 * address; only the key reads. Does not NUL terminate. */
int aamio_address(const char *id, size_t id_len, char out[AAMIO_ADDRESS_LEN]);

/* The address of a scope, over "aamio-scope-v1\n" + key. The key is the read
 * capability and the address the write capability, so a device given only the
 * address can post into a group it cannot read. */
int aamio_scope_address(const char *key, size_t key_len, char out[AAMIO_ADDRESS_LEN]);

/* The exact bytes an aamio signature covers:
 *     "aamio-v1\n" + w + "\n" + sha256hex(body)
 * Hand these to the platform's Ed25519. Signing anything else produces a
 * signature every other client refuses, which is the most expensive way to be
 * nearly compatible. Writes a NUL. */
int aamio_sign_input(const char w[AAMIO_ADDRESS_LEN], const uint8_t *body, size_t body_len,
                     char *out, size_t out_size);

/* The hash a partner keeps in its address book, and the first eight characters
 * of which presence is looked up by: sha256 of the thirty-two raw key bytes,
 * as hex. Takes the key in base64url. Writes a NUL. */
int aamio_key_hash(const char *public_key, size_t key_len, char out[65]);

/* ------------------------------------------------------------- base64url -- */

/* One key is one string. base64url lets the last character carry bits that
 * belong to no byte, so the same thirty-two bytes can be written four ways.
 * Decoding refuses every spelling but the canonical one, which is what the
 * service does since 18 September 2026: an allowlist compares strings, and two
 * spellings of one key are two identities. */
/* Nothing is written to out unless the whole string decodes: the text is
 * checked first and copied second. It used to decode as it went, so a string
 * that failed in the middle left the caller's buffer half overwritten while
 * the return said the call had failed. */
int aamio_b64url_decode(const char *text, size_t len, uint8_t *out, size_t out_size, size_t *wrote);
int aamio_b64url_encode(const uint8_t *raw, size_t len, char *out, size_t out_size);

/* A key is thirty-two bytes and a signature sixty-four, each in canonical
 * base64url. Shape only: whether a signature verifies is Ed25519's answer. */
int aamio_check_key_shape(const char *text, size_t len);
int aamio_check_signature_shape(const char *text, size_t len);

/* ------------------------------------------------------- reading answers -- */

/* Enough JSON to read an answer without a parser and without allocating: finds
 * one top level field and hands back a view into the buffer the caller already
 * holds. Returns AAMIO_E_ARG when the field is not there.
 *
 * A device should ask the service for a small answer to begin with, with the
 * X-Limit and X-Max-Bytes headers; see the README. Without them an answer can
 * be about a megabyte, which is the whole reason this file exists. */
/* What a value is, for a caller that has to tell true from "true". */
#define AAMIO_JSON_STRING     1
#define AAMIO_JSON_NUMBER     2
#define AAMIO_JSON_LITERAL    3   /* true, false, null */
#define AAMIO_JSON_OBJECT     4
#define AAMIO_JSON_ARRAY      5

/* aamio_json_field, and the type as well. The field reader hands back a string
 * without its quotes, so "true" and true arrive identical: a service answering
 * exists:"true" was read as a thread that exists, and messages:"[]" as a list.
 * Both were accepted until 20 September 2026. */
int aamio_json_typed(const char *json, size_t len, const char *name,
                     const char **value, size_t *value_len, int *type);
int aamio_json_field(const char *json, size_t len, const char *name,
                     const char **value, size_t *value_len);

/* The same, for a whole number. */
int aamio_json_number(const char *json, size_t len, const char *name, long *out);

/* Is this one complete JSON object and nothing else?
 *
 * A body cut off by a full buffer or a dropped connection looks like an answer for as
 * far as it goes, and the fields before the cut read fine. Believing those moved a
 * cursor past messages that were never delivered. Check first, believe after. */
int aamio_json_whole(const char *json, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* AAMIO_H */
