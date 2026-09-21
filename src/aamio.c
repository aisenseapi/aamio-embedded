/* See include/aamio.h for what this is and what it deliberately is not. */

#include "aamio.h"

#include <string.h>

/* ---------------------------------------------------------------- sha256 -- */

static const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(uint32_t state[8], const uint8_t block[64])
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t) block[i * 4] << 24) | ((uint32_t) block[i * 4 + 1] << 16)
             | ((uint32_t) block[i * 4 + 2] << 8) | (uint32_t) block[i * 4 + 3];
    }

    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 64; i++) {
        uint32_t s1 = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + s1 + ch + K[i] + w[i];
        uint32_t s0 = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void aamio_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    uint32_t state[8] = { 0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                          0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u };
    uint8_t tail[128];
    size_t whole = len / 64;
    size_t rest = len - whole * 64;
    size_t pad = rest < 56 ? 64 : 128;
    uint64_t bits = (uint64_t) len * 8;
    size_t i;

    for (i = 0; i < whole; i++) {
        sha256_block(state, data + i * 64);
    }

    memset(tail, 0, sizeof tail);

    if (rest > 0) {
        memcpy(tail, data + whole * 64, rest);
    }

    tail[rest] = 0x80;

    for (i = 0; i < 8; i++) {
        tail[pad - 1 - i] = (uint8_t) (bits >> (i * 8));
    }

    sha256_block(state, tail);

    if (pad == 128) {
        sha256_block(state, tail + 64);
    }

    for (i = 0; i < 8; i++) {
        out[i * 4] = (uint8_t) (state[i] >> 24);
        out[i * 4 + 1] = (uint8_t) (state[i] >> 16);
        out[i * 4 + 2] = (uint8_t) (state[i] >> 8);
        out[i * 4 + 3] = (uint8_t) state[i];
    }
}

static void hex_of(const uint8_t *raw, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++) {
        out[i * 2] = digits[raw[i] >> 4];
        out[i * 2 + 1] = digits[raw[i] & 0x0f];
    }

    out[len * 2] = '\0';
}

void aamio_sha256_hex(const uint8_t *data, size_t len, char out[65])
{
    uint8_t digest[32];

    aamio_sha256(data, len, digest);
    hex_of(digest, 32, out);
}

/* ---------------------------------------------------------------- base32 -- */

/* Lowercase, no padding, and only the first twenty characters are ever used:
 * twenty characters of base32 carry a hundred bits, which is what an address
 * is. The rest of the digest is not part of it. */
static void base32_head(const uint8_t *raw, size_t len, char *out, size_t want)
{
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";
    uint32_t buffer = 0;
    int bits = 0;
    size_t wrote = 0;
    size_t i;

    for (i = 0; i < len && wrote < want; i++) {
        buffer = (buffer << 8) | raw[i];
        bits += 8;

        while (bits >= 5 && wrote < want) {
            bits -= 5;
            out[wrote++] = alphabet[(buffer >> bits) & 0x1f];
        }
    }
}

/* ----------------------------------------------------------- derivations -- */

static int id_is_shaped(const char *id, size_t len)
{
    size_t i;

    if (id == NULL || len < AAMIO_ID_MIN || len > AAMIO_ID_MAX) {
        return 0;
    }

    for (i = 0; i < len; i++) {
        char c = id[i];

        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))) {
            return 0;
        }
    }

    return 1;
}

int aamio_address(const char *id, size_t id_len, char out[AAMIO_ADDRESS_LEN])
{
    uint8_t digest[32];

    if (out == NULL) {
        return AAMIO_E_ARG;
    }

    if (!id_is_shaped(id, id_len)) {
        return AAMIO_E_ARG;
    }

    aamio_sha256((const uint8_t *) id, id_len, digest);
    base32_head(digest, sizeof digest, out, AAMIO_ADDRESS_LEN);

    return AAMIO_OK;
}

int aamio_scope_address(const char *key, size_t key_len, char out[AAMIO_ADDRESS_LEN])
{
    static const char prefix[] = "aamio-scope-v1\n";
    uint8_t buffer[sizeof prefix - 1 + AAMIO_SCOPE_KEY_MAX];
    uint8_t digest[32];

    if (out == NULL) {
        return AAMIO_E_ARG;
    }

    /* A scope key, not a thread id. The two differ in one place only, and it is
     * the place that matters: a scope key is at least 26 characters so that it
     * cannot be a 20-character address. This took the thread rule and so took an
     * address as a key, deriving a second address from the first -- which is the
     * mistake the service refuses by name, with the derivation in the fix. */
    if (key_len < AAMIO_SCOPE_KEY_MIN || key_len > AAMIO_SCOPE_KEY_MAX
        || !id_is_shaped(key, key_len)) {
        return AAMIO_E_ARG;
    }

    memcpy(buffer, prefix, sizeof prefix - 1);
    memcpy(buffer + sizeof prefix - 1, key, key_len);
    aamio_sha256(buffer, sizeof prefix - 1 + key_len, digest);
    base32_head(digest, sizeof digest, out, AAMIO_ADDRESS_LEN);

    return AAMIO_OK;
}

int aamio_sign_input(const char w[AAMIO_ADDRESS_LEN], const uint8_t *body, size_t body_len,
                     char *out, size_t out_size)
{
    static const char prefix[] = "aamio-v1\n";
    char hex[65];

    if (w == NULL || out == NULL || (body == NULL && body_len > 0)) {
        return AAMIO_E_ARG;
    }

    if (out_size < AAMIO_SIGN_INPUT_SIZE) {
        return AAMIO_E_SMALL;
    }

    aamio_sha256_hex(body, body_len, hex);

    memcpy(out, prefix, sizeof prefix - 1);
    memcpy(out + sizeof prefix - 1, w, AAMIO_ADDRESS_LEN);
    out[sizeof prefix - 1 + AAMIO_ADDRESS_LEN] = '\n';
    memcpy(out + sizeof prefix - 1 + AAMIO_ADDRESS_LEN + 1, hex, 64);
    out[AAMIO_SIGN_INPUT_SIZE - 1] = '\0';

    return AAMIO_OK;
}

int aamio_key_hash(const char *public_key, size_t key_len, char out[65])
{
    uint8_t raw[32];
    size_t wrote = 0;
    int problem;

    if (out == NULL) {
        return AAMIO_E_ARG;
    }

    problem = aamio_b64url_decode(public_key, key_len, raw, sizeof raw, &wrote);

    if (problem != AAMIO_OK) {
        return problem;
    }

    if (wrote != 32) {
        return AAMIO_E_LENGTH;
    }

    aamio_sha256_hex(raw, 32, out);

    return AAMIO_OK;
}

/* ------------------------------------------------------------- base64url -- */

static int value_of(char c)
{
    if (c >= 'A' && c <= 'Z') { return c - 'A'; }
    if (c >= 'a' && c <= 'z') { return c - 'a' + 26; }
    if (c >= '0' && c <= '9') { return c - '0' + 52; }
    if (c == '-') { return 62; }
    if (c == '_') { return 63; }

    return -1;
}

int aamio_b64url_decode(const char *text, size_t len, uint8_t *out, size_t out_size, size_t *wrote)
{
    uint32_t buffer = 0;
    int bits = 0;
    size_t written = 0;
    size_t i;

    if (text == NULL || out == NULL) {
        return AAMIO_E_ARG;
    }

    if (len == 0 || len % 4 == 1) {
        /* Four characters carry three bytes; a remainder of one carries none. */
        return AAMIO_E_ENCODING;
    }

    for (i = 0; i < len; i++) {
        int value = value_of(text[i]);

        if (value < 0) {
            return AAMIO_E_ENCODING;
        }

        buffer = (buffer << 6) | (uint32_t) value;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;

            if (written >= out_size) {
                return AAMIO_E_SMALL;
            }

            written++;
        }
    }

    /* What is left over belongs to no byte, and an encoder leaves it zero. A
     * string that sets it decodes to the same bytes and is a second spelling
     * of the same key, which an allowlist would read as a different identity. */
    if (bits > 0 && (buffer & ((1u << bits) - 1u)) != 0) {
        return AAMIO_E_ENCODING;
    }

    /* Only now, with every character known good and the length known to fit.
     * It used to write each byte as it worked them out, so a string that failed
     * at its last character left the caller's buffer part overwritten and part
     * its own -- while the return said the call had failed and the caller had
     * every reason to believe its buffer untouched. AQ! turned 5a5a5a5a into
     * 015a5a5a and reported an encoding error, on 20 September 2026. */
    buffer = 0;
    bits = 0;
    written = 0;

    for (i = 0; i < len; i++) {
        buffer = (buffer << 6) | (uint32_t) value_of(text[i]);
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            out[written++] = (uint8_t) ((buffer >> bits) & 0xff);
        }
    }

    if (wrote != NULL) {
        *wrote = written;
    }

    return AAMIO_OK;
}

int aamio_b64url_encode(const uint8_t *raw, size_t len, char *out, size_t out_size)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t need = (len * 8 + 5) / 6;
    uint32_t buffer = 0;
    int bits = 0;
    size_t wrote = 0;
    size_t i;

    if (raw == NULL || out == NULL) {
        return AAMIO_E_ARG;
    }

    if (out_size < need + 1) {
        return AAMIO_E_SMALL;
    }

    for (i = 0; i < len; i++) {
        buffer = (buffer << 8) | raw[i];
        bits += 8;

        while (bits >= 6) {
            bits -= 6;
            out[wrote++] = alphabet[(buffer >> bits) & 0x3f];
        }
    }

    if (bits > 0) {
        out[wrote++] = alphabet[(buffer << (6 - bits)) & 0x3f];
    }

    out[wrote] = '\0';

    return AAMIO_OK;
}

static int shape_is(const char *text, size_t len, size_t bytes)
{
    uint8_t raw[64];
    size_t wrote = 0;
    int problem = aamio_b64url_decode(text, len, raw, sizeof raw, &wrote);

    if (problem != AAMIO_OK) {
        return problem;
    }

    return wrote == bytes ? AAMIO_OK : AAMIO_E_LENGTH;
}

int aamio_check_key_shape(const char *text, size_t len)
{
    return shape_is(text, len, 32);
}

int aamio_check_signature_shape(const char *text, size_t len)
{
    return shape_is(text, len, 64);
}

/* ------------------------------------------------------- reading answers -- */

/* Finds "name" at the top level and hands back a view of its value. Deliberately
 * small: it does not walk nested objects, because a device should ask for the
 * fields it needs and not carry a parser it cannot afford. Strings come back
 * without their quotes and still escaped; a caller that needs the text unescapes
 * what it reads. */
int aamio_json_field(const char *json, size_t len, const char *name,
                     const char **value, size_t *value_len)
{
    return aamio_json_typed(json, len, name, value, value_len, NULL);
}

int aamio_json_typed(const char *json, size_t len, const char *name,
                     const char **value, size_t *value_len, int *type)
{
    size_t name_len;
    size_t i;
    int depth = 0;
    int in_string = 0;

    if (json == NULL || name == NULL || value == NULL || value_len == NULL) {
        return AAMIO_E_ARG;
    }

    name_len = strlen(name);

    for (i = 0; i + name_len + 2 < len; i++) {
        char c = json[i];

        if (in_string) {
            if (c == '\\') {
                i++;
            } else if (c == '"') {
                in_string = 0;
            }

            continue;
        }

        if (c == '"') {
            /* A name at the top level of the object we were handed. */
            if (depth == 1 && json[i + 1 + name_len] == '"'
                && memcmp(json + i + 1, name, name_len) == 0) {
                size_t at = i + name_len + 2;
                int colons = 0;

                /* One colon, and whitespace either side of it. The old loop took any
                 * run of spaces and colons, so a name with none and a name with three
                 * both read as a pair. */
                while (at < len && (json[at] == ' ' || json[at] == '\n'
                                    || json[at] == '\r' || json[at] == '\t')) {
                    at++;
                }

                while (at < len && json[at] == ':') {
                    colons++;
                    at++;
                }

                while (at < len && (json[at] == ' ' || json[at] == '\n'
                                    || json[at] == '\r' || json[at] == '\t')) {
                    at++;
                }

                if (at >= len || colons != 1) {
                    return AAMIO_E_ARG;
                }

                if (json[at] == '"') {
                    size_t from = at + 1;
                    size_t to = from;

                    while (to < len && json[to] != '"') {
                        to += json[to] == '\\' ? 2 : 1;
                    }

                    if (to > len) {
                        return AAMIO_E_ARG;
                    }

                    /* The quotes come off, which is what a caller reading a string
                     * wants and what made "true" and true the same answer. The type
                     * is the only thing that tells them apart now. */
                    if (type != NULL) {
                        *type = AAMIO_JSON_STRING;
                    }

                    *value = json + from;
                    *value_len = to - from;

                    return AAMIO_OK;
                } else if (json[at] == '{' || json[at] == '[') {
                    /* An object or a list is handed over whole, brackets and
                     * all, so a caller can read a field inside it. Stopping at
                     * the first comma would have cut too_large after its seq. */
                    size_t to = at;
                    int inner = 0;
                    int quoted = 0;

                    for (; to < len; to++) {
                        char at_to = json[to];

                        if (quoted) {
                            if (at_to == '\\') {
                                to++;
                            } else if (at_to == '"') {
                                quoted = 0;
                            }

                            continue;
                        }

                        if (at_to == '"') {
                            quoted = 1;
                        } else if (at_to == '{' || at_to == '[') {
                            inner++;
                        } else if (at_to == '}' || at_to == ']') {
                            inner--;

                            if (inner == 0) {
                                to++;
                                break;
                            }
                        }
                    }

                    if (inner != 0) {
                        return AAMIO_E_ENCODING;
                    }

                    if (type != NULL) {
                        *type = json[at] == '{' ? AAMIO_JSON_OBJECT : AAMIO_JSON_ARRAY;
                    }

                    *value = json + at;
                    *value_len = to - at;

                    return AAMIO_OK;
                } else {
                    size_t to = at;

                    while (to < len && json[to] != ',' && json[to] != '}'
                           && json[to] != ']' && json[to] != ' ' && json[to] != '\n'
                           && json[to] != '\r' && json[to] != '\t') {
                        to++;
                    }

                    if (to == at) {
                        return AAMIO_E_ENCODING;
                    }

                    if (type != NULL) {
                        *type = (json[at] == '-' || (json[at] >= '0' && json[at] <= '9'))
                                ? AAMIO_JSON_NUMBER : AAMIO_JSON_LITERAL;
                    }

                    *value = json + at;
                    *value_len = to - at;

                    return AAMIO_OK;
                }
            }

            in_string = 1;

            continue;
        }

        if (c == '{' || c == '[') {
            depth++;
        } else if (c == '}' || c == ']') {
            depth--;
        }
    }

    return AAMIO_E_ARG;
}

/* Where the walk is, so a separator can be judged by what came before it. */
#define AT_START 0
#define AT_OPEN  1
#define AT_VALUE 2
#define AT_COMMA 3
#define AT_COLON 4
/* A string in an object is a name or a value, and until this existed both set
 * the same state, so {"exists"true} read as a name and a value with nothing
 * between them. A name is followed by a colon and by nothing else. */
#define AT_NAME  5
/* Deeper than a service answer ever goes, and the bitmask that remembers which
 * levels are objects is this wide. Deeper is refused rather than guessed at. */
#define JSON_MAX_DEPTH 30

static int is_hex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static int is_space(char c)
{
    return c == ' ' || c == '\n' || c == '\r' || c == '\t';
}

/* One string, from its opening quote. Gives the index past the closing quote,
 * or 0 when it is not one: an escape that is not JSON's, a control character
 * in the raw, or no closing quote before the end. A backslash used to skip
 * whatever came next, so "\q" passed, and a document with "\q" in it is not
 * JSON; a reader that took it took an answer from a service that sent nothing
 * of the kind. Bytes past ASCII are let through as they are: this checks the
 * grammar, not the UTF-8, and a caller reading a string unescapes what it reads. */
static size_t string_end(const char *json, size_t len, size_t at)
{
    size_t i = at + 1;

    while (i < len) {
        unsigned char c = (unsigned char) json[i];

        if (c == '"') {
            return i + 1;
        }

        if (c < 0x20) {
            return 0;
        }

        if (c == '\\') {
            i++;

            if (i >= len) {
                return 0;
            }

            switch (json[i]) {
            case '"': case '\\': case '/': case 'b': case 'f': case 'n': case 'r': case 't':
                break;
            case 'u':
                if (i + 4 >= len || !is_hex(json[i + 1]) || !is_hex(json[i + 2])
                    || !is_hex(json[i + 3]) || !is_hex(json[i + 4])) {
                    return 0;
                }

                i += 4;
                break;
            default:
                return 0;
            }
        }

        i++;
    }

    return 0;
}

/* -?(0|[1-9][0-9]*)(.[0-9]+)?([eE][+-]?[0-9]+)?, and nothing before or after. */
static int is_number(const char *s, size_t n)
{
    size_t i = 0;
    size_t start;

    if (i < n && s[i] == '-') {
        i++;
    }

    if (i >= n) {
        return 0;
    }

    if (s[i] == '0') {
        i++;
    } else if (s[i] >= '1' && s[i] <= '9') {
        while (i < n && s[i] >= '0' && s[i] <= '9') {
            i++;
        }
    } else {
        return 0;
    }

    if (i < n && s[i] == '.') {
        i++;
        start = i;

        while (i < n && s[i] >= '0' && s[i] <= '9') {
            i++;
        }

        if (i == start) {
            return 0;
        }
    }

    if (i < n && (s[i] == 'e' || s[i] == 'E')) {
        i++;

        if (i < n && (s[i] == '+' || s[i] == '-')) {
            i++;
        }

        start = i;

        while (i < n && s[i] >= '0' && s[i] <= '9') {
            i++;
        }

        if (i == start) {
            return 0;
        }
    }

    return i == n;
}

/* One literal or number, from its first character. Gives the index past it, or
 * 0 when it is not one. A bare word where a value belongs used to run on as one:
 * messages:[garbage] was balanced and moved the cursor, and so was next:041.
 * true, false, null and a number in JSON's own grammar are values; nothing else. */
static size_t scalar_end(const char *json, size_t len, size_t at)
{
    size_t to = at;
    size_t n;

    while (to < len && json[to] != ',' && json[to] != ']' && json[to] != '}' && !is_space(json[to])) {
        to++;
    }

    n = to - at;

    if ((n == 4 && memcmp(json + at, "true", 4) == 0)
        || (n == 5 && memcmp(json + at, "false", 5) == 0)
        || (n == 4 && memcmp(json + at, "null", 4) == 0)
        || is_number(json + at, n)) {
        return to;
    }

    return 0;
}

int aamio_json_whole(const char *json, size_t len)
{
    size_t i = 0;
    int depth = 0;
    int closed = 0;
    int was = AT_START;
    int naming = 0;
    unsigned long object_at = 0;

    if (json == NULL || len == 0) {
        return AAMIO_E_ARG;
    }

    while (i < len && is_space(json[i])) {
        i++;
    }

    if (i >= len || json[i] != '{') {
        return AAMIO_E_ENCODING;
    }

    while (i < len) {
        char c = json[i];

        if (is_space(c)) {
            i++;

            continue;
        }

        if (closed) {
            /* Something after the object. Not one answer. */
            return AAMIO_E_ENCODING;
        }

        /* Balanced brackets are not a grammar. A trailing comma, a double comma and
         * two names with no comma between them were all balanced, and all three moved
         * the cursor. What may follow what is checked here, in five states. */
        if (c == '\"') {
            if (was != AT_START && was != AT_OPEN && was != AT_COMMA && was != AT_COLON) {
                return AAMIO_E_ENCODING;
            }

            /* Inside an object, a string where a value may not yet stand is the
             * name of the pair. Inside an array there are no names. */
            naming = depth >= 1 && depth <= JSON_MAX_DEPTH
                     && (object_at & (1UL << (depth - 1))) != 0
                     && (was == AT_OPEN || was == AT_COMMA);

            if (!naming && was != AT_START && was != AT_COLON
                && !(depth >= 1 && depth <= JSON_MAX_DEPTH
                     && (object_at & (1UL << (depth - 1))) == 0)) {
                return AAMIO_E_ENCODING;
            }

            /* The whole string at once, escapes checked, or none of it. */
            i = string_end(json, len, i);

            if (i == 0) {
                return AAMIO_E_ENCODING;
            }

            was = naming ? AT_NAME : AT_VALUE;

            continue;
        } else if (c == '{' || c == '[') {
            if (was != AT_START && was != AT_OPEN && was != AT_COMMA && was != AT_COLON) {
                return AAMIO_E_ENCODING;
            }

            /* An object inside an object inside an object, thirty deep, is not an
             * answer this service sends, and guessing past the mask is worse than
             * saying no. */
            if (depth >= JSON_MAX_DEPTH) {
                return AAMIO_E_ENCODING;
            }

            depth++;

            if (c == '{') {
                object_at |= 1UL << (depth - 1);
            } else {
                object_at &= ~(1UL << (depth - 1));
            }

            was = AT_OPEN;
        } else if (c == '}' || c == ']') {
            if (was == AT_COMMA || was == AT_COLON || was == AT_NAME) {
                return AAMIO_E_ENCODING;
            }

            /* A brace closing a bracket is not a deeper object; it is a different
             * document, and one of the two shapes is not what the caller read. */
            if (depth >= 1 && depth <= JSON_MAX_DEPTH
                && ((c == '}') != ((object_at & (1UL << (depth - 1))) != 0))) {
                return AAMIO_E_ENCODING;
            }

            depth--;

            if (depth < 0) {
                return AAMIO_E_ENCODING;
            }

            if (depth == 0) {
                closed = 1;
            }

            was = AT_VALUE;
        } else if (c == ',') {
            if (was != AT_VALUE) {
                return AAMIO_E_ENCODING;
            }

            was = AT_COMMA;
        } else if (c == ':') {
            /* After a name, and after nothing else. A colon following a value is
             * how {"exists"true} and {"a"::1} both got through. */
            if (was != AT_NAME) {
                return AAMIO_E_ENCODING;
            }

            was = AT_COLON;
        } else {
            /* A number or a literal. Its first character has to stand where a value
             * may; the rest of it runs on without changing the state. Inside an
             * object that is after a colon only: a bare literal where a name
             * belongs is not a pair. */
            int inside_object = depth >= 1 && depth <= JSON_MAX_DEPTH
                                && (object_at & (1UL << (depth - 1))) != 0;

            if (was != AT_COLON && (inside_object || (was != AT_OPEN && was != AT_COMMA))) {
                return AAMIO_E_ENCODING;
            }

            /* The whole token at once, and only if it is one. It used to set the
             * state on the first character and let the rest run on unread. */
            i = scalar_end(json, len, i);

            if (i == 0) {
                return AAMIO_E_ENCODING;
            }

            was = AT_VALUE;

            continue;
        }

        i++;
    }

    /* A body that stopped before its last brace is what a truncated answer looks
     * like, and it used to be read as an answer. A string cut off is caught
     * above, where the string is read. */
    return (depth != 0 || !closed || was == AT_NAME) ? AAMIO_E_ENCODING : AAMIO_OK;
}

int aamio_json_number(const char *json, size_t len, const char *name, long *out)
{
    const char *value = NULL;
    size_t value_len = 0;
    long total = 0;
    int negative = 0;
    size_t i = 0;
    int problem = aamio_json_field(json, len, name, &value, &value_len);

    if (problem != AAMIO_OK) {
        return problem;
    }

    if (out == NULL || value_len == 0) {
        return AAMIO_E_ARG;
    }

    if (value[0] == '-') {
        negative = 1;
        i = 1;
    }

    if (i >= value_len) {
        return AAMIO_E_ENCODING;
    }

    /* 041 is not JSON, and a reader that takes it takes 041 and 41 as the same
     * cursor from a service that sent neither. */
    if (value[i] == '0' && value_len - i > 1) {
        return AAMIO_E_ENCODING;
    }

    for (; i < value_len; i++) {
        if (value[i] < '0' || value[i] > '9') {
            return AAMIO_E_ENCODING;
        }

        /* A cursor is a number the caller acts on. 99999999999999999999 wrapped a
         * long and moved the cursor to 1661992959: undefined behaviour, and a
         * position nobody chose. Refused rather than wrapped. */
        if (total > (2147483647L - (value[i] - '0')) / 10) {
            return AAMIO_E_ENCODING;
        }

        total = total * 10 + (value[i] - '0');
    }

    *out = negative ? -total : total;

    return AAMIO_OK;
}
