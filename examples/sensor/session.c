#include "session.h"

#include <string.h>

static int put_number(char *out, size_t out_size, size_t at, long value)
{
    char digits[24];
    size_t wrote = 0;
    size_t i;

    if (value == 0) {
        digits[wrote++] = '0';
    }

    while (value > 0) {
        digits[wrote++] = (char) ('0' + (value % 10));
        value /= 10;
    }

    if (at + wrote + 1 > out_size) {
        return AAMIO_E_SMALL;
    }

    for (i = 0; i < wrote; i++) {
        out[at + i] = digits[wrote - 1 - i];
    }

    return (int) (at + wrote);
}

int aamio_session_open(aamio_session *session, const char *id, size_t id_len)
{
    int problem;

    if (session == NULL || id == NULL) {
        return AAMIO_E_ARG;
    }

    if (id_len < AAMIO_ID_MIN || id_len > AAMIO_ID_MAX) {
        return AAMIO_E_ARG;
    }

    memset(session, 0, sizeof *session);
    problem = aamio_address(id, id_len, session->w);

    if (problem != AAMIO_OK) {
        return problem;
    }

    memcpy(session->id, id, id_len);
    session->id[id_len] = '\0';
    session->id_len = id_len;

    return AAMIO_OK;
}

int aamio_session_write_path(const aamio_session *session, char *out, size_t out_size)
{
    if (session == NULL || out == NULL) {
        return AAMIO_E_ARG;
    }

    if (out_size < AAMIO_ADDRESS_LEN + 2) {
        return AAMIO_E_SMALL;
    }

    out[0] = '/';
    memcpy(out + 1, session->w, AAMIO_ADDRESS_LEN);
    out[AAMIO_ADDRESS_LEN + 1] = '\0';

    return AAMIO_OK;
}

int aamio_session_read_path(const aamio_session *session, char *out, size_t out_size)
{
    static const char after[] = "/after/";
    long from;
    size_t at;
    int wrote;

    if (session == NULL || out == NULL) {
        return AAMIO_E_ARG;
    }

    /* A message this device would not take is stepped over here and nowhere
     * else. Asking for it again with the same budget would answer the same
     * thing for as long as the thread lives. */
    from = session->left_unread > session->after ? session->left_unread : session->after;

    if (from == 0) {
        return aamio_session_write_path(session, out, out_size);
    }

    if (out_size < AAMIO_ADDRESS_LEN + sizeof after + 2) {
        return AAMIO_E_SMALL;
    }

    out[0] = '/';
    memcpy(out + 1, session->w, AAMIO_ADDRESS_LEN);
    memcpy(out + 1 + AAMIO_ADDRESS_LEN, after, sizeof after - 1);
    at = 1 + AAMIO_ADDRESS_LEN + sizeof after - 1;
    wrote = put_number(out, out_size, at, from);

    if (wrote < 0) {
        return wrote;
    }

    out[wrote] = '\0';

    return AAMIO_OK;
}

int aamio_session_take_answer(aamio_session *session, const char *json, size_t len)
{
    const char *value = NULL;
    size_t value_len = 0;
    long next = 0;
    int messages = 0;

    if (session == NULL || json == NULL) {
        return AAMIO_E_ARG;
    }

    /* Checked whole before anything here is believed. A body cut off by a full
     * buffer reads fine as far as it goes, and its fields moved the cursor past
     * messages that never arrived. On a bad answer the session is left exactly as
     * it was, so the next read asks for the same thing again.
     *
     * exists is required as well: an answer without it is not this service's, and
     * a stray object with next in it used to be enough to move the cursor.
     */
    if (aamio_json_whole(json, len) != AAMIO_OK) {
        return AAMIO_E_ENCODING;
    }

    if (aamio_json_field(json, len, "exists", &value, &value_len) != AAMIO_OK) {
        return AAMIO_E_ENCODING;
    }

    if (!(value_len == 4 && memcmp(value, "true", 4) == 0)
        && !(value_len == 5 && memcmp(value, "false", 5) == 0)) {
        return AAMIO_E_ENCODING;
    }

    /* A required field has a shape as well as a name. messages as a number is
     * well formed JSON and not an answer, and it was enough to move the cursor.
     * The check runs only where messages is expected: an answer that says the
     * thread is gone carries none. */
    if (value_len == 4) {
        const char *listed = NULL;
        size_t listed_len = 0;

        if (aamio_json_field(json, len, "messages", &listed, &listed_len) != AAMIO_OK
            || listed_len == 0 || listed[0] != '[') {
            return AAMIO_E_ENCODING;
        }
    }

    session->more = 0;
    session->left_unread = 0;
    session->left_bytes = 0;

    /* exists: false is a thread nobody has written to yet, one that expired
     * and was swept, or one a restart took away. The cursor stays where it is:
     * a write opens a new thread here and it counts from one again. */
    if (value_len == 5 && memcmp(value, "false", 5) == 0) {
        session->gone = 1;

        return 0;
    }

    session->gone = 0;

    if (aamio_json_field(json, len, "more", &value, &value_len) == AAMIO_OK
        && value_len == 4 && memcmp(value, "true", 4) == 0) {
        session->more = 1;
    }

    /* Named with its size rather than cut, because a signed message is never
     * half sent. Remembered so the next path goes past it. */
    if (aamio_json_field(json, len, "too_large", &value, &value_len) == AAMIO_OK) {
        long seq = 0;
        long bytes = 0;

        if (aamio_json_number(value, value_len, "seq", &seq) == AAMIO_OK) {
            session->left_unread = seq;
            aamio_json_number(value, value_len, "bytes", &bytes);
            session->left_bytes = bytes;
        }
    }

    if (aamio_json_number(json, len, "next", &next) == AAMIO_OK && next > session->after) {
        session->after = next;
    } else if (aamio_json_field(json, len, "reset", &value, &value_len) == AAMIO_OK) {
        /* A lower cursor after a reset is the one to keep: the thread at this
         * address counts from one again, and holding the old number would read
         * nothing until the new one passed it. The device's own record of what
         * it has already carried out is not the service's cursor and does not
         * move with it. */
        if (aamio_json_number(json, len, "next", &next) == AAMIO_OK) {
            session->after = next;
        }
    }

    if (aamio_json_field(json, len, "messages", &value, &value_len) == AAMIO_OK) {
        size_t i;
        int depth = 0;
        int in_string = 0;

        for (i = 0; i < value_len; i++) {
            char c = value[i];

            if (in_string) {
                if (c == '\\') {
                    i++;
                } else if (c == '"') {
                    in_string = 0;
                }
            } else if (c == '"') {
                in_string = 1;
            } else if (c == '{') {
                if (depth == 0) {
                    messages++;
                }

                depth++;
            } else if (c == '}') {
                depth--;
            }
        }
    }

    return messages;
}
