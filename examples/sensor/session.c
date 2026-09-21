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

/* One field, required to be there and to be the kind of thing it should be.
 * A reader that strips the quotes cannot tell true from "true", so the type
 * is asked for and compared: exists:"true" was read as a thread that exists
 * and messages:"[]" as a list of none, both until 20 September 2026. */
static int field_of_kind(const char *json, size_t len, const char *name, int kind,
                         const char **value, size_t *value_len)
{
    int type = 0;

    if (aamio_json_typed(json, len, name, value, value_len, &type) != AAMIO_OK) {
        return 0;
    }

    return type == kind;
}

/* true or false, and nothing else wearing their letters. */
static int boolean_of(const char *json, size_t len, const char *name, int *out)
{
    const char *value = NULL;
    size_t value_len = 0;

    if (!field_of_kind(json, len, name, AAMIO_JSON_LITERAL, &value, &value_len)) {
        return 0;
    }

    if (value_len == 4 && memcmp(value, "true", 4) == 0) {
        *out = 1;

        return 1;
    }

    if (value_len == 5 && memcmp(value, "false", 5) == 0) {
        *out = 0;

        return 1;
    }

    return 0;
}

/* A number that counts forwards, in a field that is a number and not a string
 * wearing one. bytes:"7" used to be taken as 7: the field reader strips the
 * quotes, so the type has to be asked for as well. */
static int counting_number_of(const char *json, size_t len, const char *name, long *out)
{
    const char *value = NULL;
    size_t value_len = 0;

    return field_of_kind(json, len, name, AAMIO_JSON_NUMBER, &value, &value_len)
           && aamio_json_number(json, len, name, out) == AAMIO_OK
           && *out >= 0;
}

/* The messages, each of them the shape of a message, and how many there are.
 * Each has to be an object with a seq that counts forwards and a body that is
 * text, and that has to hold for all of them before the cursor moves past any:
 * messages:[null] counted as none and moved the cursor, and messages:[7] the
 * same, so what the service said it delivered was marked read unseen. The
 * array itself has been through aamio_json_whole, so the walk here can trust
 * the brackets and the strings and look only at what each element is. */
static int messages_are_shaped(const char *list, size_t len, int *count)
{
    size_t i = 1;   /* past the opening bracket */
    int found = 0;

    for (;;) {
        const char *value = NULL;
        size_t value_len = 0;
        size_t from;
        int depth = 0;
        int quoted = 0;
        long seq = 0;

        while (i < len && (list[i] == ' ' || list[i] == '\n' || list[i] == '\r' || list[i] == '\t')) {
            i++;
        }

        if (i >= len) {
            return 0;
        }

        if (list[i] == ']') {
            break;
        }

        /* null, a number, a string, a list: not a message. */
        if (list[i] != '{') {
            return 0;
        }

        from = i;

        for (; i < len; i++) {
            char c = list[i];

            if (quoted) {
                if (c == '\\') {
                    i++;
                } else if (c == '"') {
                    quoted = 0;
                }

                continue;
            }

            if (c == '"') {
                quoted = 1;
            } else if (c == '{' || c == '[') {
                depth++;
            } else if (c == '}' || c == ']') {
                depth--;

                if (depth == 0) {
                    i++;

                    break;
                }
            }
        }

        if (depth != 0) {
            return 0;
        }

        if (!counting_number_of(list + from, i - from, "seq", &seq)
            || !field_of_kind(list + from, i - from, "body", AAMIO_JSON_STRING, &value, &value_len)) {
            return 0;
        }

        found++;

        while (i < len && (list[i] == ' ' || list[i] == '\n' || list[i] == '\r' || list[i] == '\t')) {
            i++;
        }

        if (i < len && list[i] == ',') {
            i++;
        }
    }

    *count = found;

    return 1;
}

int aamio_session_take_answer(aamio_session *session, const char *json, size_t len)
{
    const char *value = NULL;
    size_t value_len = 0;
    long next = 0;
    long seq = 0;
    long bytes = 0;
    int messages = 0;
    int exists = 0;
    int more = 0;
    int has_next = 0;
    int has_reset = 0;

    if (session == NULL || json == NULL) {
        return AAMIO_E_ARG;
    }

    /* Everything is read into these locals and checked here. Nothing below this
     * block touches the session until the last check has passed, because the
     * promise this function makes is that an answer it refuses leaves the session
     * exactly as it was, so the next read asks for the same thing again. It used
     * to set gone, more and the unread message on the way to checks that could
     * still fail, and then return an error over a session it had already moved.
     *
     * Checked whole first. A body cut off by a full buffer reads fine as far as it
     * goes, and its fields moved the cursor past messages that never arrived.
     */
    if (aamio_json_whole(json, len) != AAMIO_OK) {
        return AAMIO_E_ENCODING;
    }

    /* exists is required: an answer without it is not this service's, and a stray
     * object with next in it used to be enough to move the cursor. */
    if (!boolean_of(json, len, "exists", &exists)) {
        return AAMIO_E_ENCODING;
    }

    if (exists) {
        /* A required field has a shape as well as a name. messages as a number is
         * well formed JSON and not an answer, and it was enough to move the cursor.
         * An answer that says the thread is gone carries none. */
        if (!field_of_kind(json, len, "messages", AAMIO_JSON_ARRAY, &value, &value_len)
            || !messages_are_shaped(value, value_len, &messages)) {
            return AAMIO_E_ENCODING;
        }

        if (aamio_json_field(json, len, "more", &value, &value_len) == AAMIO_OK
            && !boolean_of(json, len, "more", &more)) {
            return AAMIO_E_ENCODING;
        }

        /* Named with its size rather than cut, because a signed message is never
         * half sent. An object, with a sequence number that is a number and counts
         * forwards: none of that was checked, so "7" and -7 both got through. */
        if (aamio_json_field(json, len, "too_large", &value, &value_len) == AAMIO_OK) {
            const char *inner = NULL;
            size_t inner_len = 0;

            if (!field_of_kind(json, len, "too_large", AAMIO_JSON_OBJECT, &inner, &inner_len)
                || !counting_number_of(inner, inner_len, "seq", &seq)) {
                return AAMIO_E_ENCODING;
            }

            if (aamio_json_field(inner, inner_len, "bytes", &value, &value_len) == AAMIO_OK
                && !counting_number_of(inner, inner_len, "bytes", &bytes)) {
                return AAMIO_E_ENCODING;
            }
        }

        /* A cursor this client cannot represent is not a cursor, and neither is a
         * string that looks like one, nor a number that counts backwards. Believing
         * the rest of the answer while quietly ignoring next is how a reader ends up
         * at a position nobody chose: the whole answer is refused instead. */
        if (aamio_json_field(json, len, "next", &value, &value_len) == AAMIO_OK) {
            if (!field_of_kind(json, len, "next", AAMIO_JSON_NUMBER, &value, &value_len)
                || aamio_json_number(json, len, "next", &next) != AAMIO_OK
                || next < 0) {
                return AAMIO_E_ENCODING;
            }

            has_next = 1;
        }

        /* A reset is an object with the after that was sent and the newest there
         * is: that is the documented shape. The presence of the name used to be
         * the whole signal, so reset:false let the cursor go backwards. */
        if (aamio_json_field(json, len, "reset", &value, &value_len) == AAMIO_OK) {
            const char *inner = NULL;
            size_t inner_len = 0;
            long after = 0;
            long newest = 0;

            if (!field_of_kind(json, len, "reset", AAMIO_JSON_OBJECT, &inner, &inner_len)
                || !counting_number_of(inner, inner_len, "after", &after)
                || !counting_number_of(inner, inner_len, "newest", &newest)) {
                return AAMIO_E_ENCODING;
            }

            has_reset = 1;
        }
    }

    /* Everything checked. From here the session changes and nothing can fail. */
    session->more = 0;
    session->left_unread = 0;
    session->left_bytes = 0;

    /* exists: false is a thread nobody has written to yet, one that expired and was
     * swept, or one a restart took away. The cursor goes with it: whatever opens at
     * this address next counts from one, and an old cursor would read nothing until
     * the new thread passed it. Keeping it was the same fault the reset branch below
     * exists to avoid, one step earlier. */
    if (!exists) {
        session->gone = 1;
        session->after = 0;

        return 0;
    }

    session->gone = 0;
    session->more = more;

    if (seq > 0) {
        session->left_unread = seq;
        session->left_bytes = bytes;
    }

    if (has_next && next > session->after) {
        session->after = next;
    } else if (has_next && has_reset) {
        /* A lower cursor after a reset is the one to keep: the thread at this
         * address counts from one again, and holding the old number would read
         * nothing until the new one passed it. The device's own record of what it
         * has already carried out is not the service's cursor and does not move
         * with it. */
        session->after = next;
    }

    return messages;
}
