/* A sensor's side of an aamio thread: the cursor, the limits, and what to do
 * when an answer does not fit.
 *
 * This is the part of an example that can go wrong quietly, so it lives here
 * rather than in the ESP-IDF glue, and it is tested on the host. Nothing in
 * this file touches a socket, a key or a clock.
 *
 * The loop it is built for:
 *
 *     aamio_session_open(&s, id, len);
 *     for (;;) {
 *         aamio_session_read_path(&s, path, sizeof path);
 *         GET path, with X-Read, X-Limit and X-Max-Bytes
 *         aamio_session_take_answer(&s, body, length);
 *         act on what came back
 *         if (!s.more) sleep;
 *     }
 *
 * more says the answer was cut short, so the next read follows at once rather
 * than after a sleep. A message too large for the budget is remembered by seq,
 * and the next path goes past it: unread on purpose, never dropped in silence,
 * and never asked for again in a loop that cannot end.
 */

#ifndef AAMIO_SESSION_H
#define AAMIO_SESSION_H

#include "aamio.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char id[AAMIO_ID_MAX + 1];
    size_t id_len;
    char w[AAMIO_ADDRESS_LEN];
    long after;         /* the cursor: read what is past this */
    int more;           /* the last answer was cut short */
    long left_unread;   /* seq of a message too large to take, or 0 */
    long left_bytes;    /* how large it was, so the caller can decide */
    int gone;           /* the thread expired, or was never written to */
} aamio_session;

/* Holds the key and derives the address. The key is not copied anywhere else. */
int aamio_session_open(aamio_session *session, const char *id, size_t id_len);

/* The path for the next read, including the cursor. Writes a NUL. */
int aamio_session_read_path(const aamio_session *session, char *out, size_t out_size);

/* The path to POST to: just the address. Writes a NUL. */
int aamio_session_write_path(const aamio_session *session, char *out, size_t out_size);

/* Reads what the service answered and moves the cursor. Returns the number of
 * messages the answer carried, or a negative AAMIO_E_* when it could not be
 * read at all. A thread that is gone sets gone and leaves the cursor alone. */
int aamio_session_take_answer(aamio_session *session, const char *json, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* AAMIO_SESSION_H */
