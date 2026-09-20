/* The sensor loop's own logic: the cursor, more, and a message too large.
 *
 * The ESP-IDF glue beside it cannot be run here, so everything that can go
 * wrong quietly was put on this side of the line and is run here instead.
 * The answers below are the shapes the service actually returns; the bytes
 * were measured against production on 20 September 2026.
 */

#include "../examples/sensor/session.h"

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

int main(void)
{
    aamio_session session;
    char path[64];
    int carried;

    printf("\nthe sensor loop\n");

    check(aamio_session_open(&session, "abcdefghijklmnopqrstuvwxyz", 26) == AAMIO_OK,
          "a read key opens a session", NULL);
    check(memcmp(session.w, "ohcibx4t22xc6hx22fch", 20) == 0,
          "and the address is the one the other clients derive", NULL);

    aamio_session_write_path(&session, path, sizeof path);
    check(strcmp(path, "/ohcibx4t22xc6hx22fch") == 0, "the write path is the address", path);

    aamio_session_read_path(&session, path, sizeof path);
    check(strcmp(path, "/ohcibx4t22xc6hx22fch") == 0, "and the first read has no cursor yet", path);

    /* One message, and the service says there is another page. */
    {
        static const char answer[] =
            "{\"w\":\"ohcibx4t22xc6hx22fch\",\"exists\":true,\"created_at\":1,\"expire_at\":2,"
            "\"count\":5,\"allow\":[],\"messages\":[{\"seq\":1,\"body\":\"{\\\"t\\\":21.4}\"}],"
            "\"next\":1,\"waited\":0,\"more\":true}";

        carried = aamio_session_take_answer(&session, answer, sizeof answer - 1);
        check(carried == 1, "an answer carrying one message says so", NULL);
        check(session.after == 1, "the cursor moves to the last message handed over", NULL);
        check(session.more == 1, "and more says to read again rather than sleep", NULL);
    }

    aamio_session_read_path(&session, path, sizeof path);
    check(strcmp(path, "/ohcibx4t22xc6hx22fch/after/1") == 0, "the next read continues from there", path);

    /* A message this device will not take: named, not cut, not dropped. */
    {
        static const char answer[] =
            "{\"w\":\"ohcibx4t22xc6hx22fch\",\"exists\":true,\"created_at\":1,\"expire_at\":2,"
            "\"count\":5,\"allow\":[],\"messages\":[],\"next\":1,\"waited\":0,\"more\":true,"
            "\"too_large\":{\"seq\":2,\"bytes\":20180,\"fix\":\"This message alone is larger than "
            "the X-Max-Bytes you asked for, and a signed message is never cut.\"}}";

        carried = aamio_session_take_answer(&session, answer, sizeof answer - 1);
        check(carried == 0, "a page with nothing in it carries nothing", NULL);
        check(session.left_unread == 2 && session.left_bytes == 20180,
              "and the one that did not fit is remembered with its size", NULL);
    }

    aamio_session_read_path(&session, path, sizeof path);
    check(strcmp(path, "/ohcibx4t22xc6hx22fch/after/2") == 0,
          "the next read steps past it, so the same answer does not come back for ever", path);

    /* Two messages, nothing left. */
    {
        static const char answer[] =
            "{\"w\":\"ohcibx4t22xc6hx22fch\",\"exists\":true,\"created_at\":1,\"expire_at\":2,"
            "\"count\":5,\"allow\":[],\"messages\":[{\"seq\":3,\"body\":\"a\"},{\"seq\":4,"
            "\"body\":\"b, with a comma and a \\\"quote\\\"\"}],\"next\":4,\"waited\":0}";

        carried = aamio_session_take_answer(&session, answer, sizeof answer - 1);
        check(carried == 2, "two messages are counted as two, commas and quotes inside them notwithstanding", NULL);
        check(session.after == 4 && session.more == 0, "the cursor follows and there is nothing left", NULL);
        check(session.left_unread == 0, "and nothing is still being stepped over", NULL);
    }

    /* The thread at this address is gone, and the cursor goes with it.
     *
     * This check used to assert the opposite, with the right fact and the wrong
     * conclusion drawn from it: whatever opens here next counts from one again, so
     * a cursor of four would read nothing until the new thread passed four, and its
     * first four messages would be skipped without a word. The health check and
     * Codex both named it on 20 September 2026. aamio-python has forgotten the
     * thread at this point since it had a cursor at all. */
    {
        static const char answer[] =
            "{\"w\":\"ohcibx4t22xc6hx22fch\",\"exists\":false,\"next\":0,\"note\":\"There is no "
            "thread at this address.\"}";

        carried = aamio_session_take_answer(&session, answer, sizeof answer - 1);
        check(carried == 0 && session.gone == 1, "a thread that is gone says so", NULL);
        check(session.after == 0, "and the cursor goes with it, so the next thread here is read from its first message", NULL);
    }

    /* A reset: the thread here counts from one again, and the lower cursor is
     * the one to keep. Holding the old number would read nothing for ever. */
    {
        static const char answer[] =
            "{\"w\":\"ohcibx4t22xc6hx22fch\",\"exists\":true,\"created_at\":9,\"expire_at\":10,"
            "\"count\":1,\"allow\":[],\"messages\":[{\"seq\":1,\"body\":\"new thread\"}],"
            "\"next\":1,\"waited\":0,\"reset\":{\"after\":4,\"newest\":1,\"what\":\"the cursor "
            "belongs to an earlier thread\"}}";

        carried = aamio_session_take_answer(&session, answer, sizeof answer - 1);
        check(carried == 1 && session.after == 1,
              "a reset hands back a lower cursor, and it is taken rather than ignored", NULL);
    }


    /* An answer that is not one. Found by a Codex review on 20 September, hours
     * after this was written: "not JSON" read as an empty success, a body cut off
     * by a full buffer read as "nothing more, sleep", and {"next":10} moved the
     * cursor from 4 to 10 and stepped over messages that were never delivered.
     * That last one is silent loss. Nothing is believed from a document that is
     * not complete, and a refused answer leaves the session exactly as it was. */
    {
        static const char *const rubbish[] = {
            "not JSON",
            "",
            "{\"next\":10}",
            "{\"messages\":[{\"seq\":1}],\"next\":1",
            "{\"exists\":true,\"messages\":[{\"body\":\"half",
            "{\"exists\":true,\"messages\":7,\"next\":9}",
            "{\"messages\":[{\"seq\":5}],\"next\":5}",
            "{\"exists\":\"maybe\",\"messages\":[],\"next\":9}",
            "{\"exists\":true,\"messages\":[]} trailing",
            /* Balanced is not a grammar, and a long can wrap. All four moved the
             * cursor until 20 September; the last moved it to 1661992959. */
            "{\"exists\":true,\"messages\":[],\"next\":9,}",
            "{\"exists\":true,\"messages\":[],,\"next\":9}",
            "{\"exists\":true \"messages\":[] \"next\":9}",
            "{\"exists\":true,\"messages\":[],\"next\":99999999999999999999}",
        };
        size_t which;
        int refused = 0;
        int moved = 0;
        long before = session.after;

        for (which = 0; which < sizeof rubbish / sizeof rubbish[0]; which++) {
            if (aamio_session_take_answer(&session, rubbish[which], strlen(rubbish[which])) < 0) {
                refused++;
            }

            if (session.after != before) {
                moved++;
            }
        }

        check(refused == (int) (sizeof rubbish / sizeof rubbish[0]),
              "every answer that is not a whole one is refused", NULL);
        check(moved == 0, "and none of them moves the cursor past a message nobody read", NULL);
    }

    /* And a whole one is still taken, after all that. */
    {
        static const char answer[] =
            "{\"w\":\"ohcibx4t22xc6hx22fch\",\"exists\":true,"
            "\"messages\":[{\"seq\":9}],\"next\":9,\"waited\":0}";

        check(aamio_session_take_answer(&session, answer, sizeof answer - 1) == 1
              && session.after == 9, "and a whole answer is still taken", NULL);
    }

    printf("\n%d checks, %d failed\n", checks, failures);

    return failures == 0 ? 0 : 1;
}
