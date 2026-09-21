/* What an answer has to be before this session believes any of it.
 *
 * From Codex, 20 September 2026: every truncation was refused, and some
 * malformed answers and wrong field types were still taken, and the cursor
 * could move on them. Some refusals also changed the session before returning
 * the error, although the function's own docblock says an answer it refuses
 * leaves the session exactly as it was, so the next read asks for the same
 * thing again.
 *
 * That promise is the thing measured here: every bad answer is fed to a session
 * in a known state, and the whole struct is compared byte for byte afterwards.
 * A parser that reports an error and moves the cursor on the way is worse than
 * one that does neither, because the caller is told to try again and the retry
 * asks for something else.
 *
 * The good answers at the bottom are here so that the refusals above cannot be
 * bought by refusing everything.
 *
 * The deep health check of 21 September 2026 found more: a bare word where a
 * value belongs, an escape that is not JSON's, a message that is null, and
 * reset:false read as a reset, all moving the cursor. Those and their kin are in
 * testdata/answers.json, the one corpus the Python suites read too, and arrive
 * here through the generated answers.h. A case that is only in one suite is a
 * difference between the runtimes that nobody is told about.
 */

#include "../examples/sensor/session.h"
#include "answers.h"

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

/* A session mid-conversation: a cursor, a message left unread, more to come.
 * The numbers are the corpus's, so its answers mean here what they mean there. */
static void arrange(aamio_session *session)
{
    aamio_session_open(session, "abcdefghijklmnopqrstuvwxyz", 26);
    session->after = CORPUS_AFTER;
    session->more = CORPUS_MORE;
    session->left_unread = CORPUS_LEFT_UNREAD;
    session->left_bytes = CORPUS_LEFT_BYTES;
    session->gone = 0;
}

/* strlen, not a number typed beside the string: three of those were miscounted
 * here, and a length that disagrees with its string tests the parser on bytes
 * nobody wrote. */
static int took(aamio_session *session, const char *json)
{
    return aamio_session_take_answer(session, json, strlen(json));
}

/* Fed one answer, refused, and not a byte of the session different afterwards. */
static void refuses(const char *json, const char *what)
{
    aamio_session session;
    aamio_session before;
    int result;

    arrange(&session);
    memcpy(&before, &session, sizeof before);
    result = aamio_session_take_answer(&session, json, strlen(json));

    if (result >= 0) {
        check(0, what, "it was accepted");

        return;
    }

    check(memcmp(&before, &session, sizeof before) == 0, what,
          "refused, and the session changed anyway");
}

int main(void)
{
    aamio_session session;
    int carried;
    size_t which;

    printf("\nan answer this session will not believe\n");

    /* Not JSON at all, or not one object. */
    refuses("", "an empty body");
    refuses("   ", "whitespace");
    refuses("null", "a bare null");
    refuses("[]", "an array");
    refuses("{\"exists\":true,\"messages\":[]} trailing", "something after the object");
    refuses("{\"exists\":true,\"messages\":[]}{\"exists\":true,\"messages\":[]}", "two objects");
    refuses("{\"exists\":true,\"messages\":[],}", "a trailing comma");
    refuses("{\"exists\":true,,\"messages\":[]}", "a double comma");
    refuses("{\"exists\":true \"messages\":[]}", "two names with no comma");
    refuses("{\"exists\":true,\"messages\":[]", "an object that never closes");
    refuses("{\"exists\":true,\"messages\":[}", "brackets that cross");
    refuses("{\"exists\"true,\"messages\":[]}", "a name with no colon");
    refuses("{\"exists\":,\"messages\":[]}", "a colon with no value");
    refuses("{\"exists\":true,\"messages\":[],\"next\":}", "a field with no value at the end");

    /* The required fields, and their shapes. */
    refuses("{\"messages\":[]}", "no exists at all");
    refuses("{\"exists\":1,\"messages\":[]}", "exists as a number");
    refuses("{\"exists\":\"true\",\"messages\":[]}", "exists as a string");
    refuses("{\"exists\":null,\"messages\":[]}", "exists as null");
    refuses("{\"exists\":true}", "no messages on a thread that exists");
    refuses("{\"exists\":true,\"messages\":3}", "messages as a number");
    refuses("{\"exists\":true,\"messages\":\"[]\"}", "messages as a string");
    refuses("{\"exists\":true,\"messages\":{}}", "messages as an object");
    refuses("{\"exists\":true,\"messages\":null}", "messages as null");

    /* The cursor. A number this client cannot represent is not a cursor, and
     * neither is a string that looks like one. */
    refuses("{\"exists\":true,\"messages\":[],\"next\":\"41\"}", "next as a string");
    refuses("{\"exists\":true,\"messages\":[],\"next\":true}", "next as a boolean");
    refuses("{\"exists\":true,\"messages\":[],\"next\":null}", "next as null");
    refuses("{\"exists\":true,\"messages\":[],\"next\":4.5}", "next with a fraction");
    refuses("{\"exists\":true,\"messages\":[],\"next\":1e3}", "next in exponent form");
    refuses("{\"exists\":true,\"messages\":[],\"next\":+41}", "next with a leading plus");
    refuses("{\"exists\":true,\"messages\":[],\"next\":041}", "next with a leading zero");
    refuses("{\"exists\":true,\"messages\":[],\"next\":2147483648}", "next past what a long holds here");
    refuses("{\"exists\":true,\"messages\":[],\"next\":99999999999999999999}", "next far past it");
    refuses("{\"exists\":true,\"messages\":[],\"next\":-1}", "a cursor that goes backwards on its own");

    /* more and too_large: wrong shapes must not be half believed. */
    refuses("{\"exists\":true,\"messages\":[],\"more\":\"true\"}", "more as a string");
    refuses("{\"exists\":true,\"messages\":[],\"more\":1}", "more as a number");
    refuses("{\"exists\":true,\"messages\":[],\"too_large\":7}", "too_large as a number");
    refuses("{\"exists\":true,\"messages\":[],\"too_large\":{\"seq\":\"7\"}}", "a seq that is a string");
    refuses("{\"exists\":true,\"messages\":[],\"too_large\":{\"seq\":-7}}", "a seq that is negative");

    printf("\nand what it does believe\n");

    arrange(&session);
    carried = took(&session, "{\"exists\":true,\"messages\":[],\"next\":41}");
    check(carried == 0 && session.after == 41 && session.more == 0 && session.left_unread == 0,
          "a plain answer moves the cursor and clears what the last one left", NULL);

    arrange(&session);
    carried = took(&session,
        "{\"exists\":true,\"messages\":[{\"seq\":41,\"body\":\"x\"}],\"next\":41,\"more\":true}");
    check(carried == 1 && session.more == 1 && session.after == 41,
          "one message, and more says to read again at once", NULL);

    arrange(&session);
    carried = took(&session,
        "{\"exists\":true,\"messages\":[],\"next\":40,\"too_large\":{\"seq\":41,\"bytes\":70000}}");
    check(carried == 0 && session.left_unread == 41 && session.left_bytes == 70000,
          "a message too large is remembered by seq and size", NULL);

    /* A thread that is not there. Whatever opens at this address next counts
     * from one, so a cursor from the thread that is gone would skip its first
     * messages. Codex and the health check on 20 September both said so. */
    arrange(&session);
    carried = took(&session, "{\"exists\":false,\"next\":0}");
    check(carried == 0 && session.gone == 1, "a thread that is not there says so", NULL);
    check(session.after == 0,
          "and the cursor goes with it: a new thread here counts from one, and the old number would skip its first messages",
          NULL);

    /* The corpus shared with the Python suites: testdata/answers.json, through
     * answers.h. Every refusal leaves the session untouched, byte for byte, and
     * every answer taken lands where the corpus says. */
    printf("\nthe shared corpus, refused without a byte of the session changing\n");

    for (which = 0; which < sizeof CORPUS_REFUSED / sizeof CORPUS_REFUSED[0]; which++) {
        refuses(CORPUS_REFUSED[which].answer, CORPUS_REFUSED[which].what);
    }

    printf("\nand taken, so that refusing everything cannot pass\n");

    for (which = 0; which < sizeof CORPUS_TAKEN / sizeof CORPUS_TAKEN[0]; which++) {
        arrange(&session);
        carried = took(&session, CORPUS_TAKEN[which].answer);
        check(carried == CORPUS_TAKEN[which].messages && session.after == CORPUS_TAKEN[which].after,
              CORPUS_TAKEN[which].what, carried < 0 ? "refused" : "taken, but not as the corpus says");
    }

    printf("\n%d passed, %d failed\n", checks - failures, failures);

    return failures == 0 ? 0 : 1;
}
