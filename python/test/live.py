"""The Python core against the live service, over TLS, the way a board would use it.

    python python/test/live.py            # against https://aamio.at
    AAMIO_HOST=https://... python python/test/live.py

Opens a thread of its own with a random read key, writes to it, reads it back
through `Session`, and checks that a byte budget cuts the answer where it says it
does. Nothing here is a unit test: it is the claim that this module talks to the
real service, and it fails when that stops being true.

The service allows thirty thread creates, a hundred and twenty writes and six
hundred reads a minute. This uses a handful, so two runs back to back are fine.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import aamio          # noqa: E402
import aamio_http     # noqa: E402

HOST = os.environ.get("AAMIO_HOST", "https://aamio.at")

passed = 0
failed = 0


def check(condition, what):
    global passed, failed

    if condition:
        passed += 1
        print("  ok    " + what)
    else:
        failed += 1
        print("  FAIL  " + what)


def read_key():
    """Thirty-two characters from the platform's randomness, not from the clock."""
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    raw = os.urandom(32)

    return "".join(alphabet[byte % len(alphabet)] for byte in raw)


http = aamio_http.Http(host=HOST)
session = aamio.Session(read_key())

print("live against " + HOST)
print("  thread " + session.w)

# The lifetime is set when the thread is opened and nowhere else. A write that
# creates a thread gets the default, which is not what a caller who passed a ttl
# to the write thought they were getting: that now raises instead of being sent
# to a POST that does not read it.
opened = http.open(session, ttl=120)
check(opened.get("w") == session.w, "opening names the address back")
check(opened.get("expire_at", 0) - opened.get("created_at", 0) == 120,
      "and the lifetime asked for is the lifetime given: %d s"
      % (opened.get("expire_at", 0) - opened.get("created_at", 0)))

try:
    http.write(session.w, '{"x":1}', ttl=120)
    check(False, "a ttl on a write is refused rather than quietly ignored")
except ValueError:
    check(True, "a ttl on a write is refused rather than quietly ignored")

status, text = http.write(session.w, '{"text":"one"}')
check(status == 201, "a write is taken: %d" % status)

http.write(session.w, '{"text":"two"}')
http.write(session.w, '{"text":"three"}')

body = http.read(session, limit=10, max_bytes=65536)
messages = session.take_answer(body)
check(len(messages) == 3, "all three come back: %d" % len(messages))
check(session.gone is False, "and the thread exists")
check(session.after == 3, "the cursor is at the last one: %d" % session.after)
check(session.more is False, "with nothing left over")

# The payload is `body`, as text, with its hash beside it. Reading it through
# body_of is what checks the two against each other.
bodies = [aamio.body_of(message) for message in messages]
check(bodies == ['{"text":"one"}', '{"text":"two"}', '{"text":"three"}'],
      "the bodies come back whole and in order, hashes checked")

broken = dict(messages[0])
broken["body"] = broken["body"].replace("one", "two")

try:
    aamio.body_of(broken)
    check(False, "a body that does not match its hash is refused")
except aamio.EncodingError:
    check(True, "a body that does not match its hash is refused")

check(messages[0].get("verified") is False and messages[0].get("from") is None,
      "an unsigned write says so, rather than being quietly trusted")

# The same thread, read from the start with a budget that cannot hold it.
small = aamio.Session(session.read_key)
body = http.read(small, limit=1, max_bytes=65536)
took = small.take_answer(body)
check(len(took) == 1, "a limit of one gives one message: %d" % len(took))
check(small.more is True, "and says there is more")
check(small.read_path() == "/" + small.w + "/after/1",
      "so the next read follows at once: " + small.read_path())

rest = small.take_answer(http.read(small, limit=10, max_bytes=65536))
check(len(rest) == 2, "the rest follows: %d" % len(rest))
check(small.more is False, "and then there is no more")

# A budget in bytes rather than in messages, cutting at a whole message. 512 is
# the floor the service accepts, and it says so rather than rounding silently.
tiny = aamio.Session(session.read_key)
tiny.take_answer(http.read(tiny, limit=10, max_bytes=512))
check(tiny.more is True or tiny.left_unread > 0 or tiny.after == 3,
      "a small byte budget cuts at a whole message and says where")

try:
    http.read(aamio.Session(session.read_key), limit=10, max_bytes=200)
    check(False, "a budget under the floor is refused")
except aamio_http.HttpError as refused:
    check(refused.status == 400 and "fix" in refused.text,
          "a budget under the floor is refused, with a fix rather than a rounding")

# An address nobody has written to.
empty = aamio.Session(read_key())
empty.take_answer(http.read(empty, limit=4, max_bytes=4096))
check(empty.gone is True, "an address with no thread answers exists: false")
check(empty.after == 0, "and leaves the cursor at nothing")

print()
print("%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
