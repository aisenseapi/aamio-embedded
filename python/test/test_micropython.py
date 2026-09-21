"""The same checks, run by MicroPython or CircuitPython itself rather than by CPython.

    micropython python/test/test_micropython.py      # from the repository root
    python python/test/test_micropython.py           # the same file, on CPython

`test_aamio.py` is the fuller suite and needs `os.path`, `ast` and other things a
board does not have. This one holds only what both runtimes can run, so the answer
to "does it work under MicroPython" is a run and not an argument. It reads the
shared vectors from the same file every other client uses, so a change there
reaches this too.

What this cannot tell you is how the module behaves on a board: the unix port has
a desktop's memory and a desktop's speed. It tells you the syntax is accepted, the
imports resolve, the derivations agree and the refusals hold.
"""

import sys

sys.path.insert(0, "python")
sys.path.insert(0, "python/test")

import aamio  # noqa: E402

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


def refuses(call, what):
    try:
        call()
    except aamio.AamioError:
        check(True, what)
        return
    except Exception as wrong:                                  # noqa: BLE001
        check(False, what + " (raised something else: %s)" % wrong)
        return

    check(False, what + " (took it)")


with open("testdata/vectors.json") as handle:
    v = aamio.json.loads(handle.read())

print("running under " + str(sys.implementation.name))

print("the shared vectors")
check(aamio._hex(aamio._sha256(b"abc")) == v["sha256_abc"], "sha256 of abc")
check(aamio.address(v["id"]) == v["w"], "the write address: " + v["w"])
check(aamio.scope_address(v["scope"]["key"]) == v["scope"]["address"], "a scope address")
check(aamio.address(v["scope"]["key"]) == v["scope"]["thread_w_of_the_same_string"],
      "and the thread address of the same string is a different one")
check(aamio.sign_input(v["w"], v["body"]).decode() == v["signInput"],
      "the ninety-four bytes that get signed")
check(aamio.key_hash(v["a"]["public"]) == v["a"]["hash"], "the allowlist hash")

check(aamio.b64url_encode(aamio.b64url_decode(v["a"]["public"], 32)) == v["a"]["public"],
      "base64url round trips, so a key can be written as well as read")

print("what is refused")
refuses(lambda: aamio.check_key_shape(v["strayBits"]["key"]), "a key with a stray bit")
refuses(lambda: aamio.check_signature_shape(v["strayBits"]["signature"]),
        "a signature with a stray bit")
refuses(lambda: aamio.check_key_shape(v["a"]["public"] + "A"), "a key one character too long")
refuses(lambda: aamio.address("too short"), "a read key under twenty characters")

print("the session")
s = aamio.Session(v["id"])
check(s.read_path() == "/" + v["w"], "the first read carries no cursor")
check(len(s.take_answer('{"exists":true,"messages":[{"seq":1,"body":"one"},{"seq":2,"body":"two"}],"next":2}')) == 2,
      "two messages come back")
check(s.after == 2 and s.read_path() == "/" + v["w"] + "/after/2", "and the cursor followed")

s.take_answer('{"exists":true,"messages":[],"next":2,"too_large":{"seq":5,"bytes":90000}}')
check(s.read_path() == "/" + v["w"] + "/after/5", "a message too large is stepped over")

was = s.after
refuses(lambda: s.take_answer('{"exists":true,"messages":3,"next":9}'), "messages as a number")
check(s.after == was, "and a refusal left the session where it was")

s.take_answer('{"exists":false}')
check(s.gone and s.after == 0, "exists false forgets the cursor")

print("the shared corpus, testdata/answers.json")
# The same file the C suite reads through answers.h, and the fuller Python suite
# reads directly: what is refused has to be refused on this runtime too, since
# json.loads here takes what CPython's refuses.
with open("testdata/answers.json") as handle:
    corpus = aamio.json.loads(handle.read())


def arranged():
    session = aamio.Session(v["id"])
    session.after = corpus["before"]["after"]
    session.more = corpus["before"]["more"]
    session.left_unread = corpus["before"]["left_unread"]
    session.left_bytes = corpus["before"]["left_bytes"]

    return session


for entry in corpus["refused"]:
    s = arranged()
    refuses(lambda: s.take_answer(entry["answer"]), entry["what"])
    check((s.after, s.more, s.left_unread, s.left_bytes, s.gone)
          == (corpus["before"]["after"], corpus["before"]["more"], corpus["before"]["left_unread"],
              corpus["before"]["left_bytes"], False),
          "    and left the session where it was")

for entry in corpus["taken"]:
    s = arranged()

    try:
        got = s.take_answer(entry["answer"])
        check(len(got) == entry["messages"] and s.after == entry["after"], entry["what"])
    except aamio.AamioError as wrong:
        check(False, entry["what"] + " (refused: %s)" % wrong)

print("what a key is made of")
for what, bad in (("a capital letter", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
                  ("a hyphen", "abcdefghijklm-opqrstuvwxyz"),
                  ("a letter outside ASCII", "abcdefghijklmnopqrstuvwxy\u00e9"),
                  ("a carriage return and a line feed", "abcdefghijklmnopqrstuvwx\r\n")):
    refuses(lambda: aamio.address(bad), "a read key with %s" % what)
    refuses(lambda: aamio.scope_address(bad), "a scope key with %s" % what)

print("a message, and its hash")
payload = '{"reading": 21}'
whole = {"seq": 1, "body": payload, "sha256": aamio._hex(aamio._sha256(payload.encode()))}
check(aamio.body_of(whole) == payload, "a body that matches its hash comes back")
whole["body"] = payload + " "
refuses(lambda: aamio.body_of(whole), "and one that does not is refused")
check(aamio.is_sealed(v["envelopeFromAToB"]) is True,
      "a sealed envelope is recognised, so a device that cannot open one knows")
check(aamio.is_sealed(payload) is False, "and plain text is not mistaken for one")
check(aamio.is_sealed('{"\\u00652ee":"nacl.box.v1","ct":"x","nonce":"y"}') is True,
      "and an envelope whose e2ee is written as a unicode escape is still one")

print("the transport module loads")
import aamio_http  # noqa: E402

check(aamio_http.DEFAULT_MAX_BYTES > 0, "a read has a byte budget by default")
check(aamio_http.Http(transport=1).host == "https://aamio.at",
      "and the host is the service unless told otherwise")

import http_checks  # noqa: E402

http_checks.run(check)

if "--live" in sys.argv:
    # The runtime's own HTTPS, not CPython's. On the unix port and on a board that
    # is `Tls` over the runtime's mbedtls, with the root the service chains to
    # given on the command line as DER, since a board has no CA store of its own:
    #
    #     micropython python/test/test_micropython.py --live --ca isrgrootx1.der
    #
    # What this does not prove is a board's memory or a board's radio.
    import os

    import aamio_http as http_module

    print("live, through this runtime's own HTTPS")
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    key = "".join(alphabet[byte % 36] for byte in os.urandom(32))

    live = aamio.Session(key)

    if sys.implementation.name == "cpython":
        http = http_module.Http()
    else:
        at = sys.argv.index("--ca") if "--ca" in sys.argv else -1

        if at < 0 or at + 1 >= len(sys.argv):
            print("live on this runtime needs --ca <isrgrootx1.der>, the root aamio.at chains to, and the clock set")
            raise SystemExit(2)

        with open(sys.argv[at + 1], "rb") as handle:
            http = http_module.Http(http_module.Tls(handle.read()))

    check(http.transport is not None, "the runtime has something to make requests with")

    opened = http.open(live, ttl=120)
    check(opened.get("expire_at", 0) - opened.get("created_at", 0) == 120,
          "the thread is opened with the lifetime asked for")

    status, _ = http.write(live.w, '{"text":"from micropython"}')
    check(status == 201, "and a write is taken: %d" % status)

    took = live.take_answer(http.read(live, limit=4, max_bytes=4096))
    check(len(took) == 1, "and it comes back: %d" % len(took))
    check(aamio.body_of(took[0]) == '{"text":"from micropython"}',
          "whole, and matching the hash that came with it")
    check(live.after == 1 and live.gone is False, "with the cursor moved and the thread alive")

print()
print("%d passed, %d failed" % (passed, failed))

if failed:
    raise SystemExit(1)
