"""The Python core against the same vectors as every other client, and against itself.

    python python/test/test_aamio.py

Runs on CPython, which is the only place these can run without a board. What that
buys is the derivations and every refusal; what it does not buy is any claim about
how the module behaves under MicroPython's memory or CircuitPython's hashlib. That
is said in the README rather than implied by a green line here.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import aamio  # noqa: E402

VECTORS = os.path.join(os.path.dirname(os.path.dirname(HERE)), "testdata", "vectors.json")

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


def refuses(call, what, kind=aamio.AamioError):
    try:
        call()
    except kind:
        check(True, what)
        return
    except Exception as wrong:                                  # noqa: BLE001
        check(False, what + " (raised %s instead)" % type(wrong).__name__)
        return

    check(False, what + " (took it)")


def unchanged(session, what, body):
    """A refusal leaves the session exactly as it was, which is the whole promise."""
    was = (session.after, session.more, session.left_unread, session.left_bytes, session.gone)
    refuses(lambda: session.take_answer(body), what)
    check(was == (session.after, session.more, session.left_unread,
                  session.left_bytes, session.gone),
          "    and left the session where it was")


with open(VECTORS, encoding="utf-8") as handle:
    v = json.load(handle)

print("the shared vectors")
check(aamio._hex(aamio._sha256(b"abc")) == v["sha256_abc"], "sha256 of abc")
check(aamio.address(v["id"]) == v["w"], "the write address of the read key: " + v["w"])
check(aamio.sign_input(v["w"], v["body"]).decode() == v["signInput"],
      "the bytes that get signed, all ninety-four of them")
check(len(aamio.sign_input(v["w"], v["body"])) == aamio.AAMIO_SIGN_INPUT_LEN,
      "and there are exactly %d" % aamio.AAMIO_SIGN_INPUT_LEN)
check(aamio.key_hash(v["a"]["public"]) == v["a"]["hash"],
      "the allowlist hash is of the key's bytes, not of its text")

print("scopes")
check(aamio.scope_address(v["scope"]["key"]) == v["scope"]["address"], "a scope address")
check(aamio.address(v["scope"]["key"]) == v["scope"]["thread_w_of_the_same_string"],
      "and the thread address of the same string is a different address")
check(aamio.scope_address(v["scope"]["key"]) != aamio.address(v["scope"]["key"]),
      "which is the point of the prefix")

print("what is refused")
aamio.check_key_shape(v["a"]["public"])
aamio.check_signature_shape(v["signature"])
check(True, "the key and the signature from the vectors are taken")
refuses(lambda: aamio.check_key_shape(v["strayBits"]["key"]),
        "a public key with a stray bit is not the same key spelled differently",
        aamio.EncodingError)
refuses(lambda: aamio.check_signature_shape(v["strayBits"]["signature"]),
        "nor is a signature", aamio.EncodingError)
refuses(lambda: aamio.check_key_shape(v["a"]["public"] + "A"),
        "a key one character too long", aamio.LengthError)
refuses(lambda: aamio.check_key_shape(v["a"]["public"][:-1] + "+"),
        "standard base64's + is not base64url", aamio.EncodingError)
refuses(lambda: aamio.check_key_shape(v["a"]["public"][:-1] + "="),
        "and padding is not part of the shape", aamio.EncodingError)
refuses(lambda: aamio.address("too short"), "a read key under twenty characters",
        aamio.LengthError)
refuses(lambda: aamio.scope_address("short"), "a scope key under twenty-six",
        aamio.LengthError)
refuses(lambda: aamio.sign_input("not-an-address", v["body"]),
        "an address of the wrong length", aamio.LengthError)
refuses(lambda: aamio.sign_input("1" * 20, v["body"]),
        "and one with a character base32 does not have", aamio.EncodingError)

print("a message, and what a reader checks for itself")
payload = '{"reading": 21}'
whole = {"seq": 1, "body": payload, "sha256": aamio._hex(aamio._sha256(payload.encode())),
         "from": None, "sig": None, "verified": False}
check(aamio.body_of(whole) == payload, "a body that matches its hash comes back")
refuses(lambda: aamio.body_of(dict(whole, body=payload + " ")),
        "one that does not is refused, whichever way it differs", aamio.EncodingError)
refuses(lambda: aamio.body_of({"seq": 1, "body": payload}),
        "and a message with no hash at all cannot be checked, so it is refused",
        aamio.EncodingError)
check(aamio.is_sealed(v["envelopeFromAToB"]) is True,
      "a sealed envelope says what it is, without asking the service")
check(aamio.is_sealed(payload) is False, "and plain text does not")
check(aamio.is_sealed('{"e2ee":"nacl.box.v1"}') is False,
      "nor does an object that names the format and carries no ciphertext")
check(aamio.signed_bytes_of(whole, v["w"]) == aamio.sign_input(v["w"], payload),
      "the bytes a message's signature covers are the same ninety-four")
refuses(lambda: aamio.sender_is_allowed(whole, v["w"], [v["a"]["public"]], None),
        "a sender check with no verifier refuses rather than answering", aamio.ArgError)
check(aamio.sender_is_allowed(whole, v["w"], [v["a"]["public"]], lambda k, s, m: True) is False,
      "an unsigned message is not from anybody, however willing the verifier")

signed = dict(whole, **{"from": v["a"]["public"], "sig": v["signature"]})
check(aamio.sender_is_allowed(signed, v["w"], [], lambda k, s, m: True) is False,
      "a key nobody listed is refused before any signature is looked at")
check(aamio.sender_is_allowed(signed, v["w"], [v["a"]["hash"]], lambda k, s, m: True) is True,
      "a listed key whose signature verifies is allowed")
check(aamio.sender_is_allowed(signed, v["w"], [v["a"]["public"]], lambda k, s, m: False) is False,
      "and a listed key whose signature does not is not")

print("the session, reading")
s = aamio.Session(v["id"])
check(s.w == v["w"], "opening derives the address")
check(s.read_path() == "/" + v["w"], "the first read has no cursor in it")
check(s.write_path() == "/" + v["w"], "and a write goes to the address itself")

got = s.take_answer('{"exists":true,"messages":[{"seq":1},{"seq":2}],"next":2}')
check(len(got) == 2 and got[1]["seq"] == 2, "two messages come back as they were")
check(s.after == 2, "and the cursor followed next")
check(s.read_path() == "/" + v["w"] + "/after/2", "so the next read asks past them")
check(s.more is False and s.gone is False, "nothing else moved")

s.take_answer('{"exists":true,"messages":[{"seq":3}],"next":3,"more":true}')
check(s.more is True, "more says the answer was cut short")

print("the session, a message it cannot take")
s.take_answer('{"exists":true,"messages":[],"next":3,"too_large":{"seq":4,"bytes":90000}}')
check(s.left_unread == 4 and s.left_bytes == 90000,
      "the one too large is remembered by sequence number and size")
check(s.read_path() == "/" + v["w"] + "/after/4",
      "and the next read steps over it rather than asking again forever")

print("the session, a thread that is gone")
s.take_answer('{"exists":false}')
check(s.gone is True and s.after == 0,
      "exists false forgets the cursor, since whatever opens here next counts from one")
check(s.left_unread == 0, "and the message it was stepping over goes with it")

print("the session, a cursor that goes backwards")
s = aamio.Session(v["id"])
s.take_answer('{"exists":true,"messages":[],"next":9}')
s.take_answer('{"exists":true,"messages":[],"next":2}')
check(s.after == 9, "a lower next on its own is not a cursor to follow")
s.take_answer('{"exists":true,"messages":[],"next":2,"reset":true}')
check(s.after == 2, "but a lower one after a reset is the one to keep")

print("the session, answers it refuses")
s = aamio.Session(v["id"])
s.take_answer('{"exists":true,"messages":[{"seq":1}],"next":1}')
unchanged(s, "an answer cut off by a full buffer",
          '{"exists":true,"messages":[{"seq":2}],"next":2')
unchanged(s, "an answer with no exists at all", '{"messages":[],"next":77}')
unchanged(s, "exists as the string true", '{"exists":"true","messages":[]}')
unchanged(s, "messages as a number", '{"exists":true,"messages":3,"next":5}')
unchanged(s, "messages missing entirely", '{"exists":true,"next":5}')
unchanged(s, "next as a string that looks like one", '{"exists":true,"messages":[],"next":"5"}')
unchanged(s, "next counting backwards", '{"exists":true,"messages":[],"next":-5}')
unchanged(s, "more as a string", '{"exists":true,"messages":[],"more":"true"}')
unchanged(s, "too_large that is not an object",
          '{"exists":true,"messages":[],"too_large":7}')
unchanged(s, "a too_large seq that is a string",
          '{"exists":true,"messages":[],"too_large":{"seq":"7"}}')
unchanged(s, "a too_large seq that counts backwards",
          '{"exists":true,"messages":[],"too_large":{"seq":-7}}')
unchanged(s, "an answer that is an array", '[{"exists":true}]')
check(s.after == 1, "and after all of that the cursor is still where it was")

print("nothing the two runtimes lack")
# These tests run on CPython, where everything works. That is exactly why this
# check exists: an f-string or a three-argument getattr passes here and fails on
# the board, which is the one place nobody can run the suite.
import ast  # noqa: E402

BANNED = {ast.JoinedStr: "an f-string", ast.AsyncFunctionDef: "async def"}
SAFE_IMPORTS = ("hashlib", "adafruit_hashlib", "json", "ujson", "time",
                "urequests", "requests", "urllib.error", "urllib.request",
                "aamio", "aamio_http")

for name in ("aamio.py", "aamio_http.py", "examples/sensor.py"):
    path = os.path.join(os.path.dirname(HERE), name)

    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), path)

    trouble = []

    for node in ast.walk(tree):
        for kind in BANNED:
            if isinstance(node, kind):
                trouble.append("line %d: %s" % (node.lineno, BANNED[kind]))

        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name not in SAFE_IMPORTS:
                    trouble.append("line %d: imports %s" % (node.lineno, alias.name))

        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "getattr" and len(node.args) > 2):
            trouble.append("line %d: getattr with a default" % node.lineno)

    check(not trouble, "%s uses nothing the runtimes lack%s"
          % (name, "" if not trouble else ": " + "; ".join(trouble)))

print()
print("%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
