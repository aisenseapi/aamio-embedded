"""A signed write, all the way to what the service reports back.

    python python/test/live_signed.py
    micropython python/test/live_signed.py

This is the path the README describes and nothing had walked: sign_input, then
b64url_encode, then X-Key and X-Sig on a write to an inbox that lists exactly one
key. The allowlist is what makes it a test rather than a demonstration -- an
unsigned write has to be turned away, or the signed one proves nothing.

It found the reason it exists: `Http.write` used to take `allow` and `ttl` and
send them on a POST, which reads neither. A caller set an allowlist, got 201, and
had an inbox anyone could fill.

The signer is `ed25519_reference.py` beside this file: test material, not a signer
for a device. Read its docstring before copying it anywhere.
"""

import os
import sys

try:
    HERE = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, HERE)
    sys.path.insert(0, os.path.dirname(HERE))
except AttributeError:
    # MicroPython has no os.path, so this one is run from the repository root.
    sys.path.insert(0, "python/test")
    sys.path.insert(0, "python")

import aamio               # noqa: E402
import aamio_http          # noqa: E402
import ed25519_reference   # noqa: E402

try:
    HOST = os.environ.get("AAMIO_HOST", "https://aamio.at")
except AttributeError:
    # MicroPython has getenv but no environ.
    HOST = os.getenv("AAMIO_HOST") or "https://aamio.at"

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


# RFC 8032's own first vector, so a signer that is merely deterministic is not
# mistaken for one that is right.
RFC_SECRET = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
RFC_SIG = ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
           "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")

print("the signer, against RFC 8032")
check("".join("%02x" % b for b in ed25519_reference.sign(RFC_SECRET, b"")) == RFC_SIG,
      "test 1 signature matches the RFC")

seed = os.urandom(32)
scalar, _ = ed25519_reference.secret_expand(seed)
key_text = aamio.b64url_encode(
    ed25519_reference.point_compress(ed25519_reference.point_mul(scalar, ed25519_reference.G)))

print("the key, through the module's own encoder")
check(len(key_text) == 43, "the public key is 43 characters of base64url")
aamio.check_key_shape(key_text)
check(True, "and the module's shape check takes what its encoder wrote")


def sign_for(w, body):
    return aamio.b64url_encode(ed25519_reference.sign(seed, aamio.sign_input(w, body)))


alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
session = aamio.Session("".join(alphabet[byte % 36] for byte in os.urandom(32)))
http = aamio_http.Http(host=HOST)

print("an inbox that lists one key: " + session.w)
opened = http.open(session, ttl=120, allow=key_text)
check(key_text in str(opened.get("allow")), "the thread lists it back")

try:
    http.write(session.w, '{"x":1}', allow=key_text)
    check(False, "an allowlist on a write is refused rather than sent where it is not read")
except ValueError:
    check(True, "an allowlist on a write is refused rather than sent where it is not read")

first = '{"text":"signed by the key that is allowed"}'
status, answer = http.write(session.w, first, key=key_text, signature=sign_for(session.w, first))
check(status == 201, "the signed write is taken: %d" % status)
check('"verified":true' in answer.replace(" ", ""), "and the service verified the signature")

status, answer = http.write(session.w, '{"text":"no key at all"}')
check(status == 403, "the unsigned write is refused: %d" % status)
check("fix" in answer, "with a fix rather than only a number")

wrong = aamio.b64url_encode(bytes(64))
status, answer = http.write(session.w, first, key=key_text, signature=wrong)
check(status in (400, 401, 403), "a signature of the right shape that is not one: %d" % status)

print("and what the reader can check")
messages = session.take_answer(http.read(session, limit=10, max_bytes=8192))
check(len(messages) == 1, "one message in the thread, not three: %d" % len(messages))
check(messages[0].get("verified") is True, "it says verified")
check(messages[0].get("from") == key_text, "and names the key that signed")
check(aamio.body_of(messages[0]) == first, "the body matches the hash it came with")

signed_bytes = aamio.signed_bytes_of(messages[0], session.w)
check(signed_bytes == aamio.sign_input(session.w, first),
      "the ninety-four bytes recomputed from the message are the ones that were signed")
check(aamio.sender_is_allowed(messages[0], session.w, [key_text],
                              lambda k, s, m: m == signed_bytes) is True,
      "and the sender check hands the verifier those bytes")

print()
print("%d passed, %d failed" % (passed, failed))

if failed:
    raise SystemExit(1)
