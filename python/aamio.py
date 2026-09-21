"""The parts of aamio that are easy to get subtly wrong, for MicroPython and CircuitPython.

The same job as the C core in this repository, and the same refusals, for boards
that run Python instead: a write address from a read key, which exact bytes get
signed, how a public key is encoded and which spellings are refused, and a read
session that steps over a message it cannot take rather than asking for it again
forever.

What is deliberately not here, for the same reason it is not in the C:

  * Ed25519. Neither runtime has it, and a pure-Python signature on a board that
    already struggles with TLS would be slow, unaudited and mine. Pass a signer
    in instead -- anything that takes the bytes and gives back sixty-four.
  * TLS and sockets. Those are the runtime's, told to verify: `aamio_http.Tls`
    on MicroPython, `adafruit_requests` on CircuitPython. `aamio_http.py` holds
    the thin part that differs, and what a transport has to be.

Runs on CPython as well, which is how the tests beside it check this against the
same `testdata/vectors.json` as every other client.
"""

try:
    import hashlib
    hashlib.sha256
except (ImportError, AttributeError):      # some CircuitPython builds
    import adafruit_hashlib as hashlib     # noqa: F401

try:
    import json
except ImportError:
    import ujson as json                   # noqa: F401


AAMIO_ADDRESS_LEN = 20
AAMIO_ID_MIN = 20
AAMIO_ID_MAX = 64
AAMIO_SCOPE_KEY_MIN = 26
AAMIO_SCOPE_KEY_MAX = 64
AAMIO_SIGN_INPUT_LEN = 94

_B32 = "abcdefghijklmnopqrstuvwxyz234567"
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_HEX = "0123456789abcdef"
# What a read key and a scope key are made of, and nothing else: the service
# refuses anything outside it, and the C beside this always has.
_KEY_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

SCOPE_PREFIX = "aamio-scope-v1\n"
SIGN_PREFIX = b"aamio-v1\n"


class AamioError(Exception):
    """Anything this module refuses. The subclasses say which kind, as the C's codes do."""


class ArgError(AamioError):
    """A missing value, or one of a type this cannot work with."""


class LengthError(AamioError):
    """The right shape, the wrong number of bytes."""


class EncodingError(AamioError):
    """Not the encoding claimed, or not its canonical form."""


def _sha256(data):
    return hashlib.sha256(data).digest()


def _hex(raw):
    # binascii.hexlify exists on both runtimes, but this is shorter than the
    # import and behaves the same on a build that left binascii out.
    out = []

    for byte in raw:
        out.append(_HEX[byte >> 4])
        out.append(_HEX[byte & 15])

    return "".join(out)


def _as_bytes(value, what):
    if isinstance(value, str):
        return value.encode("utf-8")

    if isinstance(value, (bytes, bytearray)):
        return bytes(value)

    raise ArgError("%s must be text or bytes" % what)


def _b32_address(digest):
    """The first twenty characters of lowercase base32, no padding.

    Twenty characters is a hundred bits, so thirteen bytes of the digest are read
    and the rest is never looked at.
    """
    out = []
    acc = 0
    bits = 0

    for byte in digest[:13]:
        acc = (acc << 8) | byte
        bits += 8

        while bits >= 5:
            bits -= 5
            out.append(_B32[(acc >> bits) & 31])

            if len(out) == AAMIO_ADDRESS_LEN:
                return "".join(out)

    raise LengthError("a digest shorter than thirteen bytes cannot make an address")


def b64url_decode(text, want):
    """Exactly `want` bytes of base64url, unpadded and canonical, or nothing at all.

    The last character of a 32-byte key carries two significant bits and of a
    64-byte signature four, and the rest must be zero. A key that differs only in
    those bits is a second spelling of the same key, so an allowlist written one
    way would not match a write signed the other. Both cannot be right, so the
    non-canonical one is refused.

    Nothing comes back from a refusal, which is why this fills a local and returns
    it last rather than writing into something the caller passed.
    """
    if not isinstance(text, str):
        raise ArgError("base64url comes in as text")

    expect = (want * 8 + 5) // 6

    if len(text) != expect:
        raise LengthError("expected %d characters for %d bytes, got %d"
                          % (expect, want, len(text)))

    out = bytearray()
    acc = 0
    bits = 0

    for character in text:
        at = _B64.find(character)

        if at < 0:
            raise EncodingError("not base64url: %r" % character)

        acc = (acc << 6) | at
        bits += 6

        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)

    if bits and (acc & ((1 << bits) - 1)):
        raise EncodingError("base64url with stray bits: the %d unused bits are not zero" % bits)

    return bytes(out)


def b64url_encode(raw):
    """Bytes as unpadded base64url, the one spelling the service and an allowlist agree on.

    Without this the module could read a key and a signature and not write one, so
    the advice to sign with a library you brought and send the pair had nowhere to
    turn the pair into the text that goes in a header.

    The unused bits of the last character are zero, which is what makes the result
    canonical and what `b64url_decode` refuses when they are not.
    """
    raw = _as_bytes(raw, "the value to encode")
    out = []
    acc = 0
    bits = 0

    for byte in raw:
        acc = (acc << 8) | byte
        bits += 8

        while bits >= 6:
            bits -= 6
            out.append(_B64[(acc >> bits) & 63])

    if bits:
        out.append(_B64[(acc << (6 - bits)) & 63])

    return "".join(out)


def _key_shaped(text, what, shortest, longest):
    """A read key or a scope key: text, of a length in range, of [a-z0-9] and nothing else.

    The length was checked and the alphabet was not, so a key with a capital, a
    hyphen, a letter outside ASCII or a carriage return in it derived an address
    that looked like one, from a key the service refuses on sight. The C beside
    this refused all of them. A control character is worse than a wrong key: it
    goes into a header on a transport that writes headers as lines.
    """
    if not isinstance(text, str):
        raise ArgError("%s is text" % what)

    if not shortest <= len(text) <= longest:
        raise LengthError("%s is %d to %d characters, this is %d"
                          % (what, shortest, longest, len(text)))

    for character in text:
        if character not in _KEY_ALPHABET:
            raise EncodingError("%s is lowercase letters and digits, and this has %r"
                                % (what, character))


def check_address(w):
    """Raises unless this is an address: twenty characters of lowercase base32.

    An address goes into a path, and a signature is over it, so it is checked
    before either happens.
    """
    if not isinstance(w, str) or len(w) != AAMIO_ADDRESS_LEN:
        raise LengthError("an address is %d characters" % AAMIO_ADDRESS_LEN)

    for character in w:
        if character not in _B32:
            raise EncodingError("not a base32 address: %r" % character)


def address(read_key):
    """The write address for a read key: base32(sha256(id)), first twenty, lowercase."""
    _key_shaped(read_key, "a read key", AAMIO_ID_MIN, AAMIO_ID_MAX)

    return _b32_address(_sha256(read_key.encode("utf-8")))


def scope_address(scope_key):
    """A scope address. Not the thread address of the same string, and that is the point.

    The prefix is what keeps them apart: a group that shares a scope key must not
    thereby hand out a readable thread at the address anybody could derive from it.
    """
    _key_shaped(scope_key, "a scope key", AAMIO_SCOPE_KEY_MIN, AAMIO_SCOPE_KEY_MAX)

    return _b32_address(_sha256((SCOPE_PREFIX + scope_key).encode("utf-8")))


def sign_input(w, body):
    """The ninety-four bytes that get signed, and nothing else ever does.

    Not the body, not the URL, not a canonical form of the JSON: this exact
    string. Signing anything else gives a signature the service refuses, and the
    refusal cannot tell you which of the two you got wrong.
    """
    check_address(w)

    digest = _hex(_sha256(_as_bytes(body, "the body")))

    return SIGN_PREFIX + w.encode("ascii") + b"\n" + digest.encode("ascii")


def key_hash(public_key):
    """The hash an allowlist is compared against: sha256 of the key's bytes, not of its text."""
    return _hex(_sha256(b64url_decode(public_key, 32)))


def check_key_shape(text):
    """Raises unless this is a canonical unpadded base64url Ed25519 public key."""
    b64url_decode(text, 32)


def check_signature_shape(text):
    """Raises unless this is a canonical unpadded base64url Ed25519 signature."""
    b64url_decode(text, 64)


def body_of(message):
    """A message's payload, checked against the hash that came with it.

    The service puts the bytes in `body` and their sha256 beside them. Comparing
    them catches a body cut short or altered on the way, which is the failure a
    device notices last and suffers from longest. It is not a proof of who wrote
    it -- that is the signature, below -- and it is not a proof against the
    service itself, which computed both. It is worth doing anyway: nothing else
    on the device will.
    """
    if not isinstance(message, dict):
        raise ArgError("a message is an object")

    body = message.get("body")

    if not isinstance(body, str):
        raise EncodingError("the message has no body")

    stated = message.get("sha256")

    if stated is None:
        raise EncodingError("the message came without its hash, so nothing can be checked")

    if not isinstance(stated, str) or _hex(_sha256(body.encode("utf-8"))) != stated:
        raise EncodingError("the body does not match the hash that came with it")

    return body


def is_sealed(body):
    """Whether a body is a sealed envelope, read from the envelope and not from a flag.

    A device that cannot decrypt has to notice, or it hands a `nacl.box.v1` envelope
    to whatever acts on messages and that thing sees a JSON object with a `ct` field
    and no reading in it. The answer's own `sealed` is the service's finding; this is
    the envelope saying what it is.

    Opening one needs Curve25519, which is the platform's and is not here. What this
    buys is knowing to leave it alone.
    """
    if not isinstance(body, str):
        return False

    # Cheap first, and safe: an object starts with a brace, whatever its fields
    # are called. This used to look for the text "e2ee" before parsing, and a
    # field written as "\u00652ee" decodes to the same name and was missed, so
    # an envelope spelled that way went to whatever acts on messages. Field
    # names are read after decoding, or they are not read at all.
    if body.lstrip()[:1] != "{":
        return False

    try:
        envelope = json.loads(body)
    except (ValueError, TypeError):
        return False

    return (isinstance(envelope, dict) and isinstance(envelope.get("e2ee"), str)
            and "ct" in envelope and "nonce" in envelope)


def signed_bytes_of(message, w):
    """The ninety-four bytes this message's signature covers, for a caller that has Ed25519.

    The signature is over the write address and the hash of the body, not over the
    message object the service hands back, so it cannot be recomputed from that
    object alone: the address has to come from the session.
    """
    return sign_input(w, body_of(message))


def sender_is_allowed(message, w, allow, verify):
    """True only when the signature verifies against a key the caller listed. Never a guess.

    `allow` holds public keys as base64url, or their hashes, as an allowlist the
    device keeps for itself. `verify` is a callable taking (public key bytes,
    signature bytes, signed bytes) and answering true or false -- from a library
    the caller brought, because neither MicroPython nor CircuitPython has Ed25519
    and this module will not pretend to.

    The service's own `verified` and `from` are its findings, not an independent
    check, so they are not what this reads. Without a `verify` this raises rather
    than answering: a sender check that cannot check is worse than none, because
    it looks like one.
    """
    if verify is None:
        raise ArgError("no verifier: signature checking needs Ed25519, which this module does not have")

    sender = message.get("from")
    signature = message.get("sig")

    if not isinstance(sender, str) or not isinstance(signature, str):
        return False

    hashed = key_hash(sender)

    if sender not in allow and hashed not in allow:
        return False

    return bool(verify(b64url_decode(sender, 32), b64url_decode(signature, 64),
                       signed_bytes_of(message, w)))


# Where the walk is, so a separator can be judged by what came before it. The
# same five states as the C, and the same reason: balanced brackets are not a
# grammar, and a trailing comma, a double comma and two names with no comma
# between them are all balanced.
_AT_START = 0
_AT_OPEN = 1
_AT_VALUE = 2
_AT_COMMA = 3
_AT_COLON = 4
# A string in an object is a name or a value. A name is followed by a colon and
# by nothing else.
_AT_NAME = 5
# Deeper than a service answer ever goes. Deeper is refused rather than guessed at.
JSON_MAX_DEPTH = 30

_JSON_SPACE = " \t\r\n"
_JSON_ENDS_SCALAR = ",]} \t\r\n"
_JSON_ESCAPES = '"\\/bfnrt'
_JSON_HEX = "0123456789abcdefABCDEF"


def _string_end(text, at):
    """The index past the closing quote of the string opening at `at`, or a refusal.

    An escape has to be one of JSON's eight, or \\u and four hex digits, and a
    control character has to be escaped. MicroPython's json.loads takes "\\q" as
    the letter q, CPython's refuses it: the document is not JSON either way, and
    a reader that moved the cursor on it moved it on an answer from a service
    that sent nothing of the kind.
    """
    end = len(text)
    i = at + 1

    while i < end:
        character = text[i]

        if character == '"':
            return i + 1

        if ord(character) < 0x20:
            raise EncodingError("a control character inside a string")

        if character == "\\":
            i += 1

            if i >= end:
                break

            if text[i] == "u":
                if i + 4 >= end:
                    break

                for digit in text[i + 1:i + 5]:
                    if digit not in _JSON_HEX:
                        raise EncodingError("not a JSON escape: \\u%s" % text[i + 1:i + 5])

                i += 4
            elif text[i] not in _JSON_ESCAPES:
                raise EncodingError("not a JSON escape: \\%s" % text[i])

        i += 1

    raise EncodingError("a string that never closes")


def _is_json_number(token):
    """-?(0|[1-9][0-9]*)(.[0-9]+)?([eE][+-]?[0-9]+)?, and nothing before or after."""
    end = len(token)
    i = 0

    if i < end and token[i] == "-":
        i += 1

    if i >= end:
        return False

    if token[i] == "0":
        i += 1
    elif "1" <= token[i] <= "9":
        while i < end and "0" <= token[i] <= "9":
            i += 1
    else:
        return False

    if i < end and token[i] == ".":
        i += 1
        start = i

        while i < end and "0" <= token[i] <= "9":
            i += 1

        if i == start:
            return False

    if i < end and token[i] in "eE":
        i += 1

        if i < end and token[i] in "+-":
            i += 1

        start = i

        while i < end and "0" <= token[i] <= "9":
            i += 1

        if i == start:
            return False

    return i == end


def _scalar_end(text, at):
    """The index past the literal or number starting at `at`, or a refusal.

    A bare word where a value belongs used to run on as one: messages:[garbage]
    was balanced, and so was next:041. true, false, null and a number in JSON's
    own grammar are values; nothing else is.
    """
    end = len(text)
    i = at

    while i < end and text[i] not in _JSON_ENDS_SCALAR:
        i += 1

    token = text[at:i]

    if token in ("true", "false", "null") or _is_json_number(token):
        return i

    raise EncodingError("not a JSON value: %r" % token[:20])


def json_whole(text):
    """Raises unless `text` is one complete JSON object and nothing else.

    json.loads is not the same parser on every runtime. MicroPython's takes an
    escape that is not JSON's and a number with a leading zero, and CPython's
    refuses both; an answer that reads differently on two boards is not an answer
    either can act on. This is the C core's check in Python, run before json.loads
    is asked, so that what is refused is refused everywhere, and the same corpus
    of refusals in testdata/answers.json runs against both.

    A body cut off by a full buffer or a dropped connection looks like an answer
    for as far as it goes; this is also where that is caught.
    """
    if not isinstance(text, str):
        raise ArgError("an answer is text")

    end = len(text)
    i = 0

    while i < end and text[i] in _JSON_SPACE:
        i += 1

    if i >= end or text[i] != "{":
        raise EncodingError("the answer is not an object")

    # True for an object, False for an array, innermost last: the C keeps the
    # same thing as a bitmask.
    objects = []
    was = _AT_START
    closed = False

    while i < end:
        character = text[i]

        if character in _JSON_SPACE:
            i += 1
            continue

        if closed:
            raise EncodingError("something after the object")

        if character == '"':
            if was not in (_AT_OPEN, _AT_COMMA, _AT_COLON):
                raise EncodingError("a string where none may stand")

            # Inside an object, a string where a value may not yet stand is the
            # name of the pair. Inside an array there are no names.
            naming = objects[-1] and was in (_AT_OPEN, _AT_COMMA)

            if not naming and was != _AT_COLON and objects[-1]:
                raise EncodingError("a value with no name before it")

            i = _string_end(text, i)
            was = _AT_NAME if naming else _AT_VALUE
            continue

        if character in "{[":
            if was not in (_AT_START, _AT_OPEN, _AT_COMMA, _AT_COLON):
                raise EncodingError("an object or a list where none may stand")

            if len(objects) >= JSON_MAX_DEPTH:
                raise EncodingError("nested deeper than %d" % JSON_MAX_DEPTH)

            objects.append(character == "{")
            was = _AT_OPEN
        elif character in "}]":
            if was in (_AT_COMMA, _AT_COLON, _AT_NAME):
                raise EncodingError("a bracket closing on a separator")

            # A brace closing a bracket is not a deeper object; it is a different
            # document, and one of the two shapes is not what the caller read.
            if (character == "}") != objects[-1]:
                raise EncodingError("brackets that cross")

            objects.pop()

            if not objects:
                closed = True

            was = _AT_VALUE
        elif character == ",":
            if was != _AT_VALUE:
                raise EncodingError("a comma with no value before it")

            was = _AT_COMMA
        elif character == ":":
            if was != _AT_NAME:
                raise EncodingError("a colon with no name before it")

            was = _AT_COLON
        else:
            # A number or a literal. Inside an object that is after a colon only:
            # a bare literal where a name belongs is not a pair.
            if was != _AT_COLON and (objects[-1] or was not in (_AT_OPEN, _AT_COMMA)):
                raise EncodingError("a value where none may stand")

            i = _scalar_end(text, i)
            was = _AT_VALUE
            continue

        i += 1

    if not closed:
        raise EncodingError("an object that never closes")


def _boolean(answer, name):
    value = answer.get(name)

    if not isinstance(value, bool):
        raise EncodingError("%s is not true or false" % name)

    return value


def _counting_number(holder, name):
    value = holder.get(name)

    # isinstance(True, int) is true in Python, and a flag is not a sequence number.
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EncodingError("%s is not a number that counts forwards" % name)

    return value


class Session:
    """A device's side of a thread: the cursor, the limits, and what to do when an answer does not fit.

    The loop it is built for:

        session = aamio.Session(read_key)
        while True:
            body = http.get(session.read_path(), limit=4, max_bytes=2048)
            for message in session.take_answer(body):
                act(message)
            if not session.more:
                sleep()

    `more` says the answer was cut short, so the next read follows at once rather
    than after a sleep. A message too large for the budget is remembered by its
    sequence number, and the next path goes past it: unread on purpose, never
    dropped in silence, and never asked for again in a loop that cannot end.
    """

    def __init__(self, read_key):
        self.w = address(read_key)
        self.read_key = read_key
        self.after = 0
        self.more = False
        self.left_unread = 0
        self.left_bytes = 0
        self.gone = False

    def write_path(self):
        """Where a write goes: just the address."""
        return "/" + self.w

    def read_path(self):
        """Where the next read goes, cursor included.

        A message this device would not take is stepped over here and nowhere
        else. Asking for it again with the same budget would answer the same thing
        for as long as the thread lives.
        """
        start = self.left_unread if self.left_unread > self.after else self.after

        if start == 0:
            return self.write_path()

        return "/" + self.w + "/after/" + str(start)

    def take_answer(self, body):
        """Read what the service answered, move the cursor, and give back the messages.

        Everything is read into locals and checked before the session changes at
        all, because the promise here is that an answer this refuses leaves the
        session exactly as it was, so the next read asks for the same thing again.
        Setting `gone` or `more` on the way to a check that can still fail leaves a
        caller who was told to read the same thing reading something else.
        """
        if isinstance(body, (bytes, bytearray)):
            try:
                body = bytes(body).decode("utf-8")
            except (ValueError, UnicodeError):
                raise EncodingError("the answer is not UTF-8")

        if not isinstance(body, str):
            raise ArgError("an answer is text or bytes")

        # Whole, first, and by this module's own grammar rather than the runtime's:
        # a body cut off by a full buffer reads fine as far as it goes, and its
        # fields moved the cursor past messages that never came; and json.loads on
        # MicroPython takes what CPython's refuses. See json_whole.
        json_whole(body)

        try:
            answer = json.loads(body)
        except (ValueError, TypeError):
            raise EncodingError("the answer is not whole JSON")

        if not isinstance(answer, dict):
            raise EncodingError("the answer is not an object")

        # exists is required: an answer without it is not this service's, and a
        # stray object with next in it used to be enough to move the cursor.
        exists = _boolean(answer, "exists")

        messages = []
        more = False
        seq = 0
        left_bytes = 0
        next_cursor = None
        has_reset = False

        if exists:
            # A required field has a shape as well as a name. messages as a number
            # is well formed JSON and is not an answer.
            if not isinstance(answer.get("messages"), list):
                raise EncodingError("messages is missing, or is not a list")

            messages = answer["messages"]

            # Each one an object with a sequence number that counts forwards and a
            # body that is text, and all of them before the cursor moves past any.
            # messages:[null] came back as [None], moved the cursor, and act(None)
            # failed on the first attribute it touched, with the message gone.
            # The hash is body_of's to check, since it is checked per message
            # and reported per message; what is checked here is that there is a
            # message to check.
            for message in messages:
                if not isinstance(message, dict):
                    raise EncodingError("a message is an object, and one of these is not")

                _counting_number(message, "seq")

                if not isinstance(message.get("body"), str):
                    raise EncodingError("a message has a body that is text, and one of these has not")

            if "more" in answer:
                more = _boolean(answer, "more")

            # Named with its size rather than cut, because a signed message is
            # never half sent.
            if "too_large" in answer:
                inner = answer["too_large"]

                if not isinstance(inner, dict):
                    raise EncodingError("too_large is not an object")

                seq = _counting_number(inner, "seq")

                if "bytes" in inner:
                    left_bytes = _counting_number(inner, "bytes")

            # A cursor this client cannot represent is not a cursor, and neither is
            # a string that looks like one, nor a number that counts backwards.
            # Believing the rest of the answer while quietly ignoring next is how a
            # reader ends up at a position nobody chose: the whole answer goes
            # instead.
            if "next" in answer:
                next_cursor = _counting_number(answer, "next")

            # A reset is an object with the after that was sent and the newest there
            # is; that is the documented shape, and the presence of the name used to
            # be the whole signal, so reset:false let the cursor go backwards.
            if "reset" in answer:
                inner = answer["reset"]

                if not isinstance(inner, dict):
                    raise EncodingError("reset is an object with after and newest, or it is not a reset")

                _counting_number(inner, "after")
                _counting_number(inner, "newest")
                has_reset = True

        # Everything checked. From here the session changes and nothing can fail.
        self.more = False
        self.left_unread = 0
        self.left_bytes = 0

        # exists: false is a thread nobody has written to yet, one that expired and
        # was swept, or one a restart took away. The cursor goes with it: whatever
        # opens at this address next counts from one, and an old cursor would read
        # nothing until the new thread passed it.
        if not exists:
            self.gone = True
            self.after = 0

            return []

        self.gone = False
        self.more = more

        if seq > 0:
            self.left_unread = seq
            self.left_bytes = left_bytes

        if next_cursor is not None:
            if next_cursor > self.after:
                self.after = next_cursor
            elif has_reset:
                # A lower cursor after a reset is the one to keep: the thread at
                # this address counts from one again, and holding the old number
                # would read nothing until the new one passed it. The device's own
                # record of what it has already carried out is not the service's
                # cursor and does not move with it.
                self.after = next_cursor

        return messages
