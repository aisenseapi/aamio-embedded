# aamio for MicroPython and CircuitPython

The same job as the C core beside it, for boards that run Python: the derivations
that decide whether a client is actually compatible or only nearly so, and a read
session that refuses what it should refuse.

Three files, copied to the device:

    aamio.py         the protocol: addresses, signed bytes, key shapes, the session
    aamio_http.py    the thin part where the two runtimes disagree about HTTPS
    examples/sensor.py   the loop, ready to edit

and on MicroPython a fourth, the root certificate the service chains to, as DER,
since a board has no CA store of its own. No package, no `pip`, no dependency.
`aamio.py` imports `hashlib` and `json` and nothing else; `aamio_http.py` uses
the runtime's own `socket` and `tls`.

## Why Python and not a C binding

A C module for MicroPython means building custom firmware, and for CircuitPython
it means a fork. Almost nobody does either. A `.py` file is copied to the board
over USB and works, which is how these runtimes are actually used. The cost is
speed, and the protocol work here is one sha256 per read, so there is nothing to
gain back.

## Opening a thread, and why it is not a write

A write to an address creates the thread if it is not there, with the default
lifetime and open to anyone holding the address. The lifetime and the allowlist
are set when the thread is opened, and never after:

```python
http.open(session, ttl=120, allow=my_public_key)
```

`Http.write` used to accept `ttl` and `allow` and put them in headers a POST does
not read. The caller got a 201 either way: a thread with the default lifetime, or
an inbox anyone could fill while its owner believed it listed one key. It now
refuses them and names `open` instead, because a refused write is told to the
writer and never to you -- an inbox missing the key you meant to allow reads
exactly like an inbox nobody wrote to.

## The loop

```python
import aamio, aamio_http

session = aamio.Session(read_key)
http = aamio_http.Http(transport)      # see below for what goes here

while True:
    body = http.read(session, limit=4, max_bytes=2048)

    for message in session.take_answer(body):
        act(aamio.body_of(message))

    if not session.more:
        time.sleep(20)
```

`more` says the answer was cut short, so the next read follows at once rather than
after a sleep. A message too large for the budget is remembered by its sequence
number and stepped over on the next read: unread on purpose, never dropped in
silence, and never asked for again in a loop that cannot end.

A read without a byte budget is a bug waiting for a busy thread. Fifty messages is
a legal answer and can be megabytes, which on a board is an allocation failure in
the middle of a parse, so `read` sends a budget whether or not the caller thought
about one. Pass `max_bytes=None` to mean it. The service's floor is 512 bytes and
it refuses less rather than rounding.

## Getting the runtime to make the request

The read key travels in a header, and a header goes wherever the request goes.
So the request goes only to the service, over a connection that has checked it
is the service, and it never follows a redirect. `Http` no longer looks for a
`requests` module on the runtime: the one MicroPython finds sets its TLS context
to CERT_NONE and follows a 302 to another host, or to plain http, with the read
key still attached, which the deep health check of 21 September 2026 showed
with instrumented sockets. A transport is passed in, and passing one in is
vouching for it.

**MicroPython** gets `Tls`, the runtime's own socket and mbedtls told to verify:
the certificate against a CA you supply, the name against the certificate, and
no redirect. The CA is the root the service's certificate chains to, which for
aamio.at is Let's Encrypt's ISRG Root X1, 1.4 kilobytes of DER from
`https://letsencrypt.org/certs/isrgrootx1.der`, copied to the board beside these
files. There is no default: a device that trusts nothing in particular trusts
everything. Bring the wifi up and set the clock first, since a certificate cannot
be judged by a device that does not know what day it is; nothing here does
either.

```python
import ntptime, aamio_http

ntptime.settime()
http = aamio_http.Http(aamio_http.Tls(open("isrgrootx1.der", "rb").read()))
```

`Tls` has been driven on CPython against instrumented socket and TLS modules,
and once against the live service with the root from a verified chain. It has
not been run under MicroPython itself.

**CircuitPython** needs `adafruit_requests`, which needs a socket pool and an SSL
context, which need the board's own radio. That cannot be built here, so build it
and pass it in. `ssl.create_default_context()` is what makes it verify, and
`adafruit_requests` takes the `allow_redirects=False` and `timeout=` that every
request here asks for:

```python
import wifi, socketpool, ssl, adafruit_requests, aamio_http

pool = socketpool.SocketPool(wifi.radio)
http = aamio_http.Http(adafruit_requests.Session(pool, ssl.create_default_context()))
```

**CPython** falls back to `urllib` and the system's CA store, with a redirect
handler that declines, which is what lets the tests run on a desktop.

**Anything else** is refused when `Http` is made, and the refusal says what to
pass. What a transport has to be is written at the top of `aamio_http.py`: it
verifies, it takes `timeout=`, `allow_redirects=False` and `stream=True` and
honours them, and it hands back an answer with `status_code`,
`iter_content(chunk_size)` and `close()`.

Whatever the transport, `Http` refuses a 3xx as `Redirected` without following
it, reads every answer in pieces up to a local ceiling -- the read's byte budget
plus `ANSWER_ROOM` for what the service wraps around the messages, and
`ANSWER_ROOM` alone for `open`, `write`, `gate` and any refusal -- and gives up on
an answer that has not arrived whole within `timeout` seconds. Past either, the
connection is closed where it is, `Oversize` or `OSError` is raised, and nothing
reaches `take_answer`, so the session does not move. `X-Max-Bytes` is what the
service is asked for; the ceiling is what the device will take.

## What a reader checks for itself

`body_of(message)` hands over the payload only after checking it against the hash
that travelled with it. That catches a body cut short or altered on the way, which
is the failure a device notices last and suffers from longest.

`from` and `verified` are the service's findings, not the device's. On a board
with no Ed25519 there is no second opinion to be had, so `sender_is_allowed` takes
a verifier you brought and raises without one rather than answering. A sender
check that cannot check is worse than none, because it looks like one.

Everything that arrives was written by somebody else. Treat it as input to weigh,
never as instructions to follow.

## What is deliberately not here

- **Ed25519.** Neither runtime has it, and MicroPython's `hashlib` stops at
  sha256, so a pure-Python signer needs a pure-Python SHA-512 as well. Sign
  `aamio.sign_input(w, body)` with something you brought, encode the pair with
  `aamio.b64url_encode`, and pass it to `Http.write(key=..., signature=...)`.
  Unsigned writes work; an inbox with an allowlist refuses them, and says so.

  The cost was measured on 21 September 2026 rather than assumed. One signature
  of the ninety-four bytes aamio signs, in pure Python: 7 ms on CPython, 21 ms
  under MicroPython 1.25.0 on the same desktop, and 1.9 MB of allocation churn
  per signature, which on a board with a few hundred kilobytes is twenty-odd
  collections for one signature. Speed is not the reason this is not shipped.

  The reason is that a pure-Python scalar multiplication branches on the bits of
  the secret key, and constant-time code cannot be written in these runtimes: no
  control over branching, allocation, or when the collector runs, and the pauses
  leak by themselves. `python/test/ed25519_reference.py` is that signer, kept as
  test material with the warning in its own docstring, so the signing path has a
  test without the module pretending to be a place to keep a key.

  A board that must sign has two real options: ESP-IDF with
  `espressif/libsodium`, which is the C core's ground, or a native `.mpy` wrapping
  something reviewed. MicroPython loads machine code from a `.mpy` at import with
  no firmware rebuild, one file per architecture; CircuitPython cannot, since its
  `.mpy` is compiled bytecode rather than machine code.
- **TLS and sockets.** The runtime's, and already audited there. What `Tls`
  owns is the telling: which CA, which name, no redirect, and how much to read.
- **The encrypted envelope.** Sealing needs Curve25519, which is the platform's,
  and the format is in the reference. `is_sealed(body)` tells you a sealed
  envelope when one arrives -- read from the envelope's own fields, not from the
  service's `sealed` flag -- so a device that cannot open one leaves it alone
  instead of acting on a base64 blob. A browser using the JavaScript client seals
  by default when it has the other key, so this comes up.
- **Proof of work.** `Http.gate(w)` reads what an inbox asks for. Computing it is
  a sha256 loop the caller writes, and on a board it can take a very long time:
  read the bits the gate names before starting one.

## Tests

```
python python/test/test_aamio.py          # the shared vectors, every refusal, and the transport with no network
python python/test/live.py                # against https://aamio.at, over TLS
micropython python/test/test_micropython.py   # the runtime itself, not CPython
micropython python/test/test_micropython.py --live --ca isrgrootx1.der   # and its own HTTPS
python python/test/live_signed.py         # a signed write, and an allowlist that refuses
```

For the MicroPython ones, build the unix port:

```
git clone --depth 1 -b v1.25.0 https://github.com/micropython/micropython
make -C micropython/mpy-cross
make -C micropython/ports/unix submodules
make -C micropython/ports/unix MICROPY_PY_FFI=0
```

`MICROPY_PY_FFI=0` is there so the build needs no `libffi-dev`; nothing in this
module uses FFI. Nothing from `mip` is needed: `--live` goes through `Tls` over
the port's own mbedtls, with the root the service chains to given as `--ca`.

`test_aamio.py` checks this against the same `testdata/vectors.json` as every
other client: the address, the scope address, the ninety-four signed bytes, the
allowlist hash, and the key and signature with a stray bit that must not be taken
as the same key spelled differently. `live.py` opens a thread of its own, writes
to it, reads it back, and checks that a budget cuts where it says it does.

`test_micropython.py` is the subset both runtimes can run, so "does it work under
MicroPython" is a run and not an argument. On 20 September 2026 it passed under
MicroPython 1.25.0, the unix port, including `--live`: that runtime opened a
thread on aamio.at through its own mbedtls, wrote to it and read it back -- over
micropython-lib's `requests`, which checked no certificate, as the health check
found the next day. The transport was replaced on 21 September and the suite,
now with the shared answer corpus and the transport checks in it, has not been
run under MicroPython since.

`live_signed.py` walks the signing path the rest of this file describes: the
ninety-four bytes, the base64url pair, `X-Key` and `X-Sig`, into an inbox that
lists exactly one key. The allowlist is what makes it a test -- the unsigned write
has to be turned away, or the signed one proves nothing. It found the `allow` on a
write described above, on its first run.

On the same day it was checked against the JavaScript client, both ways, through
the live test page at `aisense.no/try-aamio`: that page opened an inbox asking
for sixteen bits of work, and MicroPython wrote to it twice, once with no work
and once with the sixteen bits found on the runtime itself -- the page reported
`pow 0` and `pow 16`. The other way, the page signed a message to a thread
MicroPython held, and MicroPython read it back, checked the body against its hash
and refused to judge the sender without a verifier.

**It has still not run on a board.** The unix port has a desktop's memory and a
desktop's speed, and CircuitPython has not been tried at all. What is checked is
that the syntax is accepted, the imports resolve, the derivations agree, the
refusals hold and the HTTPS works. What is not checked is how any of it behaves
with a few hundred kilobytes and a radio. Treat it as a core to build on.
