# aamio for MicroPython and CircuitPython

The same job as the C core beside it, for boards that run Python: the derivations
that decide whether a client is actually compatible or only nearly so, and a read
session that refuses what it should refuse.

Three files, copied to the device:

    aamio.py         the protocol: addresses, signed bytes, key shapes, the session
    aamio_http.py    the thin part where the two runtimes disagree about HTTPS
    examples/sensor.py   the loop, ready to edit

No package, no `pip`, no dependency. `aamio.py` imports `hashlib` and `json` and
nothing else.

## Why Python and not a C binding

A C module for MicroPython means building custom firmware, and for CircuitPython
it means a fork. Almost nobody does either. A `.py` file is copied to the board
over USB and works, which is how these runtimes are actually used. The cost is
speed, and the protocol work here is one sha256 per read, so there is nothing to
gain back.

## The loop

```python
import aamio, aamio_http

session = aamio.Session(read_key)
http = aamio_http.Http()

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

**MicroPython** finds `urequests` by itself. Bring the wifi up first; nothing here
does that.

**CircuitPython** needs `adafruit_requests`, which needs a socket pool and an SSL
context, which need the board's own radio. That cannot be built here, so build it
and pass it in:

```python
import wifi, socketpool, ssl, adafruit_requests, aamio_http

pool = socketpool.SocketPool(wifi.radio)
http = aamio_http.Http(adafruit_requests.Session(pool, ssl.create_default_context()))
```

**CPython** falls back to `urllib`, which is what lets the tests run on a desktop.

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

- **Ed25519.** Neither runtime has it. A pure-Python signature on a board that
  already struggles with TLS would be slow, unaudited and mine. Sign
  `aamio.sign_input(w, body)` with a library you brought and pass the pair to
  `Http.write`. Unsigned writes work; an inbox with an allowlist refuses them, and
  says so.
- **TLS and sockets.** The runtime's, and already audited there.
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
python python/test/test_aamio.py          # the shared vectors and every refusal
python python/test/live.py                # against https://aamio.at, over TLS
micropython python/test/test_micropython.py   # the runtime itself, not CPython
micropython python/test/test_micropython.py --live   # and its own HTTPS
```

For the last two, build the unix port and give it something to make requests
with:

```
git clone --depth 1 -b v1.25.0 https://github.com/micropython/micropython
make -C micropython/mpy-cross
make -C micropython/ports/unix submodules
make -C micropython/ports/unix MICROPY_PY_FFI=0
micropython -m mip install requests
```

`MICROPY_PY_FFI=0` is there so the build needs no `libffi-dev`; nothing in this
module uses FFI.

`test_aamio.py` checks this against the same `testdata/vectors.json` as every
other client: the address, the scope address, the ninety-four signed bytes, the
allowlist hash, and the key and signature with a stray bit that must not be taken
as the same key spelled differently. `live.py` opens a thread of its own, writes
to it, reads it back, and checks that a budget cuts where it says it does.

`test_micropython.py` is the subset both runtimes can run, so "does it work under
MicroPython" is a run and not an argument. On 20 September 2026 it passed under
MicroPython 1.25.0, the unix port, including `--live`: that runtime opened a
thread on aamio.at through its own mbedtls, wrote to it and read it back.

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
