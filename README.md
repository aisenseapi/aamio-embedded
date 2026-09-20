# aamio-embedded

The parts of aamio that are easy to get subtly wrong, in C, for devices that
have a few hundred kilobytes and no room to be careless.

**Status: the C core has been built, flashed to an M5Stack ATOM and run against
the live service.** Nothing on it is timed. Everything below about ESP32 memory
is arithmetic against numbers measured on a host build, not a measurement on the
device.

There is a Python module beside it, in `python/`, for MicroPython and
CircuitPython. MicroPython 1.25.0 runs it and reads the live service through its
own TLS, and it has **not** been run on a board.

## What it is, and what it deliberately is not

An ESP32 already has TLS and an HTTP client through its SDK, and Ed25519 from
`espressif/libsodium`, a component away. What it does not have is the handful of
derivations that decide whether a client is actually compatible or only nearly so:

- a write address from a read key
- which exact bytes get signed
- how a public key is encoded, and which spellings are refused
- what a scope address is, and why it is not the thread address of the same
  string

Those live here. **Signing and TLS do not.** They belong to the platform, where
they are already audited; shipping crypto nobody reviewed alongside a protocol
helper is how a small client becomes the weakest thing on the device.

## Measured

Measured on 20 September 2026 with gcc 16.2.0 (MinGW-W64 x86-64, ucrt) at
`-Os -std=c99`, on x86-64. A figure without its compiler and flags is not one
anybody can repeat, and a host build is not a device: a cross compiler for the
part you are using will give a different number, and the point of these is the
order of magnitude.

| | |
|---|---|
| Code | 4768 bytes |
| Initialised data, bss | 0, 0 |
| Heap | none, ever |
| Deepest stack, sha256 chain | 640 bytes: 272 in `aamio_sha256`, 368 in `sha256_block` |

The stack figure is that one chain, measured with `-fstack-usage`. It is not a
ceiling for every public call and not one for your program: whatever calls into
this library has a frame of its own, and the frames above it are yours.

There is no `malloc` in this library. Every output buffer is the caller's, with
its size, and nothing is written to it on failure.

## What it passes

`testdata/vectors.json` is the same file six of the seven aamio clients carry
byte for byte, sha256 `342ea401…`. One hundred checks in three suites --
thirty-seven through the core, twenty through the sensor loop and forty-three
on what an answer has to be before the loop believes any of it -- all with
`-Wall -Wextra -Werror`:

```
python tools/build.py          # generate the vector header, compile, run both suites
python tools/build.py --size   # and print what it costs in code and stack
```

The one that matters most is not in the list above. The signature in the
vectors was produced by the Python client; a real Ed25519 implementation
verifies it over the exact ninety-four bytes `aamio_sign_input` constructs
here. That is what "compatible" means, and it is checked rather than asserted.

## Reading without running out of memory

A thread may hold two hundred messages of 65536 bytes, so a plain read can
answer with about a megabyte. That is past this device's heap, and it was the
one thing no client could fix for itself: the reader is on the wrong side of
the wire.

Since service 0.7.2 a reader says how much it is willing to receive:

```
GET /{w}/after/{seq}
X-Read: {id}
X-Limit: 1
X-Max-Bytes: 2000
```

Measured against the service, a thread holding one small sensor reading and one
message of twenty kilobytes:

| Read | Bytes on the wire |
|---|---|
| No limit, as before | 20529 |
| `X-Limit: 1` | 360 |
| Nothing new | 144 |
| The large one, against a 2000 byte budget | 390, naming seq 2 at 20180 bytes |

The envelope alone — address, times, count, allowlist, cursor — is 156 bytes. These
are answers from `https://aamio.at`, not from a copy: run
`tools/measure-live.py` to take them again.

Whole messages only: a signed message is never cut, because half its bytes
verify against nothing. One that alone exceeds the budget comes back as
`too_large` with its `seq` and size, the cursor unchanged, and two ways on:
read it with a bigger budget, or pass its `seq` as `after` to leave it unread.
`more: true` says something was left behind.

Check `read-limits` in `/.well-known/aamio.json` before relying on it. An older
service ignores both headers and answers with the whole thread.

## The example, and where the line is

`examples/sensor` sends a signed reading and reads what came back. It is in two
halves on purpose.

`session.c` is the part that can go wrong quietly: the cursor, whether to read
again or sleep, and what to do with a message too large to take. It is plain C,
touches no SDK, and **seventeen checks run it on the host**, including a reset that
hands back a lower cursor and a message that is stepped past rather than asked for
again for ever.

`main_esp32.c` is the glue: Wi-Fi, libsodium and `esp_http_client`. **It has never
been compiled or flashed.** It says so in its own first lines, and it is not in the
build. Read it as a description of the shape and expect to fix names against the
SDK you have.

Ed25519 comes from `espressif/libsodium`, Espressif's own port, which supports every
target. mbedTLS is already in ESP-IDF and does TLS and sha256, but not Ed25519
signing, which is why the signature and the transport come from different places.

## Sleep is not free, and the service will not pretend it is

A thread lives at most 3600 seconds. A device that sleeps longer than that is
unreachable for that time, and aamio will not hold the night's commands until
morning. That is not a gap to be filled with a longer lifetime or a queue on
the service: it is what ephemeral means.

If a product needs it, a gateway on the local network owns a bounded buffer and
its own expiry policy, and says so. **This applies to any device that sleeps
more than an hour, not only to the smallest ones.**

And a lost read key cannot be recovered by anyone. The thread stays open and
goes on taking messages nobody will ever read, and the party writing to you
sees an ordinary delivery. Keep it where it outlives the sleep, or announce a
new inbox on waking rather than advertising one you can no longer read.

## What has run on a device

On 20 September 2026 the ESP-IDF example was built, flashed to an M5Stack ATOM
and run against the live service: derive the address once, read with a byte
budget, act, sleep. That is the loop `examples/sensor/session.h` describes, doing what it
says, over TLS, against aamio.at.

That is what is claimed, and no more.

## The same thing in Python

`python/` holds the protocol for boards that run MicroPython or CircuitPython:
three files copied over USB, no package and no dependency beyond `hashlib` and
`json`. It makes the same addresses, signs the same ninety-four bytes, refuses
the same spellings, and carries the same read session. A C module for these
runtimes would mean building custom firmware or forking one, which almost nobody
does; the protocol work is one sha256 per read, so there is nothing to win back
by it. `python/README.md` says what it does and what it leaves to the platform.

## What has not been done

- The Python module has not run on a board. MicroPython 1.25.0 runs it on a
  desktop, vectors and live service included, and CircuitPython has not been
  tried at all. That is what is claimed for it and no more.
- Nothing is timed. No TLS handshake measured, no certificate chain checked by
  hand on device, no proof of work timed.
- A signed write from the board is not claimed here. The example constructs one
  and libsodium signs it; the run reported was the read loop.
- Nothing for Arduino or the Pico SDK.
- No Ed25519 binding against mbedTLS. Signing comes from `espressif/libsodium`.
- The encrypted envelope is not here: sealing needs Curve25519, which is the
  platform's, and the format is in the reference.
- The answer reader refuses far more than it did, and a review on 20 September
  found cases it still takes. Treat it as a core to build on, not a finished
  client.
