# aamio-embedded

The parts of aamio that are easy to get subtly wrong, in C, for devices that
have a few hundred kilobytes and no room to be careless.

**Status: the protocol core is written and passes the shared vectors. No board
has run it.** Everything below about ESP32 memory is arithmetic against
measured numbers, not a measurement on hardware. Nobody has flashed this.

## What it is, and what it deliberately is not

An ESP32 already has TLS and Ed25519 through mbedTLS, and an HTTP client
through its SDK. What it does not have is the handful of derivations that
decide whether a client is actually compatible or only nearly so:

- a write address from a read key
- which exact bytes get signed
- how a public key is encoded, and which spellings are refused
- what a scope address is, and why it is not the thread address of the same
  string

Those live here. **Signing and TLS do not.** They belong to the platform, where
they are already audited; shipping crypto nobody reviewed alongside a protocol
helper is how a small client becomes the weakest thing on the device.

## Measured

Built with `gcc -Os` for x86-64:

| | |
|---|---|
| Code | 3472 bytes |
| Initialised data, bss | 0, 0 |
| Heap | none, ever |
| Deepest stack | about 640 bytes, in sha256 |

There is no `malloc` in this library. Every output buffer is the caller's, with
its size, and nothing is written to it on failure.

## What it passes

`testdata/vectors.json` is the same file six of the seven aamio clients carry
byte for byte, sha256 `342ea401…`. Twenty-nine checks, run with
`-Wall -Wextra -Werror`:

```
python tools/build.py          # generate the vector header, compile, run
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

| Read | Bytes |
|---|---|
| No limit, as before | 20526 |
| `X-Limit: 1` | 357 |
| Nothing new | 144 |
| The large one, against a 2000 byte budget | 390 |

The envelope alone — address, times, count, allowlist, cursor — is 156 bytes.

Whole messages only: a signed message is never cut, because half its bytes
verify against nothing. One that alone exceeds the budget comes back as
`too_large` with its `seq` and size, the cursor unchanged, and two ways on:
read it with a bigger budget, or pass its `seq` as `after` to leave it unread.
`more: true` says something was left behind.

Check `read-limits` in `/.well-known/aamio.json` before relying on it. An older
service ignores both headers and answers with the whole thread.

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

## What has not been done

- No firmware built, flashed or measured. No TLS handshake timed, no
  certificate chain checked on device, no proof-of-work timed.
- No example for ESP-IDF, Arduino or Pico SDK.
- No Ed25519 binding written against mbedTLS.
- The encrypted envelope is not here: sealing needs Curve25519, which is the
  platform's, and the format is in the reference.

Until those exist, this is a conformance-checked core and nothing more.
