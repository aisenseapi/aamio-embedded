# Changelog

aamio-embedded ships from git and carries no version of its own; entries are dated.

## 2026-09-21, an allowlist that was not one

- `Http.write` took `allow` and `ttl` and sent them as headers on a POST, which
  reads neither: both belong on the PUT that opens the thread. A caller set an
  allowlist, got 201, and had an inbox anyone holding the address could fill --
  and a refused write is told to the writer and never to the owner, so an inbox
  missing the key reads exactly like an inbox nobody wrote to. `Http.open` is new
  and sets both; `write` refuses them and says where they go.
- `b64url_encode` is new. The module could read a key and a signature and not
  write one, so its own advice -- sign with a library you brought and pass the
  pair -- had nowhere to turn the pair into the text a header carries.
- `python/test/live_signed.py` walks that path to what the service reports back,
  on both runtimes: signed write taken and verified, unsigned write refused 403
  with a fix, a signature of the right shape that is not one refused 401. It found
  the fault above on its first run, which is the argument for writing it.
- `python/test/ed25519_reference.py` is the signer those tests use: pure Python,
  checked against RFC 8032's own vector, and test material rather than something
  to sign with. It branches on the bits of the secret key, which is the one thing
  a signer must not do where anyone can measure it.
- Measured rather than assumed, since the reason given for leaving signing out was
  speed and that turned out to be wrong: one signature is 7 ms on CPython and 21 ms
  under MicroPython 1.25.0 on the same desktop, with 1.9 MB of allocation churn.
  The reason is side channels, not seconds, and the texts now say so.
- The board that ran the C loop has a name: an M5Stack ATOM.

## 2026-09-20, MicroPython and a browser, both ways

- Checked against the JavaScript client through the live page at
  aisense.no/try-aamio. The page opened an inbox advising sixteen bits of work;
  MicroPython wrote to it twice, once with none and once with the bits found on
  the runtime itself in a tenth of a second, and the page reported `pow 0` and
  `pow 16`. The other way, the page signed a message to a thread MicroPython held
  and MicroPython read it back, checked the body against its hash and refused to
  judge the sender without a verifier.
- `is_sealed(body)` is new, and it reads the envelope rather than the service's
  `sealed` flag. The browser seals by default when it has the other key, and a
  device that cannot decrypt was handing a `nacl.box.v1` envelope to whatever acts
  on messages -- a JSON object with a `ct` field and no reading in it. The sensor
  example now says so and leaves it alone.
- Nothing here decrypts. Opening a sealed message needs Curve25519, which is the
  platform's and is not in this module; what is new is knowing when not to try.

## 2026-09-20, MicroPython ran it

- The module was run by MicroPython 1.25.0 rather than by CPython pretending to
  be it. The unix port accepted the syntax, resolved the imports, made the same
  addresses, held every refusal, and with `--live` opened a thread on aamio.at
  through its own mbedtls, wrote to it and read it back: 26 checks, none failing.
- `python/test/test_micropython.py` is the subset both runtimes can run, kept apart
  from the fuller suite because that one needs `os.path` and `ast`, which a board
  does not have. A check that can only run where everything works is not a check.
- Still not a board, and still nothing under CircuitPython. The unix port has a
  desktop's memory and a desktop's speed; the texts say that in the same breath.

## 2026-09-20, the same protocol in Python

- `python/` carries the protocol for MicroPython and CircuitPython: three files
  copied to a board, no package and no dependency past `hashlib` and `json`. Same
  addresses, same ninety-four signed bytes, same refusals, same read session with
  its cursor and its byte budget. A C module for those runtimes means building
  custom firmware or forking one, and the protocol work is a sha256 per read.
- `body_of` hands over a payload only after checking it against the hash that came
  with it, and `sender_is_allowed` raises without a verifier rather than answering:
  neither runtime has Ed25519, and a sender check that cannot check is worse than
  none because it looks like one.
- A read sends a byte budget whether or not the caller thought about one. Fifty
  messages is a legal answer and can be megabytes, which on a board is an
  allocation failure in the middle of a parse.
- The suite refuses what runs on a desktop and not on a device -- an f-string, a
  three-argument `getattr`, an import neither runtime has. The tests run on CPython,
  which is the one place that check cannot come for free.
- Checked against the shared vectors and against the live service over TLS, from a
  desktop. **The Python module has not run on a board**, and the README says so in
  the same breath as it says the C has.
- The README said both: a status line at the top from before the flash saying no
  board had run it, and a section two screens down saying one had. A file that
  contradicts itself is worse than either claim, because a reader believes
  whichever they saw first.

## 2026-09-20, it ran on a board

- The ESP-IDF sensor example was built, flashed to an ESP32 board and run against
  the live service: derive the address once, read with a byte budget, act, sleep.
  Until now the README said no firmware had been built from it.
- What is claimed is that loop and no more. Nothing is timed, no certificate chain
  was checked by hand on device, and a signed write from the board is not claimed
  -- the example constructs and signs one, but the run reported was the read loop.

## 2026-09-20, the reader hardened

- The JSON reader refuses what it used to take. A name now needs its colon, a value
  has a type, and `true` and `"true"` are no longer the same answer: `exists` as a
  string read as a thread that exists, and `messages` as a string as a list of none.
- An answer the session refuses leaves the session exactly as it was. It used to set
  `gone`, `more` and the unread message on the way to checks that could still fail,
  so a caller told to read the same thing again read something else.
- A cursor must be a number, non-negative, and without a leading zero. A fraction, an
  exponent, a leading plus and `041` were all taken.
- `exists: false` forgets the cursor. Whatever opens at that address next counts from
  one, so the old number would have skipped its first messages without a word.
- `aamio_scope_address` requires a scope key of 26 characters or more. It took the
  thread id rule, which starts at 20, and so took an address as a key -- the mistake
  the service refuses by name.
- `aamio_b64url_decode` writes nothing unless the whole string decodes. `AQ!` used to
  turn `5a5a5a5a` into `015a5a5a` and then report an encoding error.
- A hundred checks in three suites, up from forty-nine in two.
- The README says which compiler and flags its size figures came from, and that the
  640-byte stack figure is the sha256 chain and not a ceiling for your program.

## 2026-09-20, first commit

- The protocol core in C99 for microcontrollers: the write address from a read key,
  the ninety-four bytes that get signed, canonical base64url keys, the scope address
  and a reader for a thread's answers. No heap, and every output buffer is the
  caller's with its size.
- `examples/sensor` shows the loop: derive the address once, read with a byte budget,
  act, sleep. No firmware has been built or flashed from it.
