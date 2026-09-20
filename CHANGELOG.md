# Changelog

aamio-embedded ships from git and carries no version of its own; entries are dated.

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
