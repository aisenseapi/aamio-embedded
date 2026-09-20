# Changelog

aamio-embedded ships from git and carries no version of its own; entries are dated.

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
