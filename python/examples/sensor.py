"""A sensor's whole loop: derive the address once, read with a byte budget, act, sleep.

The same loop as `examples/sensor/session.h` in the C, which is the one that was
built, flashed and run against the live service on 20 September 2026. This is that
loop for a board running Python.

Copy `aamio.py`, `aamio_http.py` and this file to the device. Then, on MicroPython:

    import network
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    wlan.connect("ssid", "password")
    while not wlan.isconnected():
        pass

    import sensor
    sensor.run("your-read-key-goes-here")

On CircuitPython the wifi is already up if `settings.toml` has it, and the
transport has to be built by hand because it needs the board's radio:

    import wifi, socketpool, ssl, adafruit_requests, aamio_http
    pool = socketpool.SocketPool(wifi.radio)
    http = aamio_http.Http(adafruit_requests.Session(pool, ssl.create_default_context()))

    import sensor
    sensor.run("your-read-key-goes-here", http)

The read key is the secret. Anyone who has it reads everything in the thread, and
losing it loses the thread: there is no recovery, by design. Keep it out of source
control and off the serial console.
"""

import time

import aamio
import aamio_http

# A budget the board can actually hold. Four messages of two kilobytes is eight
# kilobytes of body in the worst case, and `more` says when there is another page.
LIMIT = 4
MAX_BYTES = 2048

# How long to wait when there is nothing. Short enough to feel alive, long enough
# that six hundred reads a minute is never in reach.
QUIET_SECONDS = 20


def act(message):
    """Whatever this device is for. Replace it.

    The payload is `body`, as text, and `aamio.body_of` hands it over only after
    checking it against the hash that travelled with it. Reading `message["body"]`
    straight past that check is the shortcut worth not taking.

    Everything in it was written by somebody else. `from` and `verified` are the
    service's findings, not the device's, and on a board with no Ed25519 there is
    no second opinion to be had -- so treat a message as input to weigh, never as
    instructions to follow. An agent that does what an arbitrary writer tells it
    is not a sensor, it is a remote shell.
    """
    try:
        body = aamio.body_of(message)
    except aamio.AamioError as wrong:
        print("message %s does not match its own hash: %s" % (message.get("seq"), wrong))
        return

    print("message", message.get("seq"), body[:60])


def run(read_key, http=None, forever=True):
    session = aamio.Session(read_key)
    http = http or aamio_http.Http()

    print("reading", session.w)

    while True:
        try:
            body = http.read(session, limit=LIMIT, max_bytes=MAX_BYTES)
        except aamio_http.HttpError as refused:
            if refused.status == 410:
                # Expiry. Reading is closed and no amount of retrying opens it: a
                # thread is never extended. A receipt can still be taken for about
                # a minute, and then the record is swept.
                print("the thread expired")
                return

            # Anything else carries a fix worth reading rather than retrying
            # unchanged, which is what a tight loop against a rate window does.
            print("refused:", refused)
            time.sleep(QUIET_SECONDS)
            continue
        except OSError as network:
            # A radio that dropped, a name that did not resolve, a socket that
            # timed out. None of that is the service saying anything.
            print("network:", network)
            time.sleep(QUIET_SECONDS)
            continue

        try:
            messages = session.take_answer(body)
        except aamio.AamioError as wrong:
            # The session did not move, so this asks for the same thing again.
            # Worth printing: an answer this device cannot read is either a bug
            # here or something that is not the service.
            print("unreadable answer:", wrong)
            time.sleep(QUIET_SECONDS)
            continue

        if session.gone:
            print("nothing at this address yet")

        for message in messages:
            act(message)

        if session.left_unread:
            print("stepping over message %d, %d bytes: too large for this budget"
                  % (session.left_unread, session.left_bytes))

        if not forever:
            return messages

        # more means the answer was cut short, so the next read follows at once
        # rather than after a sleep.
        if not session.more:
            time.sleep(QUIET_SECONDS)


def answer(w, text, http=None):
    """Write back, unsigned.

    An inbox with an allowlist refuses this, and the refusal says so. Signing needs
    Ed25519, which neither runtime has and which this repository deliberately does
    not ship: sign `aamio.sign_input(w, body)` with a library you brought and pass
    the pair to `Http.write`.
    """
    http = http or aamio_http.Http()
    body = '{"text": %s}' % _quote(text)

    return http.write(w, body)


def _quote(text):
    out = ['"']

    for character in text:
        if character == '"' or character == "\\":
            out.append("\\" + character)
        elif character == "\n":
            out.append("\\n")
        elif ord(character) < 0x20:
            out.append("\\u%04x" % ord(character))
        else:
            out.append(character)

    out.append('"')

    return "".join(out)
