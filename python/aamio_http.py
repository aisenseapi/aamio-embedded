"""The thin part that differs between MicroPython, CircuitPython and a desktop.

Everything protocol-shaped lives in `aamio.py`. What is here is three runtimes
disagreeing about how to make an HTTPS request, and two opinions:

    a read without a byte budget is a bug waiting for a busy thread, and
    a read key goes to the service and to nobody else.

Fifty messages is a legal answer and can be megabytes. On a board that is an
allocation failure in the middle of a parse, so `read` sends a budget whether or
not the caller thought about it. Pass `max_bytes=None` to mean it, and then it is
a decision rather than an oversight. Whatever the service was asked for, what
comes back is read up to a local ceiling and no further, within a time limit,
and an answer past either is closed where it is with nothing from it believed:
the budget is a request to the service, not a guard against what arrives.

The read key travels in a header, and a header goes wherever the request goes.
So the request goes only to the service, over a connection that has checked it
is the service -- the certificate against a CA, the name against the certificate
-- and never follows a redirect, since a redirect is exactly the same request,
headers and all, going somewhere else. The deep health check of 21 September
2026 found this module taking whatever `requests` it could find, and the one
MicroPython finds sets the TLS context to CERT_NONE and follows a 302 to another
host, or to plain http, with X-Read still attached.

What a transport is
    Anything with `get(url, ...)`, `put(url, data=..., ...)` and
    `post(url, data=..., ...)` that

      * verifies the certificate against a CA and the name against the
        certificate, or it does not carry a key. Nothing here can check that from
        the outside: whoever passes a transport in vouches for it.
      * takes `timeout=` in seconds, `allow_redirects=False` and `stream=True`,
        and honours them: no redirect is ever followed, and the body is read when
        asked for, not before.
      * hands back an answer with `status_code`, `iter_content(chunk_size)`
        yielding bytes, and `close()`.

    `adafruit_requests.Session` is one, built on `ssl.create_default_context()`;
    so is CPython's `requests`. `Tls` below is one for MicroPython, and `_Urllib`
    is what a desktop gets. micropython-lib's `requests`, and `urequests` before
    it, is not one, and is not looked for any more.

MicroPython
    Pass `Tls` with the CA certificate the service chains to, as DER bytes, once
    the wifi is up and the clock is set:

        import ntptime, aamio_http
        ntptime.settime()
        http = aamio_http.Http(aamio_http.Tls(open("isrgrootx1.der", "rb").read()))

CircuitPython
    `adafruit_requests` needs a socket pool and an SSL context, which need the
    board's own wifi object, so it cannot be built here. Make it and pass it in:

        import wifi, socketpool, ssl, adafruit_requests
        pool = socketpool.SocketPool(wifi.radio)
        http = aamio_http.Http(adafruit_requests.Session(pool, ssl.create_default_context()))

CPython
    Falls back to urllib and the system's CA store, which is what lets the tests
    run this on a desktop.

Anything else, or either board with nothing passed in, is refused when `Http` is
made rather than at the first request, and the refusal says what to pass.
"""

import sys
import time

try:
    import json
except ImportError:
    import ujson as json                   # noqa: F401

import aamio


DEFAULT_HOST = "https://aamio.at"

# A read that does not say otherwise gets these. Four messages of up to four
# kilobytes is a bounded allocation on a board with a few hundred kilobytes, and
# `more` tells the caller there is another page rather than leaving it guessing.
DEFAULT_LIMIT = 4
DEFAULT_MAX_BYTES = 4096

# Longer than the longest long poll, which is twenty-five seconds, so a wait that
# ends the ordinary way is not mistaken for a peer that stopped answering. It is
# both how long one wait on the socket may take and how long the whole answer may
# take to arrive once it has started.
DEFAULT_TIMEOUT = 30

# What an answer carries around the messages it was budgeted for: the address, the
# times, the count, an allowlist of up to twenty keys, the cursor, and the text
# that comes with too_large, reset or a note. Measured at 156 bytes with nothing
# in it; a full allowlist is nine hundred more. It is also the whole ceiling for
# an answer to open, write or gate, which carry no messages, and for a refusal,
# which carries a fix.
ANSWER_ROOM = 4096

# A read with no byte budget can answer with a whole thread: 1048576 bytes of
# bodies, which is the service's ceiling per thread, and two hundred messages'
# worth of what it wraps around each. A caller who passed max_bytes=None meant it.
WHOLE_THREAD = 1048576 + 200 * 512

# How much is asked of the transport at a time: small enough to hold twice on a
# board, large enough that an ordinary answer is a few of them.
CHUNK = 1024


class HttpError(Exception):
    """A status this module will not decide about on the caller's behalf."""

    def __init__(self, status, text):
        # super(), not Exception.__init__: MicroPython has no __init__ on the
        # type object, so the old form raised AttributeError in place of every
        # refusal, and the portable suite stopped at its first redirect under
        # the real thing. Finding N3 of the health check of 21 September 2026.
        super().__init__("aamio answered %d: %s" % (status, text[:200]))
        self.status = status
        self.text = text


class Redirected(HttpError):
    """A 3xx. Refused and never followed: the key was for the service, not for wherever it points."""


class Oversize(HttpError):
    """An answer past the local ceiling. Closed where it was, and nothing from it believed."""


def _clock():
    # ticks_ms on MicroPython, monotonic on CPython and CircuitPython. getattr
    # with a default is not on every build, so this asks by trying.
    try:
        return time.ticks_ms()
    except AttributeError:
        return time.monotonic()


def _elapsed(since):
    try:
        return time.ticks_diff(time.ticks_ms(), since) / 1000.0
    except AttributeError:
        return time.monotonic() - since


def _printable(value, what):
    """Printable ASCII, or a refusal.

    A header is a line, and a line break in a value is a second header, on a
    transport that writes lines. A key or a nonce with anything else in it is not
    one the service takes either, so nothing is lost by refusing here.
    """
    if not isinstance(value, str):
        raise ValueError("%s is text" % what)

    for character in value:
        if not " " <= character <= "~":
            raise ValueError("%s carries printable ASCII and nothing else, and this has %r"
                             % (what, character))

    return value


def _collect(answer, status, ceiling, timeout):
    """The body as text, up to `ceiling` bytes and within `timeout` seconds, or a refusal.

    Read in pieces, so that an answer past the ceiling is stopped there rather
    than held whole and measured afterwards, which on a board is the allocation
    failure the ceiling is there to prevent. Each wait on the socket has the
    transport's timeout; the clock here is the whole answer's, since a peer that
    sends one byte inside every timeout would otherwise hold the device for as
    long as it liked. It runs from the answer's first byte where the transport
    says when that was, as `Tls` does: measured from the body alone, a peer
    could drip the headers for as long as it liked first. N4 of the same check.
    """
    parts = []
    got = 0

    try:
        started = answer.started
    except AttributeError:
        started = None

    if started is None:
        started = _clock()

    for piece in answer.iter_content(chunk_size=CHUNK):
        got += len(piece)

        if got > ceiling:
            raise Oversize(status, "the answer runs past %d bytes and is not read any further" % ceiling)

        parts.append(piece)

        if _elapsed(started) > timeout:
            raise OSError("the answer did not arrive within %d seconds" % timeout)

    # And once more when the answer ends, since the end can come late as well:
    # a close-delimited answer whose last byte and EOF arrived after the
    # deadline was taken, because the clock was read only after each piece.
    # E1 of the health check of 24 September 2026.
    if _elapsed(started) > timeout:
        raise OSError("the answer did not end within %d seconds" % timeout)

    raw = b"".join(parts)

    try:
        return str(raw, "utf-8")
    except (ValueError, UnicodeError):
        raise HttpError(status, "the answer is not UTF-8")


def _desktop_transport():
    """urllib on CPython, and on anything else a refusal that names what to pass.

    This used to take whatever `requests` it found, and the one MicroPython finds
    verifies nothing. Nothing is picked up from the runtime any more: a transport
    that was not named is a transport nobody vouched for.
    """
    if sys.implementation.name == "cpython":
        return _Urllib()

    raise ValueError(
        "no transport: on MicroPython pass aamio_http.Tls(cadata) with the DER bytes of "
        "the CA the service chains to, on CircuitPython an adafruit_requests.Session "
        "built on ssl.create_default_context(). micropython-lib's requests verifies no "
        "certificate and follows redirects with the read key attached, so it is not "
        "looked for")


def _split_https(url):
    """host, port and path from an https URL, and a refusal for anything else.

    https and nothing else: the read key is in a header, and a header over http
    is a postcard.
    """
    if not isinstance(url, str) or not url.startswith("https://"):
        raise ValueError("https only, and this is not: %r" % (url,))

    rest = url[len("https://"):]
    cut = rest.find("/")
    origin = rest if cut < 0 else rest[:cut]
    path = "/" if cut < 0 else rest[cut:]
    port = 443

    if ":" in origin:
        origin, port_text = origin.split(":", 1)
        port = int(port_text)

    if not origin:
        raise ValueError("no host in %r" % url)

    return origin, port, path


def _write_all(sock, data):
    view = memoryview(data)

    while len(view):
        wrote = sock.write(view)

        if not wrote:
            raise OSError("the socket took nothing")

        view = view[wrote:]


class Tls:
    """The runtime's own socket and TLS, told to verify. For MicroPython.

    micropython-lib's `requests`, and `urequests` before it, sets the TLS context
    to CERT_NONE and follows a redirect with every header it was given, Host
    aside; a read key sent over it goes to whoever answers the name, and then to
    wherever that party points. This makes the same request over the same mbedtls
    with the certificate checked against a CA the caller provides and the name
    checked against the certificate, follows nothing, writes nothing a header may
    not carry, and reads the body only as it is asked for, so `Http` can stop it.

    `cadata` is the CA certificate as DER bytes: the root the service's certificate
    chains to. For aamio.at that is Let's Encrypt's ISRG Root X1, at
    https://letsencrypt.org/certs/isrgrootx1.der, 1.4 kilobytes; copy it to the
    board beside these files. There is no default, because a device that trusts
    nothing in particular trusts everything, and a root shipped here would make
    this file the place that decides whom every device believes.

    The clock has to be right before a certificate can be judged. On MicroPython
    that is `ntptime.settime()` once the wifi is up; without it every certificate
    is not yet valid or long expired and the handshake fails, which is the right
    answer from a device that does not know what day it is.

    Needs `SSLContext`, which MicroPython has had since 1.23. Runs on CPython as
    well, over `ssl`, which is where the tests drive it against instrumented
    sockets. The same checks ran under the unix port of MicroPython 1.25.0 on 24
    September 2026; a board has not run it.

    `sockets` and `tls` stand in for the `socket` and `tls` modules, for a runtime
    that keeps them under another name, and for the tests.
    """

    # More than this of headers is not the service, whatever it is.
    HEADER_BYTES = 4096

    class _Answer:
        def __init__(self, status, sock, first, length, started=None):
            self.status_code = status
            self.sock = sock
            self.first = first     # body bytes that arrived with the headers
            self.left = length     # what Content-Length promised, or None
            self.started = started  # when the first byte of the answer arrived

        def iter_content(self, chunk_size=CHUNK):
            piece = self.first
            self.first = b""

            while True:
                if self.left is not None:
                    piece = piece[:self.left]
                    self.left -= len(piece)

                if piece:
                    yield piece

                if self.left == 0 or self.sock is None:
                    return

                piece = self.sock.read(chunk_size)

                if not piece:
                    # The end, when nothing was promised. With a Content-Length
                    # still owed it is a connection that broke, and an answer
                    # that happens to parse is not one to believe. N5.
                    if self.left:
                        raise OSError("the connection closed with %d bytes of the body still to come" % self.left)

                    return

        def close(self):
            if self.sock is not None:
                self.sock.close()
                self.sock = None

    def __init__(self, cadata, sockets=None, tls=None):
        if not isinstance(cadata, (bytes, bytearray)) or len(cadata) == 0:
            raise ValueError("cadata is the CA certificate as DER bytes, and there is no default")

        if sockets is None:
            import socket as sockets

        if tls is None:
            try:
                import tls
            except ImportError:
                import ssl as tls

        self.sockets = sockets
        self.tls = tls
        self.context = tls.SSLContext(tls.PROTOCOL_TLS_CLIENT)
        self.context.verify_mode = tls.CERT_REQUIRED
        self.context.load_verify_locations(cadata=bytes(cadata))

    def _connect(self, host, port, timeout):
        info = self.sockets.getaddrinfo(host, port, 0, self.sockets.SOCK_STREAM)[0]
        sock = self.sockets.socket(info[0], info[1], info[2])

        try:
            if timeout is not None:
                sock.settimeout(timeout)

            sock.connect(info[-1])

            # server_hostname is what the certificate's name is checked against,
            # and what SNI carries. Without it CERT_REQUIRED checks the chain and
            # not the name, and any certificate the CA ever signed would do.
            return self.context.wrap_socket(sock, server_hostname=host)
        except Exception:
            sock.close()
            raise

    def _head(self, sock, timeout=None):
        """The status, what Content-Length promised, the body bytes that came along, and when the first byte came.

        Read a piece at a time rather than a line at a time, since a line at a
        time is not on every socket; whatever follows the blank line is the start
        of the body and is handed to the answer. The clock starts at the first
        byte and is the same one the body is read against: each socket wait has
        its own timeout, and a peer that dripped one header byte inside every
        wait held the device for as long as it liked.
        """
        got = b""
        started = None

        while True:
            end = got.find(b"\r\n\r\n")

            if end >= 0:
                break

            if len(got) > self.HEADER_BYTES:
                raise OSError("more than %d bytes of headers, which is not the service" % self.HEADER_BYTES)

            piece = sock.read(512)

            if not piece:
                raise OSError("the connection closed before the headers ended")

            if started is None:
                started = _clock()

            got += piece

            if timeout is not None and _elapsed(started) > timeout:
                raise OSError("the headers did not arrive within %d seconds" % timeout)

        lines = got[:end].split(b"\r\n")
        parts = lines[0].split(None, 2)

        if len(parts) < 2 or not parts[0].startswith(b"HTTP/"):
            raise OSError("not an HTTP answer")

        try:
            status = int(str(parts[1], "utf-8"))
        except ValueError:
            raise OSError("not an HTTP status")

        length = None

        for line in lines[1:]:
            name_value = line.split(b":", 1)

            if len(name_value) != 2:
                continue

            name = name_value[0].strip().lower()
            value = name_value[1].strip()

            if name == b"content-length":
                try:
                    declared = int(str(value, "utf-8"))
                except ValueError:
                    raise OSError("a Content-Length that is not a number")

                if declared < 0:
                    raise OSError("a Content-Length below zero")

                # Two that disagree are not a length at all. The last one used
                # to win, and what arrived was measured against it. RFC 9112
                # allows a repeat only with the same value. E2 of the same check.
                if length is not None and length != declared:
                    raise OSError("two Content-Length headers that disagree: %d and %d" % (length, declared))

                length = declared
            elif name == b"transfer-encoding" and b"chunked" in value.lower():
                # HTTP/1.0 was asked for, and a 1.0 client is never sent chunks.
                # A peer that does so is not talking to this client.
                raise OSError("a chunked answer, which this transport does not read")

        return status, got[end + 4:], length, started

    def request(self, method, url, headers=None, data=None, timeout=None,
                allow_redirects=False, stream=True):
        if allow_redirects:
            raise ValueError("this transport follows no redirect")

        host, port, path = _split_https(url)

        if data is None:
            data = b""
        elif isinstance(data, str):
            data = data.encode("utf-8")

        for character in path:
            if not "!" <= character <= "~":
                raise ValueError("a path carries printable ASCII without spaces, and this has %r" % character)

        lines = ["%s %s HTTP/1.0" % (method, path),
                 "Host: " + host if port == 443 else "Host: %s:%d" % (host, port)]

        for name in (headers or {}):
            lines.append(_printable(name, "a header name") + ": "
                         + _printable(headers[name], "the header " + name))

        if method != "GET":
            lines.append("Content-Length: %d" % len(data))

        lines.append("Connection: close")
        sock = self._connect(host, port, timeout)

        try:
            _write_all(sock, ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8"))

            if data:
                _write_all(sock, data)

            status, first, length, started = self._head(sock, timeout)
        except Exception:
            sock.close()
            raise

        return self._Answer(status, sock, first, length, started)

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def put(self, url, **kw):
        return self.request("PUT", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)


class _Urllib:
    """Enough of the transport shape for CPython, so the tests exercise the real paths.

    The system's CA store through ssl.create_default_context(), which requires a
    certificate and checks the name; a redirect handler that declines every
    redirect, so a 3xx comes back as itself and is refused by `Http`; the timeout
    on every wait; and the body handed over in pieces, so the ceiling is a
    ceiling on what is read and not only on what is kept.
    """

    class _Answer:
        def __init__(self, response):
            self.status_code = response.status
            self.response = response

        def iter_content(self, chunk_size=CHUNK):
            while True:
                piece = self.response.read(chunk_size)

                if not piece:
                    return

                yield piece

        def close(self):
            self.response.close()

    def __init__(self):
        import ssl
        import urllib.request

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, request, fp, code, msg, headers, newurl):
                # None is "not handled", so urlopen goes on to raise the 3xx as an
                # HTTPError, which request() below hands back as an answer with
                # that status. Nothing is asked of newurl, and no second request
                # is made.
                return None

        self.context = ssl.create_default_context()
        self.redirects = NoRedirect
        self.opener = urllib.request.build_opener(
            NoRedirect(), urllib.request.HTTPSHandler(context=self.context))

    def request(self, method, url, headers=None, data=None, timeout=None,
                allow_redirects=False, stream=True):
        import urllib.error
        import urllib.request

        if allow_redirects:
            raise ValueError("this transport follows no redirect")

        ask = urllib.request.Request(url, data=data, headers=headers or {}, method=method)

        try:
            return self._Answer(self.opener.open(ask, timeout=timeout))
        except urllib.error.HTTPError as refused:
            # A status outside 2xx, a redirect included. The body is the service's
            # refusal with its fix, and the status is the answer's to judge.
            return self._Answer(refused)

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def put(self, url, **kw):
        return self.request("PUT", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)


class Http:
    """Reads and writes for one service. Holds no key and remembers nothing.

    `transport` is what makes the requests; see the top of this file for what one
    is and what passing one vouches for. Without one a desktop gets urllib and a
    board gets a refusal. `host` is an https origin and nothing else. `timeout`
    is seconds, for one wait on the socket and for the whole of an answer.
    """

    def __init__(self, transport=None, host=DEFAULT_HOST, timeout=DEFAULT_TIMEOUT):
        if not isinstance(host, str) or not host.startswith("https://"):
            raise ValueError("the host is an https:// origin: the read key travels in a header, "
                             "and a header over http is a postcard")

        if timeout is None or timeout <= 0:
            raise ValueError("timeout is seconds, and there is no never")

        self.host = host.rstrip("/")
        self.timeout = timeout
        self.transport = transport if transport is not None else _desktop_transport()

    def _send(self, method, path, headers, data=None, ceiling=ANSWER_ROOM):
        # get, post and put are what the transports agree on. `request` exists on
        # some of them and not on all, so it is not what this leans on.
        #
        # allow_redirects=False and stream=True are what the transport is asked
        # for; whether it honours them is what the caller vouched for. The 3xx
        # check below catches a transport that hands the redirect back, which is
        # every transport named in this file. One that follows it in silence has
        # already sent the key on, and nothing here can see that.
        url = self.host + path

        if method == "GET":
            answer = self.transport.get(url, headers=headers, timeout=self.timeout,
                                        allow_redirects=False, stream=True)
        elif method == "PUT":
            answer = self.transport.put(url, headers=headers, data=data, timeout=self.timeout,
                                        allow_redirects=False, stream=True)
        else:
            answer = self.transport.post(url, headers=headers, data=data, timeout=self.timeout,
                                         allow_redirects=False, stream=True)

        try:
            status = answer.status_code

            if 300 <= status <= 399:
                raise Redirected(status, "a redirect, refused and not followed: the key in this "
                                         "request was for %s and nowhere else" % self.host)

            text = _collect(answer, status, ceiling, self.timeout)
        finally:
            # The socket is held until this is called, and a board that forgets
            # runs out of them in a few hours rather than at once. getattr with a
            # default is not on every build, so this asks by trying.
            try:
                answer.close()
            except AttributeError:
                pass

        return status, text

    def open(self, session, ttl=None, allow=None):
        """Create the thread ahead of time, with its lifetime and its allowlist.

        A write to an address creates a thread as well, but with the default
        lifetime and open to anyone who has the address. Both of those are set here
        and nowhere else, and neither can be changed afterwards.

        `allow` is the keys that may write, as base64url or as their hashes, or
        `"*"` for any key as long as the message is signed. An address handed out
        before it lists the key you are handing it to is an address anyone can fill,
        and a refused write is told to the writer and never to you -- so an inbox
        missing that one key reads as an inbox nobody wrote to.
        """
        headers = {"X-Read": session.read_key, "Accept": "application/json"}

        if ttl is not None:
            headers["X-TTL"] = str(ttl)

        if allow is not None:
            headers["X-Allow"] = _printable(allow if isinstance(allow, str) else ",".join(allow),
                                            "the allowlist")

        status, text = self._send("PUT", "/" + session.w, headers)

        if status not in (200, 201):
            raise HttpError(status, text)

        return json.loads(text)

    def read(self, session, limit=DEFAULT_LIMIT, max_bytes=DEFAULT_MAX_BYTES):
        """One read at the session's cursor. Gives back the body for `take_answer`.

        The read key travels in a header and never in the path, because a path is
        what proxies, caches and logs keep. The answer is read up to the budget
        plus room for what wraps it, and no further: X-Max-Bytes is what the
        service was asked for, and this is what the device will take.
        """
        headers = {"X-Read": session.read_key, "Accept": "application/json"}

        if limit is not None:
            headers["X-Limit"] = str(limit)

        if max_bytes is not None:
            headers["X-Max-Bytes"] = str(max_bytes)

        ceiling = ANSWER_ROOM + (WHOLE_THREAD if max_bytes is None else max_bytes)
        status, text = self._send("GET", session.read_path(), headers, ceiling=ceiling)

        if status != 200:
            # 410 is expiry, and that is the caller's to handle: a sensor that
            # should open a new thread and one that should stop are both correct,
            # and this cannot know which.
            raise HttpError(status, text)

        return text

    def write(self, w, body, key=None, signature=None, allow=None, ttl=None, work=None):
        """Write to an address. Returns (status, text) without judging either.

        `key` and `signature` are the base64url pair; sign `aamio.sign_input(w, body)`
        with something that knows Ed25519, since this module does not. An inbox with
        an allowlist refuses an unsigned write, and that refusal carries a `fix`
        worth reading rather than retrying unchanged.
        """
        # A write used to take these and send them, and the service reads neither
        # on a POST: the caller set a lifetime and got the default, or set an
        # allowlist and got an inbox anyone could fill, with a 201 either way.
        # Refusing here is the only way that difference reaches whoever wrote it.
        if allow is not None or ttl is not None:
            raise ValueError(
                "a lifetime and an allowlist are set when the thread is opened, "
                "not on a write: use Http.open(session, ttl=..., allow=...)")

        # The address goes in the path and the pair go in headers, so each is
        # checked for shape before anything is sent, as the C beside this does.
        aamio.check_address(w)

        if key is not None:
            aamio.check_key_shape(key)

        if signature is not None:
            aamio.check_signature_shape(signature)

        if isinstance(body, str):
            body = body.encode("utf-8")
        elif isinstance(body, dict):
            body = json.dumps(body).encode("utf-8")

        headers = {"Content-Type": "application/json"}

        if key is not None:
            headers["X-Key"] = key

        if signature is not None:
            headers["X-Sig"] = signature

        if work is not None:
            headers["X-Work"] = _printable(work, "the work")

        return self._send("POST", "/" + w, headers, body)

    def gate(self, w):
        """What an inbox asks of a writer, set when it opened and never changed."""
        aamio.check_address(w)
        status, text = self._send("GET", "/" + w + "/gate", {"Accept": "application/json"})

        if status != 200:
            raise HttpError(status, text)

        return json.loads(text)
