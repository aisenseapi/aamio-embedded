"""The thin part that differs between MicroPython, CircuitPython and a desktop.

Everything protocol-shaped lives in `aamio.py`. What is here is three runtimes
disagreeing about how to make an HTTPS request, and one opinion:

    a read without a byte budget is a bug waiting for a busy thread.

Fifty messages is a legal answer and can be megabytes. On a board that is an
allocation failure in the middle of a parse, so `read` sends a budget whether or
not the caller thought about it. Pass `max_bytes=None` to mean it, and then it is
a decision rather than an oversight.

MicroPython
    `urequests` (or `requests` on newer builds) is found by itself. Connect wifi
    first; nothing here does that.

CircuitPython
    `adafruit_requests` needs a socket pool and an SSL context, which need the
    board's own wifi object, so it cannot be built here. Make it and pass it in:

        import wifi, socketpool, ssl, adafruit_requests
        pool = socketpool.SocketPool(wifi.radio)
        http = aamio_http.Http(adafruit_requests.Session(pool, ssl.create_default_context()))

CPython
    Falls back to urllib, which is what lets the tests run this on a desktop.
"""

try:
    import json
except ImportError:
    import ujson as json                   # noqa: F401


DEFAULT_HOST = "https://aamio.at"

# A read that does not say otherwise gets these. Four messages of up to four
# kilobytes is a bounded allocation on a board with a few hundred kilobytes, and
# `more` tells the caller there is another page rather than leaving it guessing.
DEFAULT_LIMIT = 4
DEFAULT_MAX_BYTES = 4096


class HttpError(Exception):
    """A status this module will not decide about on the caller's behalf."""

    def __init__(self, status, text):
        Exception.__init__(self, "aamio answered %d: %s" % (status, text[:200]))
        self.status = status
        self.text = text


def _find_requests():
    try:
        import urequests
        return urequests
    except ImportError:
        pass

    try:
        import requests
        return requests
    except ImportError:
        pass

    return None


class _Urllib:
    """Enough of the requests shape for CPython, so the tests exercise the real paths."""

    class _Answer:
        def __init__(self, status, text):
            self.status_code = status
            self.text = text

        def close(self):
            pass

    def request(self, method, url, headers=None, data=None):
        import urllib.error
        import urllib.request

        ask = urllib.request.Request(url, data=data, headers=headers or {}, method=method)

        try:
            with urllib.request.urlopen(ask, timeout=30) as answer:
                return self._Answer(answer.status, answer.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as refused:
            return self._Answer(refused.code, refused.read().decode("utf-8", "replace"))

    def get(self, url, headers=None):
        return self.request("GET", url, headers=headers)

    def post(self, url, headers=None, data=None):
        return self.request("POST", url, headers=headers, data=data)


class Http:
    """Reads and writes for one service. Holds no key and remembers nothing."""

    def __init__(self, transport=None, host=DEFAULT_HOST):
        self.host = host.rstrip("/")
        self.transport = transport or _find_requests() or _Urllib()

    def _send(self, method, path, headers, data=None):
        # get and post are the two all three transports agree on. `request` exists
        # on some of them and not on urequests, so it is not what this leans on.
        url = self.host + path

        if method == "GET":
            answer = self.transport.get(url, headers=headers)
        else:
            answer = self.transport.post(url, headers=headers, data=data)

        try:
            status = answer.status_code
            text = answer.text
        finally:
            # urequests holds the socket until this is called, and a board that
            # forgets runs out of them in a few hours rather than at once.
            # getattr with a default is not on every build, so this asks by trying.
            try:
                answer.close()
            except AttributeError:
                pass

        return status, text

    def read(self, session, limit=DEFAULT_LIMIT, max_bytes=DEFAULT_MAX_BYTES):
        """One read at the session's cursor. Gives back the body for `take_answer`.

        The read key travels in a header and never in the path, because a path is
        what proxies, caches and logs keep.
        """
        headers = {"X-Read": session.read_key, "Accept": "application/json"}

        if limit is not None:
            headers["X-Limit"] = str(limit)

        if max_bytes is not None:
            headers["X-Max-Bytes"] = str(max_bytes)

        status, text = self._send("GET", session.read_path(), headers)

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
        if isinstance(body, str):
            body = body.encode("utf-8")
        elif isinstance(body, dict):
            body = json.dumps(body).encode("utf-8")

        headers = {"Content-Type": "application/json"}

        if key is not None:
            headers["X-Key"] = key

        if signature is not None:
            headers["X-Sig"] = signature

        if allow is not None:
            headers["X-Allow"] = allow if isinstance(allow, str) else ",".join(allow)

        if ttl is not None:
            headers["X-TTL"] = str(ttl)

        if work is not None:
            headers["X-Work"] = work

        return self._send("POST", "/" + w, headers, body)

    def gate(self, w):
        """What an inbox asks of a writer, set when it opened and never changed."""
        status, text = self._send("GET", "/" + w + "/gate", {"Accept": "application/json"})

        if status != 200:
            raise HttpError(status, text)

        return json.loads(text)
