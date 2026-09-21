"""Stand-ins for a transport, a socket module and a TLS module, so the HTTP paths run with no network.

Nothing here opens a connection. A `Transport` answers with whatever it was
scripted to, and records what it was asked; `Sockets` and `TlsModule` play the
`socket` and `tls` modules for `aamio_http.Tls`, and record the one thing that
matters for each: whether a certificate was required and against what, which name
it was checked against, what timeout was set, and where the connection went. The
deep health check of 21 September 2026 found the faults these are for by the same
means, so a fix is measured the way the fault was.

Both runtimes can run this: plain classes, no `os.path`, no `unittest`.
"""


class Answer:
    """What a transport hands back: a status and a body in pieces."""

    def __init__(self, status, body=b"", pieces=None, delay=0):
        self.status_code = status
        self.body = body
        self.pieces = pieces
        self.delay = delay
        self.closed = False
        self.served = 0

    def iter_content(self, chunk_size=1):
        if self.delay:
            import time

        if self.pieces is not None:
            for piece in self.pieces:
                if self.delay:
                    time.sleep(self.delay)

                self.served += len(piece)
                yield piece

            return

        at = 0

        while at < len(self.body):
            if self.delay:
                time.sleep(self.delay)

            piece = self.body[at:at + chunk_size]
            at += len(piece)
            self.served += len(piece)
            yield piece

    def close(self):
        self.closed = True


class Transport:
    """Scripted answers, one per call, and a record of every request made."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = []

    def _serve(self, method, url, headers=None, data=None, **kw):
        self.calls.append({"method": method, "url": url, "headers": dict(headers or {}),
                           "data": data, "kw": dict(kw)})

        if not self.answers:
            raise AssertionError("a request nobody scripted: %s %s" % (method, url))

        answer = self.answers.pop(0)
        self.last = answer

        return answer

    def get(self, url, **kw):
        return self._serve("GET", url, **kw)

    def put(self, url, **kw):
        return self._serve("PUT", url, **kw)

    def post(self, url, **kw):
        return self._serve("POST", url, **kw)


class Socket:
    """One scripted connection: hands back the bytes it was given, in pieces of any size."""

    def __init__(self, sockets, family, kind, proto):
        self.sockets = sockets
        self.family = family
        self.kind = kind
        self.proto = proto
        self.timeout = None
        self.connected_to = None
        self.written = b""
        self.served = b""
        self.closed = False

    def settimeout(self, seconds):
        self.timeout = seconds

    def connect(self, address):
        self.connected_to = address
        self.sockets.connections.append(address)

    def write(self, data):
        self.written += bytes(data)

        return len(data)

    def read(self, size):
        piece = self.served[:size]
        self.served = self.served[size:]

        return piece

    def close(self):
        self.closed = True


class Sockets:
    """The `socket` module: getaddrinfo, socket, SOCK_STREAM. Each socket serves the next scripted answer."""

    SOCK_STREAM = 1

    def __init__(self, answers):
        self.answers = list(answers)
        self.connections = []
        self.sockets = []

    def getaddrinfo(self, host, port, family=0, kind=0):
        return [(2, kind, 0, "", (host, port))]

    def socket(self, family, kind, proto):
        made = Socket(self, family, kind, proto)

        if self.answers:
            made.served = self.answers.pop(0)

        self.sockets.append(made)

        return made


class Wrapped:
    """The socket after wrap_socket: the same bytes, and a note of the name it was checked against."""

    def __init__(self, inner, server_hostname):
        self.inner = inner
        self.server_hostname = server_hostname

    def read(self, size):
        return self.inner.read(size)

    def write(self, data):
        return self.inner.write(data)

    def close(self):
        self.inner.close()


class Context:
    def __init__(self, protocol):
        self.protocol = protocol
        self.verify_mode = None
        self.cadata = None
        self.wrapped = []

    def load_verify_locations(self, cafile=None, cadata=None):
        self.cadata = cadata

    def wrap_socket(self, sock, server_hostname=None):
        if self.verify_mode != TlsModule.CERT_REQUIRED:
            raise AssertionError("wrap_socket without CERT_REQUIRED: %r" % self.verify_mode)

        if self.cadata is None:
            raise AssertionError("wrap_socket with no CA loaded")

        if not server_hostname:
            raise AssertionError("wrap_socket without server_hostname: the name would go unchecked")

        wrapped = Wrapped(sock, server_hostname)
        self.wrapped.append(wrapped)

        return wrapped


class TlsModule:
    """The `tls` module: SSLContext and the constants, with the values MicroPython uses."""

    PROTOCOL_TLS_CLIENT = 2
    CERT_NONE = 0
    CERT_OPTIONAL = 1
    CERT_REQUIRED = 2

    def __init__(self):
        self.contexts = []

    def SSLContext(self, protocol):
        made = Context(protocol)
        self.contexts.append(made)

        return made


def http_answer(status, body, extra_headers=()):
    """The bytes of an HTTP/1.1 answer, Content-Length set, as a server would send them."""
    if isinstance(body, str):
        body = body.encode("utf-8")

    head = "HTTP/1.1 %d Whatever\r\nContent-Type: application/json\r\nContent-Length: %d\r\n" % (status, len(body))

    for line in extra_headers:
        head += line + "\r\n"

    return head.encode("utf-8") + b"\r\n" + body
