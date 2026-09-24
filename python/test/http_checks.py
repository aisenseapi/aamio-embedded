"""The transport, driven with no network: what `Http` asks of a transport, what it refuses from one, and what `Tls` does with a socket.

Run by both suites, since both runtimes have to give the same answers. The faults
these cover are F1, F2 and F3 of the deep health check of 21 September 2026: a
transport that authenticated nobody, a redirect followed with the read key still
attached, and an answer read whole with no timeout. They were found with
instrumented socket and TLS modules, and they are held shut the same way.
"""

import aamio
import aamio_http
import fakes

KEY = "abcdefghijklmnopqrstuvwxyz"


def _session(after=0):
    session = aamio.Session(KEY)
    session.after = after

    return session


def run(check):
    print("what is asked of a transport")
    session = _session()
    transport = fakes.Transport([fakes.Answer(200, b'{"exists":true,"messages":[],"next":0}')])
    http = aamio_http.Http(transport)
    http.read(session)
    check(transport.calls[0]["kw"] == {"timeout": aamio_http.DEFAULT_TIMEOUT,
                                       "allow_redirects": False, "stream": True},
          "every request asks for no redirect, a timeout, and a body in pieces")
    check(transport.last.closed, "and the answer is closed when it has been read")

    print("a redirect is refused, never followed, and the key goes nowhere else")
    calls = (("read", lambda h: h.read(session)),
             ("open", lambda h: h.open(session, ttl=60)),
             ("write", lambda h: h.write(session.w, "{}")),
             ("gate", lambda h: h.gate(session.w)))

    for status in (301, 302, 303, 307, 308):
        for name, call in calls:
            transport = fakes.Transport([fakes.Answer(status, b'{"note":"moved"}'),
                                         fakes.Answer(200, b'{"exists":true,"messages":[],"next":0}')])

            try:
                call(aamio_http.Http(transport))
                check(False, "%s on a %d took the redirect" % (name, status))
            except aamio_http.Redirected as refused:
                check(refused.status == status and len(transport.calls) == 1
                      and transport.calls[0]["url"].startswith("https://aamio.at/")
                      and transport.last.served == 0 and transport.last.closed,
                      "%s on a %d: refused, one request made, nothing read from it, closed" % (name, status))

    print("the local ceiling and the clock")
    session = _session(40)
    big = b'{"exists":true,"messages":[],"next":41,"pad":"' + b"x" * 5000 + b'"}'
    transport = fakes.Transport([fakes.Answer(200, big)])

    try:
        aamio_http.Http(transport).read(session, limit=1, max_bytes=512)
        check(False, "an answer past the ceiling was taken")
    except aamio_http.Oversize as refused:
        check(refused.status == 200 and transport.last.closed, "an answer past the ceiling is refused and closed")
        check(transport.last.served <= aamio_http.ANSWER_ROOM + 512 + aamio_http.CHUNK,
              "and read no further than the ceiling and one piece: %d bytes" % transport.last.served)

    check(session.after == 40, "and the cursor did not move")

    ceiling = aamio_http.ANSWER_ROOM + 512
    head = b'{"exists":true,"messages":[],"next":41,"pad":"'
    fits = head + b"x" * (ceiling - len(head) - 2) + b'"}'
    transport = fakes.Transport([fakes.Answer(200, fits)])
    session.take_answer(aamio_http.Http(transport).read(session, limit=1, max_bytes=512))
    check(len(fits) == ceiling and session.after == 41, "an answer exactly at the ceiling is taken")

    transport = fakes.Transport([fakes.Answer(400, b'{"error":"' + b"x" * 5000 + b'"}')])

    try:
        aamio_http.Http(transport).gate(session.w)
        check(False, "an error answer past the ceiling was taken")
    except aamio_http.Oversize:
        check(transport.last.closed, "an error answer past the ceiling is refused the same way")

    transport = fakes.Transport([fakes.Answer(400, b'{"error":"no","fix":"yes"}')])

    try:
        aamio_http.Http(transport).gate(session.w)
        check(False, "a refusal was taken as an answer")
    except aamio_http.HttpError as refused:
        check(refused.status == 400 and "fix" in refused.text
              and not isinstance(refused, aamio_http.Oversize),
              "and a refusal within it comes back as the refusal it is, fix and all")

    transport = fakes.Transport([fakes.Answer(200, pieces=[b"{", b'"exists":true,', b'"messages":[],"next":1}'],
                                              delay=0.06)])

    try:
        aamio_http.Http(transport, timeout=0.1).read(session)
        check(False, "an answer that trickles was waited for")
    except OSError:
        check(transport.last.closed, "an answer that trickles past the timeout is given up on, and closed")

    print("nothing is picked up from the runtime")

    class Board:
        pass

    board = Board()
    board.implementation = Board()
    board.implementation.name = "micropython"
    real = aamio_http.sys
    aamio_http.sys = board

    try:
        aamio_http.Http()
        check(False, "a board with no transport got one from somewhere")
    except ValueError as refused:
        check("Tls" in str(refused) and "adafruit_requests" in str(refused),
              "a board with no transport is refused, and told what to pass")
    finally:
        aamio_http.sys = real

    try:
        aamio_http.Http(fakes.Transport([]), host="http://aamio.at")
        check(False, "a plain http host was taken")
    except ValueError:
        check(True, "a plain http host is refused: the key is in a header")

    try:
        aamio_http.Http(fakes.Transport([]), timeout=0)
        check(False, "a timeout of nothing was taken")
    except ValueError:
        check(True, "and there is no timeout of never")

    print("Tls: the runtime's own socket, told to verify")
    answer = fakes.http_answer(200, '{"exists":true,"messages":[],"next":1}')
    sockets = fakes.Sockets([answer])
    tls = fakes.TlsModule()
    transport = aamio_http.Tls(b"\x30\x82DER", sockets=sockets, tls=tls)
    context = tls.contexts[0]
    check(context.protocol == tls.PROTOCOL_TLS_CLIENT and context.verify_mode == tls.CERT_REQUIRED,
          "Tls requires a certificate")
    check(context.cadata == b"\x30\x82DER", "against the CA it was given, and no other")

    session = _session(3)
    body = aamio_http.Http(transport).read(session, limit=2, max_bytes=1000)
    check(body == '{"exists":true,"messages":[],"next":1}', "and a read comes back through it")
    sock = sockets.sockets[0]
    check(sock.connected_to == ("aamio.at", 443), "connected to the service")
    check(context.wrapped[0].server_hostname == "aamio.at", "with the name the certificate is checked against")
    check(sock.timeout == aamio_http.DEFAULT_TIMEOUT, "and the timeout set on the socket")
    check(sock.written.startswith(b"GET /" + session.w.encode("utf-8") + b"/after/3 HTTP/1.0\r\nHost: aamio.at\r\n"),
          "asking HTTP/1.0 for the read path")
    check(b"\r\nX-Read: " + KEY.encode("utf-8") + b"\r\n" in sock.written
          and b"\r\nX-Limit: 2\r\n" in sock.written and b"\r\nX-Max-Bytes: 1000\r\n" in sock.written
          and sock.written.endswith(b"Connection: close\r\n\r\n"),
          "with the key, the budget, and Connection: close")
    check(sock.closed, "and the socket is closed afterwards")

    sockets = fakes.Sockets([fakes.http_answer(302, "", ["Location: http://redirect.invalid/leak"])])
    tls = fakes.TlsModule()
    http = aamio_http.Http(aamio_http.Tls(b"DER", sockets=sockets, tls=tls))

    try:
        http.read(session)
        check(False, "Tls followed a redirect")
    except aamio_http.Redirected:
        check(sockets.connections == [("aamio.at", 443)] and sockets.sockets[0].closed,
              "a 302 through Tls is refused with one connection made, to the service, and closed")

    sockets = fakes.Sockets([fakes.http_answer(200, '{"pad":"' + "x" * 6000 + '"}')])
    http = aamio_http.Http(aamio_http.Tls(b"DER", sockets=sockets, tls=fakes.TlsModule()))

    try:
        http.read(session, max_bytes=512)
        check(False, "Tls read an answer past the ceiling")
    except aamio_http.Oversize:
        check(sockets.sockets[0].closed and len(sockets.sockets[0].served) > 0,
              "an answer past the ceiling is left unread on the socket, and the socket closed")

    sockets = fakes.Sockets([b"HTTP/1.0 200 OK\r\n\r\n" + b'{"exists":true,"messages":[],"next":1}'])
    http = aamio_http.Http(aamio_http.Tls(b"DER", sockets=sockets, tls=fakes.TlsModule()))
    check(http.read(session) == '{"exists":true,"messages":[],"next":1}',
          "an answer with no Content-Length is read to the end")

    # N5 of the health check of 21 September 2026: Content-Length said 999, the
    # connection ended after 39 bytes of JSON that parsed, and the answer was
    # taken and the cursor moved.
    session = _session(40)
    sockets = fakes.Sockets([b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n" + b'{"exists":true,"messages":[],"next":41}'])
    http = aamio_http.Http(aamio_http.Tls(b"DER", sockets=sockets, tls=fakes.TlsModule()))

    try:
        session.take_answer(http.read(session))
        check(False, "an answer that ended before its Content-Length was taken")
    except OSError:
        check(session.after == 40 and sockets.sockets[0].closed,
              "an answer that ends before its Content-Length is refused, the socket closed and the cursor unmoved")

    sockets = fakes.Sockets([b"HTTP/1.1 200 OK\r\nContent-Length: -5\r\n\r\n{}"])
    http = aamio_http.Http(aamio_http.Tls(b"DER", sockets=sockets, tls=fakes.TlsModule()))

    try:
        http.read(session)
        check(False, "a Content-Length below zero was taken")
    except OSError:
        check(sockets.sockets[0].closed, "and a Content-Length below zero is refused")

    # N4 of the same check: the clock started with the body, and a peer that
    # dripped one header byte inside every socket wait held the device for as
    # long as it liked. The clock is faked, so the wait is not real.
    print("one clock from the first byte")

    class Drip(fakes.Socket):
        reads = 0

        def read(self, size):
            Drip.reads += 1
            clock[0] += 0.009

            return fakes.Socket.read(self, 1)

    class DripSockets(fakes.Sockets):
        def socket(self, family, kind, proto):
            made = Drip(self, family, kind, proto)
            made.served = self.answers.pop(0)
            self.sockets.append(made)

            return made

    clock = [0.0]
    real_clock, real_elapsed = aamio_http._clock, aamio_http._elapsed
    aamio_http._clock = lambda: clock[0]
    aamio_http._elapsed = lambda since: clock[0] - since
    sockets = DripSockets([fakes.http_answer(200, '{"exists":true,"messages":[],"next":41}')])
    session = _session(40)

    try:
        http = aamio_http.Http(aamio_http.Tls(b"DER", sockets=sockets, tls=fakes.TlsModule()), timeout=0.010)

        try:
            session.take_answer(http.read(session))
            check(False, "headers that dripped in past the timeout were waited for")
        except OSError:
            check(Drip.reads <= 4 and clock[0] < 0.05 and session.after == 40 and sockets.sockets[0].closed,
                  "headers that drip in past the timeout are given up on within it: %d reads, %.3f s, cursor unmoved, closed"
                  % (Drip.reads, clock[0]))
    finally:
        aamio_http._clock, aamio_http._elapsed = real_clock, real_elapsed

    sockets = fakes.Sockets([b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n{\"a\":\r\n0\r\n\r\n"])
    http = aamio_http.Http(aamio_http.Tls(b"DER", sockets=sockets, tls=fakes.TlsModule()))

    try:
        http.read(session)
        check(False, "a chunked answer was read")
    except OSError:
        check(sockets.sockets[0].closed, "a chunked answer is refused, since HTTP/1.0 was asked for")

    sockets = fakes.Sockets([b"HTTP/1.1 200 OK\r\n" + b"X-Long: " + b"y" * 5000 + b"\r\n\r\n{}"])
    http = aamio_http.Http(aamio_http.Tls(b"DER", sockets=sockets, tls=fakes.TlsModule()))

    try:
        http.read(session)
        check(False, "headers without end were read")
    except OSError:
        check(sockets.sockets[0].closed, "headers past their ceiling are refused")

    sockets = fakes.Sockets([b"garbage\r\n\r\n"])
    http = aamio_http.Http(aamio_http.Tls(b"DER", sockets=sockets, tls=fakes.TlsModule()))

    try:
        http.read(session)
        check(False, "something that is not HTTP was read")
    except OSError:
        check(True, "and so is an answer that is not HTTP")

    print("nothing a header may not carry")
    sockets = fakes.Sockets([])
    http = aamio_http.Http(aamio_http.Tls(b"DER", sockets=sockets, tls=fakes.TlsModule()))

    try:
        http.write(session.w, "{}", work="abc\r\nX-Read: stolen")
        check(False, "a line break in a header value was sent")
    except ValueError:
        check(sockets.connections == [], "a line break in a header value is refused before anything connects")

    try:
        http.open(session, allow="k\r\nX-Read: stolen")
        check(False, "a line break in an allowlist was sent")
    except ValueError:
        check(sockets.connections == [], "and so is one in an allowlist")

    try:
        http.write("OHCIBX4T22XC6HX22FCH", "{}")
        check(False, "an address in capitals went into a path")
    except aamio.AamioError:
        check(sockets.connections == [], "an address that is not one never reaches the path")

    try:
        http.write(session.w, "{}", key="not a key")
        check(False, "a key of no shape was sent")
    except aamio.AamioError:
        check(sockets.connections == [], "a key of no shape never reaches a header")

    try:
        aamio_http.Tls(b"")
        check(False, "Tls without a CA was made")
    except ValueError:
        check(True, "Tls without a CA is refused: there is no default")

    try:
        aamio_http.Tls(b"DER", sockets=sockets, tls=fakes.TlsModule()).get("http://aamio.at/x")
        check(False, "Tls spoke plain http")
    except ValueError:
        check(sockets.connections == [], "Tls refuses plain http before connecting")

    try:
        aamio_http.Tls(b"DER", sockets=sockets, tls=fakes.TlsModule()).get("https://aamio.at/x", allow_redirects=True)
        check(False, "Tls was told to follow redirects and agreed")
    except ValueError:
        check(True, "and refuses to be told to follow redirects")

    sockets = fakes.Sockets([fakes.http_answer(201, '{"seq":1}')])
    http = aamio_http.Http(aamio_http.Tls(b"DER", sockets=sockets, tls=fakes.TlsModule()))
    status, text = http.write(session.w, '{"t":1}')
    check(status == 201 and text == '{"seq":1}', "a write through Tls comes back with its status and text")
    check(sockets.sockets[0].written.endswith(b"Content-Length: 7\r\nConnection: close\r\n\r\n{\"t\":1}"),
          "with the body after the headers and its length before them")
