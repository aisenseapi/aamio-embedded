"""Take the numbers in the README again, from the live service.

Nothing here is a test: it opens a short thread on aamio.at, writes two messages, reads it
three ways and closes it. Run it when a number in the README needs checking.
"""

import base64
import hashlib
import json
import secrets
import string
import urllib.error
import urllib.request

HOST = "https://aamio.at"


def call(method, url, body=None, headers=None):
    request = urllib.request.Request(url, data=body, method=method)

    for key, value in (headers or {}).items():
        request.add_header(key, value)

    try:
        with urllib.request.urlopen(request, timeout=25) as answer:
            return answer.status, answer.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


descriptor = json.loads(call("GET", "%s/.well-known/aamio.json" % HOST)[1])
print("service   :", descriptor["version"])
print("read-limits declared:", "read-limits" in descriptor["protocol"]["capabilities"])
print()

alphabet = string.ascii_lowercase + string.digits
read_key = "".join(secrets.choice(alphabet) for _ in range(26))
w = base64.b32encode(hashlib.sha256(read_key.encode()).digest()).decode().lower()[:20]
call("PUT", "%s/%s" % (HOST, w), b"", {"X-Read": read_key, "X-TTL": "120"})

call("POST", "%s/%s" % (HOST, w), json.dumps({"t": 21.4, "h": 48}).encode(), {"Content-Type": "application/json"})
call("POST", "%s/%s" % (HOST, w), b"x" * 20000, {"Content-Type": "text/plain"})

for label, headers in (
    ("no limit, as it always was", {"X-Read": read_key}),
    ("X-Limit: 1", {"X-Read": read_key, "X-Limit": "1"}),
    ("X-Max-Bytes: 2000 from seq 1", {"X-Read": read_key, "X-Max-Bytes": "2000"}),
):
    status, body = call("GET", "%s/%s%s" % (HOST, w, "/after/1" if "from seq 1" in label else ""), None, headers)
    answer = json.loads(body)
    print("  %-30s %6d byte on the wire, %d message(s)%s" % (
        label, len(body), len(answer.get("messages", [])),
        "   more" if answer.get("more") else ""))

    if answer.get("too_large"):
        print("      too_large: seq %s, %s bytes" % (answer["too_large"]["seq"], answer["too_large"]["bytes"]))

status, body = call("GET", "%s/%s" % (HOST, w), None, {"X-Read": read_key, "X-Limit": "nonsense"})
print()
print("  a limit this service cannot use -> %s %s" % (status, json.loads(body).get("field")))

tools = json.loads(call("POST", "%s/mcp" % HOST,
                        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode(),
                        {"Content-Type": "application/json"})[1])["result"]["tools"]
read_tool = next(t for t in tools if t["name"] == "aamio_read")
print("  hosted aamio_read takes        :", sorted(read_tool["inputSchema"]["properties"]))

small = json.loads(call("POST", "%s/mcp" % HOST,
                        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                    "params": {"name": "aamio_read",
                                               "arguments": {"w": w, "id": read_key, "limit": 1}}}).encode(),
                        {"Content-Type": "application/json"})[1])
text = small["result"]["content"][0]["text"]
print("  a model asking for one message : %d characters into its context" % len(text))

call("DELETE", "%s/%s" % (HOST, w), None, {"X-Read": read_key})
