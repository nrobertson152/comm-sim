"""Application-layer building blocks shared by several protocols: HTTP/1.1
requests and responses, WebSocket frames (RFC 6455), JSON payloads and TLS
records. Each returns a Pdu with dissection rows."""
import json
import os
from ..engine import Bld, Pdu

HTTP_REASON = {101: "Switching Protocols", 200: "OK", 201: "Created", 202: "Accepted", 204: "No Content", 301: "Moved Permanently", 304: "Not Modified",
               400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 500: "Internal Server Error", 503: "Service Unavailable"}


def _hdr_rows(b, headers):
    for k, v in headers:
        b.text(None, "%s: %s\r\n" % (k, v), {"Host": "Which site (virtual hosting)", "Content-Type": "Media type of the body", "Content-Length": "Body size in bytes",
                                             "Upgrade": "Ask to switch protocols (WebSocket)", "Connection": "Upgrade / keep-alive / close",
                                             "Sec-WebSocket-Key": "Random nonce; the server proves it understood WebSocket by hashing it",
                                             "Sec-WebSocket-Accept": "base64(SHA-1(key + 258EAFA5-E914-47DA-95CA-C5AB0DC85B11))",
                                             "Authorization": "Credentials (token)", "User-Agent": "Client software", "Accept": "Media types the client wants",
                                             "Cache-Control": "Caching rules", "Server": "Server software", "Date": "Response time"}.get(k, ""))


def http_req(method, path, headers, body=b"", title=None):
    b = Bld(title or "Hypertext Transfer Protocol (request)", "HTTP/1.1, RFC 9112: text request line, headers, empty line, optional body")
    b.text("Request line", "%s %s HTTP/1.1\r\n" % (method, path), "Method + target + version")
    hs = list(headers)
    if body:
        hs.append(("Content-Length", str(len(body))))
    _hdr_rows(b, hs)
    b.text(None, "\r\n", "Empty line ends the header section")
    if body:
        b.raw("Body", body, body.decode("utf-8", "replace")[:200], "Message body")
    return b.done()


def http_rsp(code, headers, body=b"", title=None):
    b = Bld(title or "Hypertext Transfer Protocol (response)", "HTTP/1.1 status line, headers, body")
    b.text("Status line", "HTTP/1.1 %d %s\r\n" % (code, HTTP_REASON.get(code, "")), "Version + status code + reason. 2xx success, 3xx redirect, 4xx client error, 5xx server error")
    hs = list(headers)
    if body and code != 101:
        hs.append(("Content-Length", str(len(body))))
    _hdr_rows(b, hs)
    b.text(None, "\r\n", "Empty line")
    if body:
        b.raw("Body", body, body.decode("utf-8", "replace")[:200], "")
    return b.done()


WS_OP = {0: "continuation", 1: "text", 2: "binary", 8: "close", 9: "ping", 10: "pong"}


def ws_frame(payload, opcode=1, masked=False, key=b"\x37\xfa\x21\x3d", title=None, desc=""):
    """One WebSocket frame. Client-to-server frames must be masked."""
    data = payload.encode() if isinstance(payload, str) else bytes(payload)
    b = Bld(title or "WebSocket frame (%s)" % WS_OP.get(opcode, "?"), "RFC 6455: 2-14 byte header + payload. " + desc)
    n = len(data)
    b.u8("FIN | RSV | opcode", 0x80 | opcode, "FIN 1, opcode %d (%s)" % (opcode, WS_OP.get(opcode, "")), "FIN = last fragment of the message")
    if n < 126:
        b.u8("MASK | payload length", (0x80 if masked else 0) | n, "MASK %d, length %d" % (masked, n), "Lengths 126 / 127 mean a 16- / 64-bit length follows")
    elif n < 65536:
        b.u8("MASK | payload length", (0x80 if masked else 0) | 126, "MASK %d, length 126 -> 16-bit length" % masked, "")
        b.u16("Extended payload length", n, None, "")
    else:
        b.u8("MASK | payload length", (0x80 if masked else 0) | 127, "MASK %d, 64-bit length" % masked, "")
        b.raw("Extended payload length", n.to_bytes(8, "big"), str(n), "")
    if masked:
        b.raw("Masking key", key, key.hex(), "Client frames are XOR-masked with this key (protects broken proxies, not secrecy)")
        md = bytes(c ^ key[i % 4] for i, c in enumerate(data))
        b.raw("Payload (masked)", md, None, "On the wire it is unreadable until unmasked")
        b.note("Unmasked: %s" % data.decode("utf-8", "replace")[:300], "", d=2)
    else:
        b.raw("Payload", data, data.decode("utf-8", "replace")[:300] if opcode == 1 else None, "")
    return b.done()


def jdump(obj):
    return json.dumps(obj, separators=(",", ":"))


def tls_record(ctype, body, desc="", title=None):
    """TLS 1.2/1.3 record. body: bytes (handshake) or int (length of encrypted data)."""
    names = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "Application data"}
    data = os.urandom(body) if isinstance(body, int) else bytes(body)
    b = Bld(title or "Transport Layer Security: %s" % names.get(ctype, ""), "Record layer: type, legacy version 0x0303, length, fragment. " + desc)
    b.u8("Content type", ctype, "%d (%s)" % (ctype, names.get(ctype, "")), "")
    b.u16("Legacy version", 0x0303, "0x0303 (TLS 1.2 on the wire; TLS 1.3 negotiates in extensions)", "")
    b.u16("Length", len(data), None, "")
    b.raw("Encrypted data" if isinstance(body, int) else "Fragment", data, None, "Ciphertext + 16-byte AEAD tag" if isinstance(body, int) else "")
    return b.done()


def tls_hs(kind, extra_rows=(), size=None):
    """Simplified handshake message inside a record (ClientHello, ServerHello...)."""
    hs = {1: "ClientHello", 2: "ServerHello", 11: "Certificate", 15: "CertificateVerify", 20: "Finished", 8: "EncryptedExtensions"}
    n = size or {1: 240, 2: 122, 11: 800, 15: 264, 20: 52, 8: 30}.get(kind, 60)
    body = bytes([kind]) + (n - 4).to_bytes(3, "big") + os.urandom(n - 4)
    p = tls_record(22, body, title="TLS Handshake: %s" % hs.get(kind, kind))
    for txt, desc in extra_rows:
        p.rows.append([1, txt, None, 0, desc])
    return p
