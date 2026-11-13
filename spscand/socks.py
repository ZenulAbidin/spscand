"""HTTP(S) over a SOCKS5 proxy such as Tor, without local DNS lookups."""

from __future__ import annotations

import http.client
import secrets
import socket
import struct
import urllib.request
from urllib.parse import unquote, urlsplit


class SocksError(OSError):
    pass


def parse_proxy(url: str) -> tuple[str, int, str, str]:
    """socks5h://[user:password@]host:port -> (host, port, user, password).

    Without credentials a random pair is chosen. Tor isolates streams by SOCKS
    credentials (IsolateSOCKSAuth, on by default), so spscand then shares no
    circuit with other programs using the same Tor.
    """
    parts = urlsplit(url)
    if parts.scheme != "socks5h" or not parts.hostname or not parts.port:
        raise ValueError(f"proxy must look like socks5h://127.0.0.1:9050, not {url!r}")
    user = unquote(parts.username or "") or "spscand-" + secrets.token_hex(8)
    password = unquote(parts.password or "") or secrets.token_hex(8)
    return parts.hostname, parts.port, user, password


def _recv(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise SocksError("SOCKS proxy closed the connection")
        data += chunk
    return data


def connect(proxy: tuple[str, int, str, str], host: str, port: int,
            timeout: float | None) -> socket.socket:
    proxy_host, proxy_port, user, password = proxy
    sock = socket.create_connection((proxy_host, proxy_port), timeout)
    try:
        sock.sendall(b"\x05\x01\x02")  # username/password auth only
        if _recv(sock, 2) != b"\x05\x02":
            raise SocksError("SOCKS proxy refused username/password authentication")
        u, p = user.encode(), password.encode()
        sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        if _recv(sock, 2)[1] != 0:
            raise SocksError("SOCKS proxy rejected the credentials")
        # Always send the host name (address type 3) so the proxy resolves it.
        name = host.encode("idna")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack(">H", port))
        version, status, _, kind = _recv(sock, 4)
        if version != 5 or status != 0:
            raise SocksError(f"SOCKS proxy could not connect to {host}:{port} (error {status})")
        _recv(sock, {1: 4, 4: 16}.get(kind) or _recv(sock, 1)[0])
        _recv(sock, 2)
        return sock
    except BaseException:
        sock.close()
        raise


def socks_opener(url: str) -> urllib.request.OpenerDirector:
    """A urllib opener that sends every request through the proxy.

    Proxy environment variables are ignored: they would route around it.
    """
    proxy = parse_proxy(url)

    class HTTPConnection(http.client.HTTPConnection):
        def connect(self):
            self.sock = connect(proxy, self.host, self.port, self.timeout)

    class HTTPSConnection(http.client.HTTPSConnection):
        def connect(self):
            sock = connect(proxy, self.host, self.port, self.timeout)
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)

    class HTTPHandler(urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(HTTPConnection, req)

    class HTTPSHandler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(HTTPSConnection, req)

    return urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                       HTTPHandler, HTTPSHandler)
