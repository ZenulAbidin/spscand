"""A minimal SOCKS5 server for tests: username/password auth, CONNECT only.

It records every request so tests can check what the client revealed, and
can map host names (e.g. a fake .onion) to local addresses.
"""

from __future__ import annotations

import socket
import socketserver
import struct
import threading


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True


class SocksServer:
    def __init__(self, hosts: dict[str, tuple[str, int]] | None = None) -> None:
        self.hosts = hosts or {}
        self.requests: list[dict] = []
        outer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                sock = self.request
                n = sock.recv(2)[1]
                methods = sock.recv(n)
                if 2 not in methods:
                    sock.sendall(b"\x05\xff")
                    return
                sock.sendall(b"\x05\x02")
                ulen = sock.recv(2)[1]
                user = sock.recv(ulen).decode()
                password = sock.recv(sock.recv(1)[0]).decode()
                sock.sendall(b"\x01\x00")
                _, cmd, _, kind = sock.recv(4)
                if kind == 3:
                    host = sock.recv(sock.recv(1)[0]).decode()
                elif kind == 1:
                    host = socket.inet_ntoa(sock.recv(4))
                else:
                    host = socket.inet_ntop(socket.AF_INET6, sock.recv(16))
                port = struct.unpack(">H", sock.recv(2))[0]
                outer.requests.append({"kind": kind, "host": host, "port": port,
                                       "user": user, "password": password})
                try:
                    upstream = socket.create_connection(outer.hosts.get(host, (host, port)), 10)
                except OSError:
                    sock.sendall(b"\x05\x04\x00\x01" + bytes(6))
                    return
                sock.sendall(b"\x05\x00\x00\x01" + bytes(6))
                pipe = threading.Thread(target=self.copy, args=(upstream, sock), daemon=True)
                pipe.start()
                self.copy(sock, upstream)
                pipe.join(10)
                upstream.close()

            @staticmethod
            def copy(src, dst):
                try:
                    while data := src.recv(65536):
                        dst.sendall(data)
                except OSError:
                    pass
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        self.server = _Server(("127.0.0.1", 0), Handler)
        self.url = f"socks5h://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
