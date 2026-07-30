#!/usr/bin/env python3
import os
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path("/srv/opshaven/current")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            status = int((ROOT / "status.txt").read_text(encoding="utf-8").strip())
            body = b"ok\n" if status == 200 else b"unhealthy\n"
        elif self.path == "/version":
            status = 200
            body = (ROOT / "version.txt").read_bytes()
        else:
            status = 404
            body = b"not found\n"
        self.send_response(status)
        self.send_header("content-type", "text/plain; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


def notify_ready():
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return
    if address.startswith("@"):
        address = "\0" + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notifier:
        notifier.connect(address)
        notifier.sendall(b"READY=1")


server = ThreadingHTTPServer(("127.0.0.1", 18080), Handler)
notify_ready()
server.serve_forever()
