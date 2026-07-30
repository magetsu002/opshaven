#!/usr/bin/env python3
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


ThreadingHTTPServer(("127.0.0.1", 18080), Handler).serve_forever()
