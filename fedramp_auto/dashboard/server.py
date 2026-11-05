"""
fedramp_auto.dashboard.server
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Serves the dashboard on the loopback interface only.

The page is rebuilt on every request, so a new scan appears on refresh.  Requests
with a foreign ``Host`` header are refused: otherwise a website using DNS
rebinding could read the scan results from the visitor's own browser.
"""

from __future__ import annotations

from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
_ALLOWED_HOSTS = ("127.0.0.1", "localhost")


def make_server(build_page: Callable[[], str], port: int = 0) -> ThreadingHTTPServer:
    """A server for the page *build_page* returns; port 0 picks a free port."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 (name set by http.server)
            host = self.headers.get("Host", "").rsplit(":", 1)[0]
            if host not in _ALLOWED_HOSTS:
                self.send_error(HTTPStatus.FORBIDDEN)
            elif self.path.split("?", 1)[0] != "/":
                self.send_error(HTTPStatus.NOT_FOUND)
            else:
                body = build_page().encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass  # keep the terminal for the CLI's own output

    return ThreadingHTTPServer((HOST, port), Handler)
