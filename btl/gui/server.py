"""The HTTP server that serves the graphical interface.

The server is built on :mod:`http.server` from the standard library, so
the graphical interface needs no dependency beyond the ones the core
project already uses.  That matters for the assignment: the interface can
be started on a bare Ubuntu installation without installing a web stack.

Only the loopback interface is bound by default, because the interface
accepts a password and can run commands on a server.  Binding it to
another address has to be asked for explicitly.
"""

from __future__ import annotations

import json
import mimetypes
import os
import posixpath
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from ..utils.logging import get_logger
from .api import Api, error_response
from .service import Service

logger = get_logger("gui.server")

#: Where the static files of the interface live.
WEB_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

#: The content types of the interface files.
#:
#: The standard library cannot always work the type of a file out: on
#: Windows the registry that :mod:`mimetypes` consults does not map
#: ``.js`` to ``text/javascript``, and the browser then refuses to run the
#: script because it was served as plain text.  The types of the three
#: files that make up the interface are therefore given explicitly.
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".png": "image/png",
}

#: The largest request body that is accepted.
MAX_BODY_BYTES = 64 * 1024 * 1024


def content_type_for(path: str) -> str:
    """Return the content type of *path*.

    Args:
        path: The path of the file.

    Returns:
        The content type, defaulting to ``application/octet-stream``.
    """
    extension = os.path.splitext(path)[1].lower()
    if extension in CONTENT_TYPES:
        return CONTENT_TYPES[extension]

    guessed, _ = mimetypes.guess_type(path)
    return guessed or "application/octet-stream"


class GuiHandler(BaseHTTPRequestHandler):
    """Serves the interface and dispatches the JSON requests.

    The handler is created by :func:`make_handler`, which passes the
    application service in through the class attributes.
    """

    server_version = "BTL/1.0"
    protocol_version = "HTTP/1.1"

    #: The application service, set by :func:`make_handler`.
    service: Service = None  # type: ignore[assignment]
    #: The JSON API, set by :func:`make_handler`.
    api: Api = None  # type: ignore[assignment]

    # -- logging ---------------------------------------------------------

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Send the access log to the project logger instead of stderr."""
        logger.debug("%s - %s", self.address_string(), format % args)

    # -- helpers ---------------------------------------------------------

    def _send_json(self, payload: "Dict[str, Any]", status: int = 200) -> None:
        """Send a JSON response."""
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(
        self, body: bytes, content_type: str, status: int = 200, filename: str = ""
    ) -> None:
        """Send a binary response, optionally as an attachment."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        if filename:
            self.send_header(
                "Content-Disposition", f'attachment; filename="{filename}"'
            )
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> "Dict[str, Any]":
        """Read and decode the JSON request body.

        Returns:
            The decoded body, or an empty dictionary when there is none.

        Raises:
            ValueError: If the body is not valid JSON.
        """
        length = _as_int(self.headers.get("Content-Length"), 0)
        if length <= 0:
            return {}
        if length > MAX_BODY_BYTES:
            raise ValueError("the request body is too large")

        raw = self.rfile.read(length)
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"the request body is not valid JSON: {exc}") from exc

        if not isinstance(decoded, dict):
            raise ValueError("the request body must be a JSON object")
        return decoded

    # -- routing ---------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - required by the base class
        """Handle a GET request."""
        path = urlparse(self.path).path

        if path in ("/", "/index.html"):
            self._serve_file("index.html")
            return

        if path == "/api/state":
            try:
                self._send_json({"ok": True, "result": self.api.dispatch("state", {})})
            except Exception as exc:  # noqa: BLE001 - the browser needs an answer
                self._send_json(error_response(exc))
            return

        if path.startswith("/static/"):
            self._serve_file(path[len("/static/"):])
            return

        self._send_bytes(b"not found", "text/plain; charset=utf-8", status=404)

    def do_POST(self) -> None:  # noqa: N802 - required by the base class
        """Handle a POST request."""
        path = urlparse(self.path).path

        if not path.startswith("/api/"):
            self._send_bytes(b"not found", "text/plain; charset=utf-8", status=404)
            return

        action = path[len("/api/"):].strip("/")

        try:
            payload = self._read_body()
        except ValueError as exc:
            self._send_json({"ok": False, "error": str(exc)}, status=400)
            return

        try:
            result = self.api.dispatch(action, payload)
        except Exception as exc:  # noqa: BLE001 - the browser needs an answer
            self._send_json(error_response(exc))
            return

        self._send_json({"ok": True, "result": result})

    def do_OPTIONS(self) -> None:  # noqa: N802 - required by the base class
        """Answer a preflight request."""
        self.send_response(204)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    # -- static files ----------------------------------------------------

    def _serve_file(self, relative: str) -> None:
        """Serve a file from the web root.

        The path is resolved and checked against the web root, so that a
        request for ``/static/../../etc/passwd`` cannot escape the
        directory.
        """
        root = os.path.realpath(WEB_ROOT)
        candidate = os.path.realpath(os.path.join(root, relative.lstrip("/")))

        if candidate != root and not candidate.startswith(root + os.sep):
            self._send_bytes(b"forbidden", "text/plain; charset=utf-8", status=403)
            return

        if not os.path.isfile(candidate):
            self._send_bytes(b"not found", "text/plain; charset=utf-8", status=404)
            return

        content_type = content_type_for(candidate)
        with open(candidate, "rb") as handle:
            body = handle.read()

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        # The interface is a single page application that is edited while
        # it is running, so the static files must never be cached.  A stale
        # script would keep using an API that no longer exists.
        self.send_header("Cache-Control", "no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.end_headers()
        self.wfile.write(body)


def _as_int(value: Any, default: int = 0) -> int:
    """Interpret a header value as an integer."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def make_handler(service: Service) -> type:
    """Build a request handler class bound to *service*.

    Args:
        service: The application service.

    Returns:
        A handler class that can be given to a server.
    """
    api = Api(service)
    app_service = service
    app_api = api

    class BoundHandler(GuiHandler):
        service = app_service
        api = app_api

    return BoundHandler


class GuiServer:
    """The interface server.

    Args:
        host: The address to bind to.
        port: The port to listen on.
        service: The application service.  A new one is created when it is
            not given.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8765,
        service: Optional[Service] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.service = service or Service()
        self._server: Optional[ThreadingHTTPServer] = None

    @property
    def url(self) -> str:
        """The address the interface is reachable at."""
        return f"http://{self.host}:{self.port}/"

    def start(self) -> "GuiServer":
        """Start serving in a background thread.

        Returns:
            ``self``, so the call can be chained.
        """
        handler = make_handler(self.service)

        class Server(ThreadingHTTPServer):
            daemon_threads = True
            allow_reuse_address = True

        self._server = Server((self.host, self.port), handler)
        thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        thread.start()
        logger.info("the interface is available at %s", self.url)
        return self

    def serve_forever(self) -> None:
        """Serve in the foreground until the process is interrupted."""
        handler = make_handler(self.service)

        class Server(ThreadingHTTPServer):
            daemon_threads = True
            allow_reuse_address = True

        self._server = Server((self.host, self.port), handler)
        logger.info("the interface is available at %s", self.url)
        try:
            self._server.serve_forever()
        except KeyboardInterrupt:
            logger.info("stopping the interface")
        finally:
            self.stop()

    def stop(self) -> None:
        """Stop the server."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def port_in_use(self) -> bool:
        """Return whether the configured port is already taken."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.5)
            return probe.connect_ex((self.host, self.port)) == 0


__all__ = ["GuiHandler", "GuiServer", "MAX_BODY_BYTES", "WEB_ROOT", "make_handler"]
