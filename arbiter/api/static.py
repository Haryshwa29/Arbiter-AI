"""Serve only bundled dashboard resources, including from a zipapp."""

from importlib.resources import files
from urllib.parse import unquote


CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
}

# React and charts use inline styles, but scripts must be local files.
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
       "object-src 'none'; base-uri 'none'; frame-ancestors 'none'")


def dashboard_resource(path, root=None):
    """Return (bytes, content-type), or None. Never read outside the bundle."""
    root = root if root is not None else files("arbiter").joinpath("static")
    path = unquote(path)
    parts = path.lstrip("/").split("/")
    if "\\" in path or ":" in path or "\x00" in path:
        return None
    if any(part.startswith(".") for part in parts if part):
        return None
    # Explicit client routes only: unknown files must not become index.html.
    routes = {"", "login", "overview", "live", "audit", "assets"}
    if path.strip("/") in routes:
        parts = ["index.html"]
    resource = root.joinpath(*parts)
    suffix = "." + parts[-1].rsplit(".", 1)[-1]
    if suffix not in CONTENT_TYPES:
        return None
    try:
        if resource.is_file():
            return resource.read_bytes(), CONTENT_TYPES[suffix]
    except (OSError, ValueError):
        pass
    return None
