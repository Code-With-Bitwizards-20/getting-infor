"""Vercel Serverless entrypoint for Sherlock Web UI."""
from __future__ import annotations

import sys
from pathlib import Path

# Add project root directory to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


from urllib.parse import parse_qs


class VercelPathFixer:
    """WSGI middleware to correct PATH_INFO when Vercel rewrites to /api/index."""

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        query_string = environ.get("QUERY_STRING", "")
        if "__path__=" in query_string:
            params = parse_qs(query_string)
            if "__path__" in params and params["__path__"]:
                environ["PATH_INFO"] = params["__path__"][0]
        elif environ.get("HTTP_X_FORWARDED_URI"):
            clean = environ["HTTP_X_FORWARDED_URI"].split("?")[0]
            if clean and clean != "/api/index":
                environ["PATH_INFO"] = clean
        elif environ.get("REQUEST_URI"):
            clean = environ["REQUEST_URI"].split("?")[0]
            if clean and clean != "/api/index":
                environ["PATH_INFO"] = clean
        elif environ.get("PATH_INFO") == "/api/index":
            environ["PATH_INFO"] = "/"
        return self.wsgi_app(environ, start_response)


# Import the Flask application instance directly at top-level for Vercel detection
from web_app.app import app

# Apply WSGI middleware to handle path rewriting
app.wsgi_app = VercelPathFixer(app.wsgi_app)

