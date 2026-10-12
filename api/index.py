"""Vercel Serverless entrypoint for Sherlock Web UI."""
from __future__ import annotations

import sys
from pathlib import Path

# Add project root directory to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


class VercelPathFixer:
    """WSGI middleware to correct PATH_INFO when Vercel rewrites to /api/index."""

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        matched = environ.get("HTTP_X_MATCHED_PATH") or environ.get("REQUEST_URI") or ""
        if matched:
            clean = matched.split("?")[0]
            if clean and clean != "/api/index":
                environ["PATH_INFO"] = clean
            elif clean in ("/api/index", ""):
                environ["PATH_INFO"] = "/"
        elif environ.get("PATH_INFO") == "/api/index":
            environ["PATH_INFO"] = "/"
        return self.wsgi_app(environ, start_response)


try:
    from web_app.app import app
    app.wsgi_app = VercelPathFixer(app.wsgi_app)
except Exception:
    import traceback
    err_text = traceback.format_exc()
    from flask import Flask, Response

    app = Flask(__name__)

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def error_fallback(path):
        return Response(
            f"Vercel Serverless Function Startup Error:\n\n{err_text}",
            mimetype="text/plain",
            status=500,
        )

