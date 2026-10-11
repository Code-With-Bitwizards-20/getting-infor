"""Vercel Serverless entrypoint for Sherlock Web UI."""
from __future__ import annotations

import sys
from pathlib import Path

# Add project root directory to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Import the Flask application instance
from web_app.app import app

# Vercel uses the 'app' WSGI callable by default
