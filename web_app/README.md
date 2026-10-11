# Sherlock Web UI

A local, browser-based interface for the Sherlock username search engine. It
uses the repository's bundled site catalogue and streams structured results
from the real Sherlock engine—no external web service or API key is required.

## Start it

From the repository root:

```powershell
python -m pip install -e . flask
python web_app/app.py
```

Then open <http://127.0.0.1:5000>.

The page supports multiple usernames, live progress, cancellation, filtering,
optional proxy and NSFW settings, and CSV export. Searches make outbound
requests to the public sites in Sherlock's catalogue; only investigate
usernames you are permitted to research and respect each site's terms.

## Architecture

- `app.py` serves the UI and manages short-lived Server-Sent Events sessions.
- `worker.py` adapts Sherlock's native callback API to newline-delimited JSON.
- `static/` contains the dependency-free frontend.

Searches run in a child process so cancelling from the browser stops network
activity promptly without modifying Sherlock's CLI or core engine.
