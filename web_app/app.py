"""Local web interface for Sherlock with ExifTool & Deep OSINT Intelligence.

Runs upstream Sherlock in an isolated subprocess, pairs claimed profiles with
concurrent ExifTool image forensics (avatar + top 5 photos per profile),
runs GitHub and Gravatar deep OSINT investigations, and generates downloadable
PDF dossiers with clickable profile and geolocation hyperlinks.
"""

from __future__ import annotations

import json
import logging
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import warnings

# Suppress unverified HTTPS warnings from scraping diverse third-party target sites
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass
warnings.filterwarnings("ignore", category=UserWarning, module="urllib3")

# Ensure project root is in sys.path regardless of execution method
WEB_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = WEB_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from flask import Flask, Response, jsonify, request, send_file, send_from_directory

try:
    from web_app.osint_engine import (
        EXIFTOOL_PATH,
        OSINTImageHarvester,
        calculate_footprint_risk,
        correlate_avatars,
        harvest_contacts_from_text,
        run_github_osint,
        run_gravatar_osint,
        run_keybase_osint,
        run_snapintel_osint,
        run_holehe_email_osint,
        run_instagram_osint,
        run_phoneinfoga_osint,
        run_email_breach_osint,
        generate_google_dorks,
        build_osint_mapping_graph,
        OSINT_FRAMEWORK_DATA,
    )
    from web_app.pdf_generator import build_pdf_report
except ImportError:
    from osint_engine import (  # type: ignore
        EXIFTOOL_PATH,
        OSINTImageHarvester,
        calculate_footprint_risk,
        correlate_avatars,
        harvest_contacts_from_text,
        run_github_osint,
        run_gravatar_osint,
        run_keybase_osint,
        run_snapintel_osint,
        run_holehe_email_osint,
        run_instagram_osint,
        run_phoneinfoga_osint,
        run_email_breach_osint,
        generate_google_dorks,
        build_osint_mapping_graph,
        OSINT_FRAMEWORK_DATA,
    )
    from pdf_generator import build_pdf_report  # type: ignore

logger = logging.getLogger(__name__)

STATIC_ROOT = WEB_ROOT / "static"
WORKER_PATH = WEB_ROOT / "worker.py"
DATA_PATH = PROJECT_ROOT / "sherlock_project" / "resources" / "data.json"
MAX_USERNAMES = 8
MAX_USERNAME_LENGTH = 100
SESSION_TTL_SECONDS = 30 * 60  # Retain sessions for 30 minutes for report downloading

app = Flask(__name__, static_folder=str(STATIC_ROOT), static_url_path="")
search_sessions: dict[str, dict] = {}
sessions_lock = threading.Lock()


def _event_stream(event: dict) -> str:
    return f"data: {json.dumps(event, ensure_ascii=False)}\n\n"


def _cleanup_sessions() -> None:
    """Remove completed sessions older than SESSION_TTL_SECONDS and clean up their temp files."""
    cutoff = time.monotonic() - SESSION_TTL_SECONDS
    with sessions_lock:
        expired = [
            session_id
            for session_id, session in search_sessions.items()
            if not session["running"] and session["created_at"] < cutoff
        ]
        for session_id in expired:
            sess = search_sessions.pop(session_id, None)
            if sess and "harvester_dir" in sess:
                try:
                    shutil.rmtree(sess["harvester_dir"], ignore_errors=True)
                except Exception:
                    pass


def _parse_usernames(raw_value: object) -> list[str]:
    if not isinstance(raw_value, str):
        return []
    usernames = [item.strip() for item in re.split(r"[\s,]+", raw_value) if item.strip()]
    return list(dict.fromkeys(usernames))


def _valid_proxy(proxy: str) -> bool:
    if not proxy:
        return True
    parsed = urlparse(proxy)
    return parsed.scheme in {"http", "https", "socks4", "socks5"} and bool(parsed.netloc)


def _run_worker(session_id: str, usernames: list[str], options: dict) -> None:
    with sessions_lock:
        session = search_sessions.get(session_id)
    if session is None:
        return

    event_queue: queue.Queue = session["queue"]
    harvester = OSINTImageHarvester(Path(session["harvester_dir"]))
    osint_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="OSINTWorker")
    pending_tasks = []

    # Launch deep OSINT on GitHub & Gravatar for target usernames
    def _fetch_deep_identity(u: str):
        try:
            gh = run_github_osint(u)
            if gh:
                with sessions_lock:
                    session["github_data"] = gh
                event_queue.put({"type": "osint_github", "username": u, "data": gh})
        except Exception as e:
            logger.debug(f"Deep GitHub fetch error: {e}")

        try:
            grav = run_gravatar_osint(u)
            if grav:
                with sessions_lock:
                    session["gravatar_data"] = grav
                event_queue.put({"type": "osint_gravatar", "username": u, "data": grav})
        except Exception as e:
            logger.debug(f"Deep Gravatar fetch error: {e}")

        try:
            kb = run_keybase_osint(u)
            if kb:
                with sessions_lock:
                    session["keybase_data"] = kb
                event_queue.put({"type": "osint_keybase", "username": u, "data": kb})
        except Exception as e:
            logger.debug(f"Deep Keybase fetch error: {e}")

        try:
            snap = run_snapintel_osint(u)
            if snap:
                with sessions_lock:
                    session["snapchat_data"] = snap
                event_queue.put({"type": "osint_snapchat", "username": u, "data": snap})
        except Exception as e:
            logger.debug(f"Deep Snapchat fetch error: {e}")

        try:
            ig = run_instagram_osint(u)
            if ig:
                with sessions_lock:
                    session["instagram_data"] = ig
                event_queue.put({"type": "osint_instagram", "username": u, "data": ig})
        except Exception as e:
            logger.debug(f"Deep Instagram fetch error: {e}")

        try:
            dorks = generate_google_dorks(u)
            if dorks:
                with sessions_lock:
                    session["dorks_data"] = dorks
                event_queue.put({"type": "osint_dorks", "username": u, "data": dorks})
        except Exception as e:
            logger.debug(f"Google Dorks generator error: {e}")

        try:
            candidate_emails = []
            with sessions_lock:
                gh_d = session.get("github_data")
                if gh_d and gh_d.get("email"):
                    candidate_emails.append(gh_d["email"])
                if gh_d and gh_d.get("commit_emails_discovered"):
                    candidate_emails.extend(gh_d["commit_emails_discovered"])
                candidate_emails.extend(session.get("contacts", {}).get("emails", []))

            if not candidate_emails and "@" not in u:
                candidate_emails.append(f"{u}@gmail.com")

            seen_emails = set()
            for em in candidate_emails[:2]:
                if em and em not in seen_emails:
                    seen_emails.add(em)
                    try:
                        breach = run_email_breach_osint(em)
                        if breach:
                            with sessions_lock:
                                session["breach_data"] = breach
                            event_queue.put({"type": "osint_breach", "email": em, "data": breach})
                    except Exception:
                        pass

                    holehe_matches = run_holehe_email_osint(em, max_checks=25)
                    if holehe_matches:
                        with sessions_lock:
                            session["holehe_data"].extend(holehe_matches)
                        event_queue.put({"type": "osint_holehe", "email": em, "data": holehe_matches})
        except Exception as e:
            logger.debug(f"Deep Holehe fetch error: {e}")

    for target_u in usernames:
        if options.get("deep_osint", True):
            osint_pool.submit(_fetch_deep_identity, target_u)

    def _process_claimed_profile(site_name: str, profile_url: str, username: str):
        if not options.get("scan_exif", True):
            return
        try:
            images_meta = harvester.scan_claimed_profile(
                site_name, profile_url, username, max_additional=options.get("max_images_per_site", 5)
            )
            if images_meta:
                with sessions_lock:
                    session["exif_results"].extend(images_meta)
                    # Harvest any emails or contact info
                    for img in images_meta:
                        raw_desc = img.get("raw_metadata", {}).get("Description", "") or ""
                        if raw_desc:
                            harvested = harvest_contacts_from_text(raw_desc)
                            session["contacts"]["emails"].extend(harvested["emails"])
                            session["contacts"]["phones"].extend(harvested["phones"])

                    # Check PhoneInfoga on any discovered phone
                    phones = session.get("contacts", {}).get("phones", [])
                    if phones and not session.get("phone_data"):
                        p_info = run_phoneinfoga_osint(phones[0])
                        if p_info:
                            session["phone_data"] = p_info
                            event_queue.put({"type": "osint_phone", "data": p_info})

                    # Check socid extracted
                    if harvester.extracted_socids:
                        session["socid_data"].update(harvester.extracted_socids)
                        event_queue.put({"type": "osint_socid", "data": session["socid_data"]})

                    # Recalculate threat exposure
                    session["risk_assessment"] = calculate_footprint_risk(
                        claimed_sites_count=len([r for r in session["sherlock_results"] if r.get("status") == "claimed"]),
                        exif_results=session["exif_results"],
                        github_data=session.get("github_data"),
                        gravatar_data=session.get("gravatar_data"),
                        contacts=session["contacts"],
                    )

                event_queue.put({
                    "type": "exif_result",
                    "site": site_name,
                    "username": username,
                    "images": images_meta,
                    "total_images_scanned": len(session["exif_results"]),
                    "risk_assessment": session["risk_assessment"],
                })
        except Exception as exc:
            logger.debug(f"ExifTool profile scan error for {site_name}: {exc}")

    command = [
        sys.executable,
        str(WORKER_PATH),
        "--timeout",
        str(options["timeout"]),
    ]
    if options["nsfw"]:
        command.append("--nsfw")
    if options["proxy"]:
        command.extend(["--proxy", options["proxy"]])
    command.extend(["--", *usernames])

    worker_emitted_terminal = False
    try:
        process = subprocess.Popen(
            command,
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        session["process"] = process

        assert process.stdout is not None
        for line in process.stdout:
            if session["cancelled"]:
                break
            try:
                event = json.loads(line)
                ev_type = event.get("type")

                if ev_type == "result":
                    with sessions_lock:
                        session["sherlock_results"].append(event)
                    # Trigger ExifTool scan for claimed profile
                    if event.get("status") == "claimed":
                        t = osint_pool.submit(
                            _process_claimed_profile,
                            event.get("site", ""),
                            event.get("url", ""),
                            event.get("username", ""),
                        )
                        pending_tasks.append(t)

                if ev_type in {"complete", "error"}:
                    worker_emitted_terminal = True
                event_queue.put(event)
            except json.JSONDecodeError:
                event_queue.put({"type": "log", "level": "info", "message": line.strip()})

        if session["cancelled"]:
            osint_pool.shutdown(wait=False, cancel_futures=True)
            event_queue.put({"type": "cancelled", "message": "Search cancelled"})
            return

        process.wait()

        # Allow pending ExifTool / OSINT scans to wrap up gracefully
        for t in pending_tasks:
            try:
                t.result(timeout=10)
            except Exception:
                pass
        osint_pool.shutdown(wait=True)

        # Final risk assessment
        with sessions_lock:
            session["risk_assessment"] = calculate_footprint_risk(
                claimed_sites_count=len([r for r in session["sherlock_results"] if r.get("status") == "claimed"]),
                exif_results=session["exif_results"],
                github_data=session.get("github_data"),
                gravatar_data=session.get("gravatar_data"),
                contacts=session["contacts"],
            )
            correlations = correlate_avatars(session["exif_results"])

        event_queue.put({
            "type": "osint_complete",
            "total_exif_images": len(session["exif_results"]),
            "correlations": correlations,
            "risk_assessment": session["risk_assessment"],
        })

    except Exception as exc:
        event_queue.put({"type": "error", "message": str(exc)})
    finally:
        session["running"] = False


@app.get("/")
def index():
    return send_from_directory(STATIC_ROOT, "index.html")


@app.get("/favicon.ico")
def favicon():
    return send_from_directory(STATIC_ROOT, "favicon.svg", mimetype="image/svg+xml")


@app.get("/api/exiftool-status")
def exiftool_status():
    """Verify ExifTool status and capabilities."""
    version = None
    if EXIFTOOL_PATH and Path(EXIFTOOL_PATH).is_file():
        try:
            res = subprocess.run([EXIFTOOL_PATH, "-ver"], capture_output=True, text=True, timeout=5)
            version = res.stdout.strip()
        except Exception:
            pass
    return jsonify({
        "available": bool(version),
        "path": EXIFTOOL_PATH,
        "version": version or "Not Found",
    })


@app.post("/api/search")
def start_search():
    _cleanup_sessions()
    payload = request.get_json(silent=True) or {}
    usernames = _parse_usernames(payload.get("usernames", ""))
    if not usernames:
        return jsonify(error="Enter at least one username."), 400
    if len(usernames) > MAX_USERNAMES:
        return jsonify(error=f"Search up to {MAX_USERNAMES} usernames at a time."), 400
    if any(len(username) > MAX_USERNAME_LENGTH for username in usernames):
        return jsonify(error=f"Usernames must be {MAX_USERNAME_LENGTH} characters or fewer."), 400

    try:
        timeout = int(payload.get("timeout", 20))
    except (TypeError, ValueError):
        return jsonify(error="Timeout must be a whole number."), 400
    if timeout < 2 or timeout > 120:
        return jsonify(error="Timeout must be between 2 and 120 seconds."), 400

    proxy = str(payload.get("proxy", "")).strip()
    if not _valid_proxy(proxy):
        return jsonify(error="Use a valid HTTP, HTTPS, SOCKS4, or SOCKS5 proxy URL."), 400

    options = {
        "timeout": timeout,
        "nsfw": bool(payload.get("nsfw", False)),
        "proxy": proxy,
        "scan_exif": bool(payload.get("scan_exif", True)),
        "deep_osint": bool(payload.get("deep_osint", True)),
        "max_images_per_site": int(payload.get("max_images_per_site", 5)),
    }

    session_id = uuid.uuid4().hex
    harvester_dir = Path(tempfile.gettempdir()) / f"sherlock_exif_{session_id}"
    harvester_dir.mkdir(parents=True, exist_ok=True)

    session = {
        "queue": queue.Queue(),
        "process": None,
        "running": True,
        "cancelled": False,
        "terminal_event": False,
        "created_at": time.monotonic(),
        "usernames": usernames,
        "options": options,
        "sherlock_results": [],
        "exif_results": [],
        "github_data": None,
        "gravatar_data": None,
        "keybase_data": None,
        "snapchat_data": None,
        "instagram_data": None,
        "phone_data": None,
        "breach_data": None,
        "dorks_data": [],
        "socid_data": {},
        "holehe_data": [],
        "contacts": {"emails": [], "phones": []},
        "risk_assessment": {"score": 0, "level": "LOW EXPOSURE", "color": "#22c55e", "summary": "Scan in progress"},
        "harvester_dir": str(harvester_dir),
    }

    with sessions_lock:
        search_sessions[session_id] = session

    threading.Thread(
        target=_run_worker,
        args=(session_id, usernames, options),
        daemon=True,
    ).start()

    return jsonify(session_id=session_id, usernames=usernames), 202


@app.get("/api/stream/<session_id>")
def stream_results(session_id: str):
    with sessions_lock:
        session = search_sessions.get(session_id)
    if session is None:
        return jsonify(error="Search session not found."), 404

    def generate():
        while True:
            try:
                event = session["queue"].get(timeout=10)
            except queue.Empty:
                if not session["running"]:
                    break
                yield ": heartbeat\n\n"
                continue

            if event.get("type") in {"complete", "error", "cancelled", "osint_complete"}:
                if event.get("type") in {"complete", "error", "cancelled"}:
                    session["terminal_event"] = True
            yield _event_stream(event)
            if session["terminal_event"] and session["queue"].empty():
                break

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/cancel/<session_id>")
def cancel_search(session_id: str):
    with sessions_lock:
        session = search_sessions.get(session_id)
    if session is None:
        return jsonify(error="Search session not found."), 404

    session["cancelled"] = True
    process = session.get("process")
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
    session["running"] = False
    return jsonify(status="cancelled")


@app.get("/api/report/pdf/<session_id>")
def download_pdf_report(session_id: str):
    """Generate and return the comprehensive downloadable PDF report."""
    with sessions_lock:
        session = search_sessions.get(session_id)
    if session is None:
        return jsonify(error="Session not found or expired."), 404

    try:
        pdf_bytes = build_pdf_report(
            session_id=session_id,
            usernames=session.get("usernames", []),
            sherlock_results=session.get("sherlock_results", []),
            exif_results=session.get("exif_results", []),
            github_data=session.get("github_data"),
            gravatar_data=session.get("gravatar_data"),
            keybase_data=session.get("keybase_data"),
            snapchat_data=session.get("snapchat_data"),
            instagram_data=session.get("instagram_data"),
            phone_data=session.get("phone_data"),
            breach_data=session.get("breach_data"),
            dorks_data=session.get("dorks_data", []),
            socid_data=session.get("socid_data", {}),
            holehe_data=session.get("holehe_data", []),
            contacts=session.get("contacts", {"emails": [], "phones": []}),
            risk_assessment=session.get("risk_assessment", {}),
        )
        safe_name = "_".join(session.get("usernames", ["target"]))[:30]
        filename = f"sherlock_osint_report_{safe_name}_{session_id[:8]}.pdf"
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(pdf_bytes)),
            },
        )
    except Exception as exc:
        logger.error(f"Failed to generate PDF for session {session_id}: {exc}", exc_info=True)
        return jsonify(error=f"PDF generation failed: {str(exc)}"), 500


@app.get("/api/report/json/<session_id>")
def download_json_report(session_id: str):
    """Export the entire investigation dataset as structured JSON."""
    with sessions_lock:
        session = search_sessions.get(session_id)
    if session is None:
        return jsonify(error="Session not found or expired."), 404

    payload = {
        "case_id": session_id,
        "usernames": session.get("usernames", []),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "risk_assessment": session.get("risk_assessment", {}),
        "sherlock_results": session.get("sherlock_results", []),
        "exif_results": session.get("exif_results", []),
        "github_osint": session.get("github_data"),
        "gravatar_osint": session.get("gravatar_data"),
        "keybase_osint": session.get("keybase_data"),
        "snapchat_osint": session.get("snapchat_data"),
        "instagram_osint": session.get("instagram_data"),
        "phone_osint": session.get("phone_data"),
        "breach_osint": session.get("breach_data"),
        "dorks_osint": session.get("dorks_data", []),
        "socid_osint": session.get("socid_data", {}),
        "holehe_osint": session.get("holehe_data", []),
        "contacts_harvested": session.get("contacts", {}),
    }
    safe_name = "_".join(session.get("usernames", ["target"]))[:30]
    filename = f"sherlock_osint_data_{safe_name}_{session_id[:8]}.json"
    return Response(
        json.dumps(payload, indent=2, ensure_ascii=False),
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/session/<session_id>")
def get_session_details(session_id: str):
    """Fetch live session details, including ExifTool images and deep OSINT findings."""
    with sessions_lock:
        session = search_sessions.get(session_id)
    if session is None:
        return jsonify(error="Session not found."), 404

    return jsonify({
        "session_id": session_id,
        "running": session.get("running", False),
        "usernames": session.get("usernames", []),
        "claimed_count": len([r for r in session.get("sherlock_results", []) if r.get("status") == "claimed"]),
        "total_checked": len(session.get("sherlock_results", [])),
        "exif_images_count": len(session.get("exif_results", [])),
        "exif_results": session.get("exif_results", []),
        "github_data": session.get("github_data"),
        "gravatar_data": session.get("gravatar_data"),
        "keybase_data": session.get("keybase_data"),
        "snapchat_data": session.get("snapchat_data"),
        "instagram_data": session.get("instagram_data"),
        "phone_data": session.get("phone_data"),
        "breach_data": session.get("breach_data"),
        "dorks_data": session.get("dorks_data", []),
        "socid_data": session.get("socid_data", {}),
        "holehe_data": session.get("holehe_data", []),
        "contacts": session.get("contacts", {}),
        "risk_assessment": session.get("risk_assessment", {}),
    })


@app.get("/api/graph/<session_id>")
def get_session_graph(session_id: str):
    """Generate and return the interactive OSINT network graph topology."""
    with sessions_lock:
        session = search_sessions.get(session_id)
    if session is None:
        return jsonify(error="Session not found."), 404

    graph = build_osint_mapping_graph(
        usernames=session.get("usernames", []),
        sherlock_results=session.get("sherlock_results", []),
        exif_results=session.get("exif_results", []),
        github_data=session.get("github_data"),
        gravatar_data=session.get("gravatar_data"),
        keybase_data=session.get("keybase_data"),
        snapchat_data=session.get("snapchat_data"),
        instagram_data=session.get("instagram_data"),
        phone_data=session.get("phone_data"),
        breach_data=session.get("breach_data"),
        socid_data=session.get("socid_data", {}),
        contacts=session.get("contacts", {"emails": [], "phones": []}),
        holehe_data=session.get("holehe_data", []),
    )
    return jsonify(graph)


@app.get("/api/osint-framework")
def get_osint_framework():
    """Return the structured OSINT framework interactive resource directory."""
    return jsonify(categories=OSINT_FRAMEWORK_DATA)


@app.get("/api/sites")
def get_sites():
    try:
        with DATA_PATH.open(encoding="utf-8") as data_file:
            data = json.load(data_file)
        data.pop("$schema", None)
        sites = [
            {"name": name, "url": details.get("urlMain", ""), "nsfw": bool(details.get("isNSFW"))}
            for name, details in sorted(data.items(), key=lambda item: item[0].casefold())
        ]
        return jsonify(sites=sites, total=len(sites))
    except (OSError, json.JSONDecodeError):
        return jsonify(error="Site catalogue unavailable."), 500


@app.get("/api/status")
def api_status():
    with sessions_lock:
        active_sessions = sum(1 for session in search_sessions.values() if session["running"])
    exif_ok = bool(EXIFTOOL_PATH and Path(EXIFTOOL_PATH).is_file())
    return jsonify(
        status="ok",
        version="0.16.2",
        active_sessions=active_sessions,
        exiftool_available=exif_ok,
    )


if __name__ == "__main__":
    print("Sherlock Web + ExifTool OSINT Suite is ready at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, threaded=True)
