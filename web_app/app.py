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

from sherlock_project.notify import QueryNotify
from sherlock_project.result import QueryStatus
from sherlock_project.sherlock import check_for_parameter, multiple_usernames, sherlock
from sherlock_project.sites import SitesInformation

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

    try:
        sites = SitesInformation(str(DATA_PATH), honor_exclusions=False)
        if not options.get("nsfw", False):
            sites.remove_nsfw_sites()
        site_data = {site.name: site.information.copy() for site in sites}

        all_usernames = []
        for username in usernames:
            all_usernames.extend(multiple_usernames(username) if check_for_parameter(username) else [username])

        total_checks = len(site_data) * len(all_usernames)

        class WebNotifier(QueryNotify):
            def __init__(self, total: int):
                super().__init__()
                self.total = total
                self.checked = 0
                self.found = 0

            def start(self, username):
                event_queue.put({"type": "username_start", "username": username})

            def update(self, result):
                super().update(result)
                self.checked += 1
                if result.status == QueryStatus.CLAIMED:
                    self.found += 1
                ev = {
                    "type": "result",
                    "username": result.username,
                    "site": result.site_name,
                    "url": result.site_url_user,
                    "status": result.status.value.lower(),
                    "response_time": round(result.query_time * 1000) if result.query_time is not None else None,
                    "context": result.context,
                    "checked": self.checked,
                    "total": self.total,
                    "found": self.found,
                }
                with sessions_lock:
                    session["sherlock_results"].append(ev)
                if result.status == QueryStatus.CLAIMED:
                    t = osint_pool.submit(
                        _process_claimed_profile,
                        result.site_name,
                        result.site_url_user,
                        result.username,
                    )
                    pending_tasks.append(t)
                event_queue.put(ev)

        notifier = WebNotifier(total=total_checks)
        started = time.monotonic()
        event_queue.put({"type": "start", "usernames": all_usernames, "total": notifier.total, "sites": len(site_data)})

        timeout_sec = min(int(options.get("timeout", 10)), 15)
        for target_user in all_usernames:
            if session.get("cancelled"):
                break
            username_sites = {name: details.copy() for name, details in site_data.items()}
            sherlock(target_user, username_sites, notifier, proxy=options.get("proxy") or None, timeout=timeout_sec)

        if session["cancelled"]:
            osint_pool.shutdown(wait=False, cancel_futures=True)
            event_queue.put({"type": "cancelled", "message": "Search cancelled"})
            return

        event_queue.put({
            "type": "complete",
            "found": notifier.found,
            "checked": notifier.checked,
            "total": notifier.total,
            "elapsed": round(time.monotonic() - started, 2),
        })

        # Allow pending ExifTool / OSINT scans to wrap up gracefully
        for t in pending_tasks:
            try:
                t.result(timeout=5)
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
        raw_users = request.args.get("usernames", "")
        usernames = _parse_usernames(raw_users)
        if not usernames:
            return jsonify(error="Search session not found."), 404

        timeout = int(request.args.get("timeout", 10))
        options = {
            "timeout": max(2, min(timeout, 30)),
            "nsfw": request.args.get("nsfw") == "1",
            "proxy": request.args.get("proxy", "").strip(),
            "scan_exif": request.args.get("scan_exif", "1") == "1",
            "deep_osint": request.args.get("deep_osint", "1") == "1",
            "max_images_per_site": int(request.args.get("max_images_per_site", 5)),
        }
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


@app.post("/api/check-batch")
def check_batch():
    """Serverless endpoint: verify a batch of sites without long-running connections."""
    payload = request.get_json(silent=True) or {}
    usernames = _parse_usernames(payload.get("usernames", "") or payload.get("username", ""))
    site_names = payload.get("sites", [])
    timeout = max(2, min(int(payload.get("timeout", 4)), 10))
    proxy = payload.get("proxy", "").strip() or None

    if not usernames or not site_names:
        return jsonify(results=[])

    data_path = PROJECT_ROOT / "sherlock_project" / "resources" / "data.json"
    sites = SitesInformation(str(data_path), honor_exclusions=False)
    site_dict = {site.name: site.information.copy() for site in sites if site.name in site_names}

    results = []
    class BatchNotifier(QueryNotify):
        def update(self, result):
            super().update(result)
            results.append({
                "type": "result",
                "username": result.username,
                "site": result.site_name,
                "url": result.site_url_user,
                "status": result.status.value.lower(),
                "response_time": round(result.query_time * 1000) if result.query_time is not None else None,
                "context": result.context,
            })

    notifier = BatchNotifier()
    for u in usernames:
        u_sites = {name: details.copy() for name, details in site_dict.items()}
        sherlock(u, u_sites, notifier, proxy=proxy, timeout=timeout)

    return jsonify(results=results)


@app.post("/api/deep-osint")
def deep_osint_endpoint():
    """Serverless endpoint: run GitHub, Gravatar, Keybase, Dorks, Holehe OSINT."""
    payload = request.get_json(silent=True) or {}
    username = payload.get("username", "").strip()
    if not username:
        return jsonify(error="Username required"), 400

    out = {}
    try:
        out["github"] = run_github_osint(username)
    except Exception:
        out["github"] = None
    try:
        out["gravatar"] = run_gravatar_osint(username)
    except Exception:
        out["gravatar"] = None
    try:
        out["keybase"] = run_keybase_osint(username)
    except Exception:
        out["keybase"] = None
    try:
        out["snapchat"] = run_snapintel_osint(username)
    except Exception:
        out["snapchat"] = None
    try:
        out["instagram"] = run_instagram_osint(username)
    except Exception:
        out["instagram"] = None
    try:
        out["dorks"] = generate_google_dorks(username)
    except Exception:
        out["dorks"] = []

    candidate_emails = []
    if out.get("github") and out["github"].get("email"):
        candidate_emails.append(out["github"]["email"])
    if not candidate_emails and "@" not in username:
        candidate_emails.append(f"{username}@gmail.com")

    holehe_matches = []
    for em in candidate_emails[:1]:
        try:
            m = run_holehe_email_osint(em, max_checks=15)
            if m:
                holehe_matches.extend(m)
        except Exception:
            pass
    out["holehe"] = holehe_matches

    return jsonify(out)


@app.post("/api/report/pdf")
def generate_pdf_post():
    """Generate PDF directly from JSON payload without relying on in-memory server sessions."""
    payload = request.get_json(silent=True) or {}
    session_id = payload.get("session_id", "report")
    usernames = payload.get("usernames", ["target"])
    sherlock_results = payload.get("sherlock_results", [])
    exif_results = payload.get("exif_results", [])
    github_data = payload.get("github_data")
    gravatar_data = payload.get("gravatar_data")
    keybase_data = payload.get("keybase_data")
    snapchat_data = payload.get("snapchat_data")
    instagram_data = payload.get("instagram_data")
    phone_data = payload.get("phone_data")
    breach_data = payload.get("breach_data")
    dorks_data = payload.get("dorks_data", [])
    socid_data = payload.get("socid_data", {})
    holehe_data = payload.get("holehe_data", [])
    contacts = payload.get("contacts", {"emails": [], "phones": []})
    risk_assessment = payload.get("risk_assessment", {})

    try:
        pdf_bytes = build_pdf_report(
            session_id=session_id,
            usernames=usernames,
            sherlock_results=sherlock_results,
            exif_results=exif_results,
            github_data=github_data,
            gravatar_data=gravatar_data,
            keybase_data=keybase_data,
            snapchat_data=snapchat_data,
            instagram_data=instagram_data,
            phone_data=phone_data,
            breach_data=breach_data,
            dorks_data=dorks_data,
            socid_data=socid_data,
            holehe_data=holehe_data,
            contacts=contacts,
            risk_assessment=risk_assessment,
        )
        safe_name = "_".join(usernames)[:30]
        filename = f"sherlock_osint_report_{safe_name}.pdf"
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(pdf_bytes)),
            },
        )
    except Exception as exc:
        return jsonify(error=f"PDF generation failed: {str(exc)}"), 500


if __name__ == "__main__":
    print("Sherlock Web + ExifTool OSINT Suite is ready at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, threaded=True)
