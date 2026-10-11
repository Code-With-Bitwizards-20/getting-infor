"""Structured subprocess adapter for the Sherlock search engine."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from sherlock_project.notify import QueryNotify  # noqa: E402
from sherlock_project.result import QueryStatus  # noqa: E402
from sherlock_project.sherlock import check_for_parameter, multiple_usernames, sherlock  # noqa: E402
from sherlock_project.sites import SitesInformation  # noqa: E402


def emit(event_type: str, **payload) -> None:
    print(json.dumps({"type": event_type, **payload}, ensure_ascii=False), flush=True)


class WebNotifier(QueryNotify):
    def __init__(self, total: int):
        super().__init__()
        self.total = total
        self.checked = 0
        self.found = 0

    def start(self, username):
        emit("username_start", username=username)

    def update(self, result):
        super().update(result)
        self.checked += 1
        if result.status == QueryStatus.CLAIMED:
            self.found += 1
        emit(
            "result",
            username=result.username,
            site=result.site_name,
            url=result.site_url_user,
            status=result.status.value.lower(),
            response_time=round(result.query_time * 1000) if result.query_time is not None else None,
            context=result.context,
            checked=self.checked,
            total=self.total,
            found=self.found,
        )


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--proxy", default=None)
    parser.add_argument("--nsfw", action="store_true")
    parser.add_argument("usernames", nargs="+")
    args = parser.parse_args()

    data_path = PROJECT_ROOT / "sherlock_project" / "resources" / "data.json"
    sites = SitesInformation(str(data_path), honor_exclusions=False)
    if not args.nsfw:
        sites.remove_nsfw_sites()
    site_data = {site.name: site.information.copy() for site in sites}

    usernames = []
    for username in args.usernames:
        usernames.extend(multiple_usernames(username) if check_for_parameter(username) else [username])

    notifier = WebNotifier(total=len(site_data) * len(usernames))
    started = time.monotonic()
    emit("start", usernames=usernames, total=notifier.total, sites=len(site_data))
    for username in usernames:
        # Sherlock annotates site records with request futures, so each pass gets
        # its own shallow copy of the manifest records.
        username_sites = {name: details.copy() for name, details in site_data.items()}
        sherlock(username, username_sites, notifier, proxy=args.proxy, timeout=args.timeout)

    emit(
        "complete",
        found=notifier.found,
        checked=notifier.checked,
        total=notifier.total,
        elapsed=round(time.monotonic() - started, 2),
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        emit("error", message=str(exc))
        raise SystemExit(1)
