"""OSINT and ExifTool Forensics Engine for Sherlock Web.

Integrates:
1. ExifTool Forensics Scanner (Camera, Software, Timestamps, GPS Geolocation, Metadata)
2. Profile Image & Media Harvester (Avatar and top images from claimed accounts)
3. GitHub Deep OSINT Analyzer (Public keys, commit emails, profile info, orgs)
4. Gravatar Identity & Linked Accounts Prober
5. Bio & Contact Identifier Harvester (Emails, phone numbers via libphonenumber, social handles)
6. Avatar Hash & Cross-Platform Identity Correlation (Identifies matching avatars across sites)
7. Digital Footprint Exposure & Privacy Risk Scorer
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

try:
    import phonenumbers
    from phonenumbers import carrier, geocoder
except ImportError:
    phonenumbers = None
    carrier = None
    geocoder = None

try:
    import socid_extractor
except ImportError:
    socid_extractor = None

try:
    import toutatis
except ImportError:
    toutatis = None

try:
    from PIL import Image
except ImportError:
    Image = None

logger = logging.getLogger(__name__)

# Base directories
MODULE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = MODULE_DIR.parent
EXIFTOOL_BUNDLE = PROJECT_ROOT / "exiftool-13.59_64" / "exiftool.exe"


def find_exiftool_binary() -> Optional[str]:
    """Locate exiftool binary either from the bundled folder or system PATH."""
    if EXIFTOOL_BUNDLE.is_file():
        return str(EXIFTOOL_BUNDLE)
    system_path = shutil.which("exiftool")
    if system_path:
        return system_path
    alt_bundle = PROJECT_ROOT / "exiftool-13.59_64" / "exiftool(-k).exe"
    if alt_bundle.is_file():
        return str(alt_bundle)
    return None


EXIFTOOL_PATH = find_exiftool_binary()

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# Image extensions we are interested in for Exif analysis
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff", ".heic", ".avif", ".gif"}


def parse_gps_coordinate(coord_val: Any) -> Optional[float]:
    """Convert various GPS coordinate representations to a float."""
    if coord_val is None:
        return None
    if isinstance(coord_val, (int, float)):
        return float(coord_val)
    if isinstance(coord_val, str):
        # Format like "+37.774929" or "37 deg 46' 29.74\" N"
        m = re.match(r"^([+-]?\d+(?:\.\d+)?)$", coord_val.strip())
        if m:
            return float(m.group(1))
        # Match DMS format: 37 deg 46' 29.74" N
        dms_m = re.match(
            r"(\d+)\s*deg\s*(\d+)'\s*([\d\.]+)\"\s*([NSEW])", coord_val, re.IGNORECASE
        )
        if dms_m:
            deg = float(dms_m.group(1))
            minute = float(dms_m.group(2))
            sec = float(dms_m.group(3))
            direction = dms_m.group(4).upper()
            val = deg + (minute / 60.0) + (sec / 3600.0)
            if direction in ("S", "W"):
                val = -val
            return val
    return None


def run_exiftool(file_paths: List[str]) -> List[Dict[str, Any]]:
    """Execute ExifTool on a batch of files and return structured JSON metadata."""
    if not EXIFTOOL_PATH or not file_paths:
        return []

    valid_paths = [p for p in file_paths if os.path.isfile(p)]
    if not valid_paths:
        return []

    command = [
        EXIFTOOL_PATH,
        "-json",
        "-c",
        "%+.6f",  # format coordinates in decimal with sign
        "-fast",
        *valid_paths,
    ]

    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        if proc.returncode in (0, 1) and proc.stdout:
            try:
                return json.loads(proc.stdout)
            except json.JSONDecodeError:
                pass
    except Exception as exc:
        logger.error(f"ExifTool execution error: {exc}")

    return []


def generate_reverse_image_search_links(image_url: str) -> Dict[str, str]:
    """Generate direct reverse image search URLs across major visual search engines."""
    quoted = quote(image_url or "", safe="")
    return {
        "google_lens": f"https://lens.google.com/uploadbyurl?url={quoted}",
        "yandex": f"https://yandex.com/images/search?rpt=imageview&url={quoted}",
        "tineye": f"https://tineye.com/search?url={quoted}",
        "bing": f"https://www.bing.com/images/search?view=detailv2&iss=sbi&FORM=SBIHMP&sbisrc=UrlPaste&q=imgurl:{quoted}",
        "geospy": "https://geospy.ai",
    }


def clean_metadata_record(raw: Dict[str, Any], original_url: str, is_avatar: bool, site_name: str, username: str) -> Dict[str, Any]:
    """Clean and standardize an ExifTool raw record into an informative summary."""
    filename = raw.get("FileName", "image")
    file_type = raw.get("FileType", "")
    mime_type = raw.get("MIMEType", "")
    file_size = raw.get("FileSize", "")
    dimensions = f"{raw.get('ImageWidth', '')}x{raw.get('ImageHeight', '')}" if raw.get("ImageWidth") else ""
    megapixels = raw.get("Megapixels")

    # Camera & Device
    make = raw.get("Make", "")
    model = raw.get("Model", "")
    camera = f"{make} {model}".strip() or raw.get("CameraModelName", "Unknown / Stripped")
    lens = raw.get("LensModel") or raw.get("LensID") or raw.get("LensInfo", "")
    software = raw.get("Software", "")

    # Timestamps
    date_original = raw.get("DateTimeOriginal") or raw.get("CreateDate") or raw.get("DateCreated", "")
    date_modify = raw.get("ModifyDate") or raw.get("FileModifyDate", "")

    # Geolocation / GPS
    lat_raw = raw.get("GPSLatitude")
    lon_raw = raw.get("GPSLongitude")
    lat = parse_gps_coordinate(lat_raw)
    lon = parse_gps_coordinate(lon_raw)
    altitude = raw.get("GPSAltitude", "")

    has_gps = lat is not None and lon is not None
    google_maps_url = f"https://www.google.com/maps?q={lat:.6f},{lon:.6f}" if has_gps else None
    osm_url = f"https://www.openstreetmap.org/?mlat={lat:.6f}&mlon={lon:.6f}#map=16/{lat:.6f}/{lon:.6f}" if has_gps else None
    google_earth_url = f"https://earth.google.com/web/search/{lat:.6f},{lon:.6f}" if has_gps else None
    dualmaps_url = f"https://www.dualmaps.com/map.htm?lat={lat:.6f}&lng={lon:.6f}&zoom=17" if has_gps else None
    mapillary_url = f"https://www.mapillary.com/app/?lat={lat:.6f}&lng={lon:.6f}&z=17" if has_gps else None

    # Color space & profiles
    color_space = raw.get("ColorSpace", "")
    profile_desc = raw.get("ProfileDescription", "")

    # Copyright / Author
    author = raw.get("Artist") or raw.get("XPAuthor") or raw.get("Creator") or raw.get("By-line", "")
    copyright_text = raw.get("Copyright", "")

    # Hashes / Fingerprints
    source_file = raw.get("SourceFile", "")
    file_hash = ""
    if source_file and os.path.isfile(source_file):
        try:
            with open(source_file, "rb") as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
        except OSError:
            pass

    return {
        "site_name": site_name,
        "username": username,
        "filename": filename,
        "original_url": original_url,
        "is_avatar": is_avatar,
        "file_type": file_type,
        "mime_type": mime_type,
        "file_size": file_size,
        "dimensions": dimensions,
        "megapixels": megapixels,
        "camera": camera,
        "make": make,
        "model": model,
        "lens": lens,
        "software": software,
        "date_original": str(date_original) if date_original else None,
        "date_modify": str(date_modify) if date_modify else None,
        "has_gps": has_gps,
        "latitude": round(lat, 6) if lat is not None else None,
        "longitude": round(lon, 6) if lon is not None else None,
        "altitude": str(altitude) if altitude else None,
        "google_maps_url": google_maps_url,
        "osm_url": osm_url,
        "google_earth_url": google_earth_url,
        "dualmaps_url": dualmaps_url,
        "mapillary_url": mapillary_url,
        "geospy_ai_url": "https://geospy.ai",
        "color_space": color_space,
        "profile_description": profile_desc,
        "author": author,
        "copyright": copyright_text,
        "md5_hash": file_hash,
        "reverse_image_links": generate_reverse_image_search_links(original_url),
        "raw_tags_count": len(raw),
        "raw_metadata": raw,
    }


class OSINTImageHarvester:
    """Discovers and extracts profile avatar and top 5 media images from target profiles."""

    def __init__(self, session_dir: Path):
        self.session_dir = session_dir
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        self.extracted_socids: Dict[str, Any] = {}

    def scrape_profile_images(
        self, site_name: str, profile_url: str, username: str, max_additional: int = 5
    ) -> List[Dict[str, Any]]:
        """Scrape profile avatar and up to max_additional images from a given profile URL."""
        discovered: List[Dict[str, Any]] = []

        # Known direct avatar fallbacks
        lower_site = site_name.lower()
        if "github" in lower_site:
            discovered.append({
                "url": f"https://avatars.githubusercontent.com/{username}",
                "is_avatar": True,
            })
        elif "gitlab" in lower_site:
            discovered.append({
                "url": f"https://gitlab.com/{username}.png",
                "is_avatar": True,
            })
        elif "gravatar" in lower_site:
            u_hash = hashlib.md5(username.lower().strip().encode()).hexdigest()
            discovered.append({
                "url": f"https://www.gravatar.com/avatar/{u_hash}?s=400&d=identicon",
                "is_avatar": True,
            })

        # Fetch the HTML page to scrape meta tags and images
        try:
            resp = self.session.get(profile_url, timeout=7, verify=False)
            if resp.status_code == 200 and "text/html" in resp.headers.get("Content-Type", ""):
                if socid_extractor:
                    try:
                        s_ids = socid_extractor.extract(resp.text)
                        if s_ids and isinstance(s_ids, dict):
                            self.extracted_socids.update(s_ids)
                    except Exception:
                        pass
                soup = BeautifulSoup(resp.text, "html.parser")

                # Look for meta image (og:image, twitter:image)
                meta_img = (
                    soup.find("meta", property="og:image")
                    or soup.find("meta", attrs={"name": "twitter:image"})
                    or soup.find("meta", attrs={"name": "twitter:image:src"})
                    or soup.find("meta", property="og:image:secure_url")
                    or soup.find("link", rel="image_src")
                )
                if meta_img:
                    meta_url = meta_img.get("content") or meta_img.get("href")
                    if meta_url:
                        full_meta_url = urljoin(profile_url, meta_url)
                        if not any(d["url"] == full_meta_url for d in discovered):
                            discovered.append({"url": full_meta_url, "is_avatar": True})

                # Search for prominent user avatar in DOM
                avatar_tag = soup.find(
                    "img",
                    attrs={"class": re.compile(r"avatar|profile|user-pic|profile-img|author", re.IGNORECASE)},
                )
                if avatar_tag:
                    src = avatar_tag.get("src") or avatar_tag.get("data-src")
                    if src:
                        full_src = urljoin(profile_url, src)
                        if not any(d["url"] == full_src for d in discovered):
                            discovered.append({"url": full_src, "is_avatar": True})

                # Now extract additional images from page (up to max_additional)
                additional_count = 0
                for img in soup.find_all("img"):
                    if additional_count >= max_additional:
                        break
                    src = img.get("src") or img.get("data-src") or img.get("data-original")
                    if not src:
                        continue
                    full_src = urljoin(profile_url, src)

                    # Filter out tiny icon sprites, tracking pixels, badges
                    parsed = urlparse(full_src)
                    ext = Path(parsed.path).suffix.lower()
                    if ext in (".svg", ".ico"):
                        continue
                    if any(term in full_src.lower() for term in ("pixel", "beacon", "spacer", "tracking", "1x1", "badge")):
                        continue
                    if any(d["url"] == full_src for d in discovered):
                        continue

                    discovered.append({"url": full_src, "is_avatar": False})
                    additional_count += 1

        except Exception as exc:
            logger.debug(f"Failed to scrape images from {profile_url}: {exc}")

        # Limit total to 1 avatar + 5 additional images
        avatars = [d for d in discovered if d["is_avatar"]][:1]
        extras = [d for d in discovered if not d["is_avatar"]][:max_additional]
        return avatars + extras

    def download_image(self, img_info: Dict[str, Any], site_name: str, username: str, index: int) -> Optional[Dict[str, Any]]:
        """Download an image to temporary disk and return its local file path."""
        url = img_info["url"]
        try:
            resp = self.session.get(url, timeout=8, stream=True, verify=False)
            if resp.status_code != 200:
                return None

            content_type = resp.headers.get("Content-Type", "").lower()
            if not ("image" in content_type or any(ext in url.lower() for ext in IMAGE_EXTENSIONS)):
                return None

            # Enforce 12MB size limit
            content_length = resp.headers.get("Content-Length")
            if content_length and int(content_length) > 12 * 1024 * 1024:
                return None

            # Determine extension
            ext = ".jpg"
            parsed_path = urlparse(url).path
            p_ext = Path(parsed_path).suffix.lower()
            if p_ext in IMAGE_EXTENSIONS:
                ext = p_ext
            elif "png" in content_type:
                ext = ".png"
            elif "webp" in content_type:
                ext = ".webp"

            safe_site = re.sub(r"[^\w\-]", "_", site_name.lower())
            safe_user = re.sub(r"[^\w\-]", "_", username.lower())
            role = "avatar" if img_info["is_avatar"] else f"img_{index}"
            local_name = f"{safe_site}_{safe_user}_{role}{ext}"
            local_path = self.session_dir / local_name

            with open(local_path, "wb") as f:
                downloaded = 0
                for chunk in resp.iter_content(chunk_size=16384):
                    downloaded += len(chunk)
                    if downloaded > 12 * 1024 * 1024:
                        break
                    f.write(chunk)

            return {
                "local_path": str(local_path),
                "original_url": url,
                "is_avatar": img_info["is_avatar"],
                "site_name": site_name,
                "username": username,
            }
        except Exception as exc:
            logger.debug(f"Error downloading {url}: {exc}")
            return None

    def scan_claimed_profile(
        self, site_name: str, profile_url: str, username: str, max_additional: int = 5
    ) -> List[Dict[str, Any]]:
        """Complete workflow for a single profile: Scrape -> Download -> ExifTool -> Metadata Clean."""
        images_to_fetch = self.scrape_profile_images(site_name, profile_url, username, max_additional=max_additional)
        if not images_to_fetch:
            return []

        downloaded_items = []
        for idx, img in enumerate(images_to_fetch):
            res = self.download_image(img, site_name, username, idx + 1)
            if res:
                downloaded_items.append(res)

        if not downloaded_items:
            return []

        # Run ExifTool on the local images
        local_paths = [item["local_path"] for item in downloaded_items]
        exif_raw_list = run_exiftool(local_paths)

        # Map back results
        raw_by_path = {os.path.normpath(r.get("SourceFile", "")): r for r in exif_raw_list}
        cleaned_results: List[Dict[str, Any]] = []

        for item in downloaded_items:
            norm = os.path.normpath(item["local_path"])
            raw = raw_by_path.get(norm)
            if not raw:
                # Fallback if exiftool missed or couldn't parse
                raw = {
                    "SourceFile": item["local_path"],
                    "FileName": Path(item["local_path"]).name,
                    "FileType": Path(item["local_path"]).suffix.lstrip(".").upper(),
                }
            cleaned = clean_metadata_record(
                raw=raw,
                original_url=item["original_url"],
                is_avatar=item["is_avatar"],
                site_name=item["site_name"],
                username=item["username"],
            )
            cleaned_results.append(cleaned)

        return cleaned_results


# ============================================================================
# Deep OSINT Tool: GitHub Deep Profile & Key Harvester
# ============================================================================
def run_github_osint(username: str) -> Optional[Dict[str, Any]]:
    """Deep OSINT scan on GitHub: Profile info, public keys, recent commit emails."""
    try:
        url = f"https://api.github.com/users/{username}"
        resp = requests.get(url, headers=DEFAULT_HEADERS, timeout=8)
        if resp.status_code == 200:
            data = resp.json()

            # Also check public GPG and SSH keys
            keys_info: List[str] = []
            try:
                k_resp = requests.get(f"https://github.com/{username}.keys", headers=DEFAULT_HEADERS, timeout=5)
                if k_resp.status_code == 200 and k_resp.text.strip():
                    keys_info = [line.strip() for line in k_resp.text.splitlines() if line.strip()]
            except Exception:
                pass

            # Check public events for commit email addresses
            commit_emails: List[str] = []
            try:
                events_resp = requests.get(f"https://api.github.com/users/{username}/events/public", headers=DEFAULT_HEADERS, timeout=5)
                if events_resp.status_code == 200:
                    events = events_resp.json()
                    for ev in events:
                        if ev.get("type") == "PushEvent":
                            for commit in ev.get("payload", {}).get("commits", []):
                                email = commit.get("author", {}).get("email")
                                if email and "noreply.github.com" not in email:
                                    if email not in commit_emails:
                                        commit_emails.append(email)
            except Exception:
                pass

            return {
                "platform": "GitHub",
                "username": username,
                "name": data.get("name"),
                "company": data.get("company"),
                "blog": data.get("blog"),
                "location": data.get("location"),
                "email": data.get("email"),
                "bio": data.get("bio"),
                "twitter_username": data.get("twitter_username"),
                "public_repos": data.get("public_repos"),
                "public_gists": data.get("public_gists"),
                "followers": data.get("followers"),
                "following": data.get("following"),
                "created_at": data.get("created_at"),
                "avatar_url": data.get("avatar_url"),
                "html_url": data.get("html_url"),
                "public_ssh_keys_count": len(keys_info),
                "commit_emails_discovered": commit_emails,
            }
    except Exception as exc:
        logger.debug(f"GitHub deep OSINT error: {exc}")
    return None


# ============================================================================
# Deep OSINT Tool: Gravatar Identity Prober
# ============================================================================
def run_gravatar_osint(username: str, email_guess: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Probes Gravatar public profile to uncover linked accounts, names, and crypto keys."""
    hashes_to_test = [
        hashlib.md5(username.lower().strip().encode()).hexdigest(),
    ]
    if email_guess:
        hashes_to_test.append(hashlib.md5(email_guess.lower().strip().encode()).hexdigest())

    for h in hashes_to_test:
        try:
            url = f"https://en.gravatar.com/{h}.json"
            resp = requests.get(url, headers=DEFAULT_HEADERS, timeout=6)
            if resp.status_code == 200:
                entries = resp.json().get("entry", [])
                if entries:
                    entry = entries[0]
                    accounts = [
                        {"domain": acc.get("domain"), "url": acc.get("url"), "username": acc.get("username")}
                        for acc in entry.get("accounts", [])
                    ]
                    photos = [p.get("value") for p in entry.get("photos", []) if p.get("value")]
                    crypto = entry.get("currency", [])

                    return {
                        "platform": "Gravatar",
                        "hash": h,
                        "display_name": entry.get("displayName") or entry.get("preferredUsername"),
                        "about_me": entry.get("aboutMe"),
                        "current_location": entry.get("currentLocation"),
                        "profile_url": entry.get("profileUrl"),
                        "avatar_url": entry.get("thumbnailUrl"),
                        "linked_accounts": accounts,
                        "verified_accounts_count": len(accounts),
                        "photos": photos,
                        "crypto_wallets": crypto,
                    }
        except Exception:
            continue
    return None


# ============================================================================
# Deep OSINT Tool: Contact & Phone/Email Harvester
# ============================================================================
def harvest_contacts_from_text(raw_text: str) -> Dict[str, List[str]]:
    """Extract emails, phone numbers, and potential crypto addresses from text."""
    results: Dict[str, List[str]] = {
        "emails": [],
        "phones": [],
        "crypto_btc": [],
        "crypto_eth": [],
    }

    # Email regex
    email_matches = re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b", raw_text)
    for email in email_matches:
        e_clean = email.lower().strip()
        if e_clean not in results["emails"] and not e_clean.endswith((".png", ".jpg", ".jpeg", ".webp")):
            results["emails"].append(e_clean)

    # Bitcoin address pattern
    btc_matches = re.findall(r"\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b", raw_text)
    for btc in btc_matches:
        if btc not in results["crypto_btc"]:
            results["crypto_btc"].append(btc)

    # Ethereum address pattern
    eth_matches = re.findall(r"\b0x[a-fA-F0-9]{40}\b", raw_text)
    for eth in eth_matches:
        if eth not in results["crypto_eth"]:
            results["crypto_eth"].append(eth)

    # Phone numbers via Google's phonenumbers if available
    if phonenumbers:
        try:
            for match in phonenumbers.PhoneNumberMatcher(raw_text, "US"):
                fmt = phonenumbers.format_number(match.number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
                if fmt not in results["phones"]:
                    results["phones"].append(fmt)
        except Exception:
            pass

    return results


# ============================================================================
# Avatar Correlation Engine (Cross-Platform Photo Re-use)
# ============================================================================
def correlate_avatars(exif_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group avatars that have identical or matching MD5 hashes to prove cross-platform account correlation."""
    hash_groups: Dict[str, List[Dict[str, Any]]] = {}

    for item in exif_results:
        if not item.get("is_avatar"):
            continue
        h = item.get("md5_hash")
        if h:
            hash_groups.setdefault(h, []).append(item)

    correlations: List[Dict[str, Any]] = []
    for h, group in hash_groups.items():
        if len(group) > 1:
            sites = list({g["site_name"] for g in group})
            correlations.append({
                "md5_hash": h,
                "shared_count": len(group),
                "sites": sites,
                "avatar_url": group[0]["original_url"],
                "usernames": list({g["username"] for g in group}),
            })

    return correlations


# ============================================================================
# Digital Footprint Exposure & Privacy Risk Assessment
# ============================================================================
def calculate_footprint_risk(
    claimed_sites_count: int,
    exif_results: List[Dict[str, Any]],
    github_data: Optional[Dict[str, Any]],
    gravatar_data: Optional[Dict[str, Any]],
    contacts: Dict[str, List[str]],
) -> Dict[str, Any]:
    """Calculate an objective OSINT Digital Footprint Exposure & Privacy Threat Score (0 - 100)."""
    score = 0
    reasons: List[str] = []

    # Breadth of public profiles
    if claimed_sites_count > 0:
        pts = min(35, claimed_sites_count * 3)
        score += pts
        reasons.append(f"{claimed_sites_count} confirmed online public accounts detected (+{pts} pts)")

    # ExifTool Forensics Findings
    gps_images = [img for img in exif_results if img.get("has_gps")]
    if gps_images:
        pts = min(25, len(gps_images) * 15)
        score += pts
        reasons.append(f"EXIF Geolocation coordinates (GPS) discovered in {len(gps_images)} photos! (+{pts} pts)")

    camera_images = [img for img in exif_results if img.get("camera") and img.get("camera") != "Unknown / Stripped"]
    if camera_images:
        pts = min(15, len(camera_images) * 5)
        score += pts
        reasons.append(f"Physical hardware & camera models identified from EXIF tags (+{pts} pts)")

    # Contact leaks
    emails_count = len(contacts.get("emails", [])) + (1 if github_data and github_data.get("email") else 0)
    if emails_count > 0:
        pts = min(15, emails_count * 5)
        score += pts
        reasons.append(f"{emails_count} public email address(es) directly exposed (+{pts} pts)")

    phones_count = len(contacts.get("phones", []))
    if phones_count > 0:
        pts = min(15, phones_count * 10)
        score += pts
        reasons.append(f"{phones_count} phone number(s) identified (+{pts} pts)")

    # Developer exposure
    if github_data and github_data.get("commit_emails_discovered"):
        score += 10
        reasons.append(f"Commit author emails harvested from Git activity history (+10 pts)")

    score = min(100, score)

    if score >= 75:
        level = "CRITICAL EXPOSURE"
        color = "#ef4444"
        summary = "Extremely high digital footprint. Severe risk of spear-phishing, physical tracking (via GPS), and identity correlation."
    elif score >= 50:
        level = "HIGH EXPOSURE"
        color = "#f97316"
        summary = "Substantial public footprint across multiple services with hardware/metadata signatures and contact exposure."
    elif score >= 25:
        level = "MODERATE EXPOSURE"
        color = "#eab308"
        summary = "Standard public presence with moderate digital footprint. Some identity points discoverable."
    else:
        level = "LOW EXPOSURE"
        color = "#22c55e"
        summary = "Minimal public presence. Profile metadata appears sanitized or limited in scope."

    return {
        "score": score,
        "level": level,
        "color": color,
        "summary": summary,
        "factors": reasons,
    }


# ============================================================================
# Deep OSINT Tool: Keybase Identity & Cryptographic Proofs Hunter
# ============================================================================
def run_keybase_osint(username: str) -> Optional[Dict[str, Any]]:
    """Query Keybase API to uncover cryptographic identity proofs and linked accounts."""
    try:
        url = f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={username}"
        resp = requests.get(url, headers=DEFAULT_HEADERS, timeout=7)
        if resp.status_code == 200:
            data = resp.json()
            them = data.get("them", [])
            if them and them[0]:
                user_obj = them[0]
                profile = user_obj.get("profile", {}) or {}
                proofs_raw = user_obj.get("proofs_summary", {}).get("all", []) or []
                proofs = [
                    {
                        "service": p.get("proof_type", ""),
                        "nametag": p.get("nametag", ""),
                        "service_url": p.get("service_url", ""),
                        "human_url": p.get("human_url", ""),
                    }
                    for p in proofs_raw
                ]
                cryptocurrency = user_obj.get("cryptocurrency_addresses", {}) or {}
                crypto_list = []
                for coin, addrs in cryptocurrency.items():
                    for a in addrs:
                        crypto_list.append(f"{coin.upper()}: {a.get('address', '')}")

                full_name = profile.get("full_name")
                bio = profile.get("bio")
                location = profile.get("location")

                # If there's real information on Keybase
                if full_name or bio or proofs or crypto_list:
                    return {
                        "platform": "Keybase",
                        "username": username,
                        "full_name": full_name,
                        "bio": bio,
                        "location": location,
                        "profile_url": f"https://keybase.io/{username}",
                        "proofs": proofs,
                        "verified_proofs_count": len(proofs),
                        "cryptocurrency_addresses": crypto_list,
                    }
    except Exception as exc:
        logger.debug(f"Keybase OSINT error: {exc}")
    return None


# ============================================================================
# Deep OSINT Tool: Wayback Machine Historical Footprint Prober
# ============================================================================
def check_wayback_machine(url: str) -> Optional[Dict[str, Any]]:
    """Query Internet Archive Wayback Machine to detect historical snapshots."""
    try:
        api_url = f"https://archive.org/wayback/available?url={url}"
        resp = requests.get(api_url, headers=DEFAULT_HEADERS, timeout=6)
        if resp.status_code == 200:
            data = resp.json()
            closest = data.get("archived_snapshots", {}).get("closest")
            if closest and closest.get("available"):
                ts = closest.get("timestamp", "")
                formatted_ts = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts
                return {
                    "url": url,
                    "archive_url": closest.get("url"),
                    "timestamp": formatted_ts,
                    "status": closest.get("status"),
                }
    except Exception:
        pass
    return None


# ============================================================================
# Deep OSINT Tool: Domain & Website IP Geolocation
# ============================================================================
def run_domain_ip_osint(domain_or_url: str) -> Optional[Dict[str, Any]]:
    """Resolve website domain to IP and query public geolocational network info."""
    import socket

    clean_host = domain_or_url
    if "://" in clean_host:
        clean_host = urlparse(clean_host).netloc
    clean_host = clean_host.split(":")[0].strip()

    if not clean_host or clean_host in ("github.com", "twitter.com", "instagram.com", "reddit.com"):
        return None

    try:
        ip = socket.gethostbyname(clean_host)
        # Query public IP geo
        resp = requests.get(f"https://ipapi.co/{ip}/json/", headers=DEFAULT_HEADERS, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "host": clean_host,
                "ip": ip,
                "country": data.get("country_name"),
                "city": data.get("city"),
                "region": data.get("region"),
                "org": data.get("org"),
                "asn": data.get("asn"),
            }
    except Exception:
        pass
    return None


# ============================================================================
# Deep OSINT Tool: SnapIntel (Snapchat Public Intelligence & Bitmoji Forensics)
# ============================================================================
def run_snapintel_osint(username: str) -> Optional[Dict[str, Any]]:
    """Extract public Snapchat Bitmoji 3D avatar, display name, and bio for ExifTool analysis."""
    try:
        url = f"https://www.snapchat.com/add/{username}"
        resp = requests.get(url, headers=DEFAULT_HEADERS, timeout=6)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "html.parser")
            meta_img = soup.find("meta", property="og:image")
            meta_desc = soup.find("meta", property="og:description")
            meta_title = soup.find("meta", property="og:title") or soup.find("title")

            avatar_url = meta_img.get("content") if meta_img else None
            title_text = meta_title.get("content") if hasattr(meta_title, "get") else (meta_title.text if meta_title else "")
            desc_text = meta_desc.get("content") if meta_desc else ""

            # Check if this is an actual user profile
            if avatar_url and "snapchat.com" in avatar_url:
                display_name = title_text.split("on Snapchat")[0].strip() if "on Snapchat" in title_text else title_text.strip()
                return {
                    "platform": "Snapchat",
                    "username": username,
                    "display_name": display_name or username,
                    "bio": desc_text,
                    "avatar_url": avatar_url,
                    "profile_url": url,
                    "snapcode_url": f"https://app.snapchat.com/web/deeplink/snapcode?username={username}&type=SVG",
                }
    except Exception as exc:
        logger.debug(f"SnapIntel error for {username}: {exc}")
    return None


# ============================================================================
# Deep OSINT Tool: Holehe Email Footprint Prober (120+ Platforms)
# ============================================================================
def run_holehe_email_osint(email: str, max_checks: int = 30) -> List[Dict[str, Any]]:
    """Execute Holehe across platforms to identify registered accounts for discovered emails."""
    results: List[Dict[str, Any]] = []
    try:
        import trio
        import httpx
        from holehe.core import get_functions, import_submodules
        from holehe import modules

        all_funcs = get_functions(import_submodules(modules))
        # Prioritize top platforms
        priority = {
            "twitter", "instagram", "discord", "spotify", "github", "snapchat",
            "imgur", "ebay", "pinterest", "wordpress", "gravatar", "aboutme",
            "atlassian", "dropbox", "protonmail", "yahoo", "adobe", "google",
        }
        chosen = [f for f in all_funcs if f.__name__ in priority]
        # Fill remainder up to max_checks
        for f in all_funcs:
            if len(chosen) >= max_checks:
                break
            if f not in chosen:
                chosen.append(f)

        raw_out: List[Dict[str, Any]] = []

        async def _run_holehe():
            async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:
                async with trio.open_nursery() as nursery:
                    for check_fn in chosen:
                        nursery.start_soon(check_fn, email, client, raw_out)

        trio.run(_run_holehe)

        for item in raw_out:
            if item.get("exists") is True:
                results.append({
                    "service": item.get("name", "Unknown").capitalize(),
                    "domain": item.get("domain", ""),
                    "exists": True,
                    "email_recovery": item.get("emailrecovery"),
                    "phone_number": item.get("phoneNumber"),
                })

    except Exception as exc:
        logger.debug(f"Holehe scan error: {exc}")

    return results


# ============================================================================
# OSINT Mapping Tool: Node & Edge Graph Generator
# ============================================================================
def build_osint_mapping_graph(
    usernames: List[str],
    sherlock_results: List[Dict[str, Any]],
    exif_results: List[Dict[str, Any]],
    github_data: Optional[Dict[str, Any]] = None,
    gravatar_data: Optional[Dict[str, Any]] = None,
    keybase_data: Optional[Dict[str, Any]] = None,
    snapchat_data: Optional[Dict[str, Any]] = None,
    contacts: Optional[Dict[str, List[str]]] = None,
    holehe_data: Optional[List[Dict[str, Any]]] = None,
    instagram_data: Optional[Dict[str, Any]] = None,
    breach_data: Optional[Dict[str, Any]] = None,
    phone_data: Optional[Dict[str, Any]] = None,
    socid_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Construct an interactive node-and-link network topology for graph visualization."""
    contacts = contacts or {}
    holehe_data = holehe_data or []
    nodes: List[Dict[str, Any]] = []
    links: List[Dict[str, Any]] = []
    node_ids = set()

    def add_node(node_id: str, label: str, group: str, details: str = "", url: str = ""):
        if node_id not in node_ids:
            node_ids.add(node_id)
            nodes.append({
                "id": node_id,
                "label": label,
                "group": group,
                "details": details,
                "url": url,
            })

    def add_link(source: str, target: str, relationship: str = ""):
        links.append({"source": source, "target": target, "rel": relationship})

    # Central Identity Root
    primary_handle = usernames[0] if usernames else "Target"
    root_id = f"target_{primary_handle}"
    add_node(root_id, f"@{primary_handle}", "target", "Central Investigation Target")

    # Sherlock Claimed Profiles
    claimed = [r for r in sherlock_results if r.get("status") == "claimed"]
    for r in claimed:
        site_id = f"site_{r.get('site', '')}"
        add_node(site_id, r.get("site", "Profile"), "profile", f"Confirmed Public Account: {r.get('url')}", r.get("url", ""))
        add_link(root_id, site_id, "owns_account")

    # ExifTool Images & GPS Geotags
    for idx, img in enumerate(exif_results, 1):
        img_id = f"img_{idx}"
        role = "Avatar" if img.get("is_avatar") else "Media"
        add_node(img_id, f"{img.get('site_name', '')} {role}", "image", f"Camera: {img.get('camera')} • Size: {img.get('dimensions')}", img.get("original_url", ""))

        parent_site = f"site_{img.get('site_name', '')}"
        if parent_site in node_ids:
            add_link(parent_site, img_id, "contains_image")
        else:
            add_link(root_id, img_id, "contains_image")

        # If GPS found, add Geolocation node
        if img.get("has_gps"):
            geo_id = f"geo_{idx}"
            geo_label = f"GPS ({img.get('latitude')}, {img.get('longitude')})"
            add_node(geo_id, geo_label, "location", f"Altitude: {img.get('altitude')} • Google Maps Geotag", img.get("google_maps_url", ""))
            add_link(img_id, geo_id, "geotagged_at")

        # If Camera hardware found, add hardware node
        cam = img.get("camera")
        if cam and cam != "Unknown / Stripped":
            cam_id = f"cam_{re.sub(r'[^a-zA-Z0-9]', '_', cam)}"
            add_node(cam_id, cam, "hardware", "Identified Camera Physical Hardware")
            add_link(img_id, cam_id, "captured_by")

    # Keybase Proofs
    if keybase_data:
        kb_id = "node_keybase"
        add_node(kb_id, "Keybase Proofs", "crypto", "Cryptographically Proven Identity Hub", keybase_data.get("profile_url", ""))
        add_link(root_id, kb_id, "cryptographic_proof")
        for p in keybase_data.get("proofs", []):
            proof_id = f"proof_{p.get('service')}_{p.get('nametag')}"
            add_node(proof_id, f"{p.get('service')}: {p.get('nametag')}", "proof", "Verified Account Proof", p.get("human_url") or "")
            add_link(kb_id, proof_id, "proves")

    # Snapchat Bitmoji (SnapIntel)
    if snapchat_data:
        snap_id = "node_snapchat"
        add_node(snap_id, "Snapchat (Bitmoji)", "social", f"Display: {snapchat_data.get('display_name')}", snapchat_data.get("profile_url", ""))
        add_link(root_id, snap_id, "has_snapchat")

    # Harvested Emails & Holehe Discoveries
    for email in contacts.get("emails", []):
        em_id = f"email_{email}"
        add_node(em_id, email, "email", "Harvested Public Email")
        add_link(root_id, em_id, "associated_email")

        # Link Holehe results to this email
        for h in holehe_data:
            h_id = f"holehe_{h.get('service')}"
            add_node(h_id, f"{h.get('service')} (Registered)", "account_holehe", f"Registered account via Holehe: {h.get('domain')}")
            add_link(em_id, h_id, "registered_on")

    # Instagram OSINT
    if instagram_data:
        ig_id = "node_instagram"
        ig_label = f"Instagram (@{instagram_data.get('username')})"
        ig_details = f"Followers: {instagram_data.get('followers') or '—'} • ID: {instagram_data.get('profile_id') or '—'}"
        add_node(ig_id, ig_label, "social", ig_details, instagram_data.get("profile_url", ""))
        add_link(root_id, ig_id, "has_instagram")

    # Breach Intelligence (Have I Been Pwned)
    if breach_data:
        br_id = "node_breach"
        add_node(br_id, "Breach Leaks (HIBP)", "breach", breach_data.get("risk_level", "BREACH RECORD"), breach_data.get("hibp_url", ""))
        add_link(root_id, br_id, "breach_exposure")

    # Phone Intelligence (PhoneInfoga)
    if phone_data:
        ph_id = "node_phoneinfoga"
        add_node(ph_id, f"PhoneInfoga ({phone_data.get('international')})", "phone", f"Carrier: {phone_data.get('carrier')} • {phone_data.get('location')}")
        add_link(root_id, ph_id, "carrier_intelligence")

    # socid_extractor extracted IDs
    if socid_data:
        for platform, sid in socid_data.items():
            s_id = f"socid_{platform}"
            add_node(s_id, f"ID: {platform}", "proof", f"Extracted Account ID: {sid}")
            add_link(root_id, s_id, "extracted_id")

    # Harvested Phone Numbers
    for phone in contacts.get("phones", []):
        ph_id = f"phone_{phone}"
        add_node(ph_id, phone, "phone", "Harvested International Phone")
        add_link(root_id, ph_id, "associated_phone")

    return {"nodes": nodes, "links": links}


# ============================================================================
# Deep OSINT Tool: Instagram Profile & Toutatis Forensics
# ============================================================================
def run_instagram_osint(username: str) -> Optional[Dict[str, Any]]:
    """Instagram OSINT prober (Toutatis / Osintgram / SoIG public intelligence).
    
    Extracts public Instagram account information, profile pictures for ExifTool,
    follower counts, user IDs, and bio details.
    """
    clean_u = username.lstrip("@").strip()
    profile_url = f"https://www.instagram.com/{clean_u}/"
    result: Dict[str, Any] = {
        "platform": "Instagram",
        "username": clean_u,
        "profile_url": profile_url,
        "full_name": None,
        "bio": None,
        "external_url": None,
        "is_verified": False,
        "followers": None,
        "following": None,
        "posts_count": None,
        "avatar_url": None,
        "profile_id": None,
        "masked_email": None,
        "masked_phone": None,
    }

    try:
        resp = requests.get(
            profile_url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                "Accept-Language": "en-US,en;q=0.9",
            },
            timeout=8,
        )
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "html.parser")
            og_desc = soup.find("meta", property="og:description")
            og_title = soup.find("meta", property="og:title")
            og_img = soup.find("meta", property="og:image")

            if og_img and og_img.get("content"):
                result["avatar_url"] = og_img.get("content")

            if og_desc and og_desc.get("content"):
                desc_text = og_desc.get("content")
                match = re.search(r"([\d,KMkm\.]+)\s+Followers,\s+([\d,KMkm\.]+)\s+Following,\s+([\d,KMkm\.]+)\s+Posts", desc_text)
                if match:
                    result["followers"] = match.group(1)
                    result["following"] = match.group(2)
                    result["posts_count"] = match.group(3)

            if og_title and og_title.get("content"):
                title_content = og_title.get("content")
                if "(@" in title_content:
                    result["full_name"] = title_content.split("(@")[0].strip()
    except Exception as exc:
        logger.debug(f"Instagram public scrape error: {exc}")

    if toutatis:
        try:
            user_id = toutatis.getUserId(clean_u)
            if user_id:
                result["profile_id"] = str(user_id)
        except Exception:
            pass

    if result.get("avatar_url") or result.get("followers") or result.get("full_name") or result.get("profile_id"):
        return result
    return None


# ============================================================================
# Deep OSINT Tool: PhoneInfoga International Phone Forensics
# ============================================================================
def run_phoneinfoga_osint(phone_str: str) -> Optional[Dict[str, Any]]:
    """PhoneInfoga-style phone number reconnaissance framework."""
    if not phonenumbers:
        return None
    try:
        clean_num = re.sub(r"[^\d+]", "", phone_str.strip())
        if not clean_num:
            return None
        if not clean_num.startswith("+"):
            clean_num = "+" + clean_num

        parsed = phonenumbers.parse(clean_num, None)
        if not phonenumbers.is_valid_number(parsed):
            return None

        e164_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        intl_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        nat_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
        
        country_code = parsed.country_code

        geo_location = geocoder.description_for_number(parsed, "en") if geocoder else "Unknown Region"
        carrier_name = carrier.name_for_number(parsed, "en") if carrier else "Unknown / Unassigned"

        num_type = phonenumbers.number_type(parsed)
        type_names = {
            phonenumbers.PhoneNumberType.MOBILE: "Mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
            phonenumbers.PhoneNumberType.TOLL_FREE: "Toll Free",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
            phonenumbers.PhoneNumberType.SHARED_COST: "Shared Cost",
            phonenumbers.PhoneNumberType.VOIP: "VoIP (Virtual Number)",
            phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
            phonenumbers.PhoneNumberType.PAGER: "Pager",
            phonenumbers.PhoneNumberType.UAN: "Universal Access",
            phonenumbers.PhoneNumberType.VOICEMAIL: "VoICEMAIL",
        }
        line_type = type_names.get(num_type, "Standard")
        digits_only = re.sub(r"\D", "", e164_format)
        is_voip = (num_type == phonenumbers.PhoneNumberType.VOIP)
        spam_risk = "Elevated Risk (VoIP / Virtual Number)" if is_voip else "Normal / Low Risk (Standard Carrier Line)"

        dork_links = {
            "google_search": f"https://www.google.com/search?q=%22{quote(e164_format)}%22+OR+%22{quote(intl_format)}%22",
            "whatsapp_chat": f"https://wa.me/{digits_only}",
            "telegram_link": f"https://t.me/+{digits_only}",
            "viber_chat": f"viber://chat?number=%2B{digits_only}",
            "epieos_lookup": f"https://epieos.com/?q={quote(e164_format)}",
            "osint_industries": "https://www.osint.industries/post/osint-phone-number-investigations-how-to-use-phone-osint-tools",
            "osint_ui_lookup": f"https://osint-ui.com/en/tools/phone-number-lookup?phone={quote(e164_format)}",
            "tellows_spam": f"https://www.tellows.com/num/{digits_only}",
            "truecaller_search": f"https://www.truecaller.com/search/global/{digits_only}",
            "syncme_search": f"https://sync.me/search/?number={digits_only}",
            "osm_map": f"https://www.openstreetmap.org/search?query={quote(geo_location)}" if geo_location and geo_location != "Unknown Region" else None,
        }

        return {
            "raw_input": phone_str,
            "e164": e164_format,
            "international": intl_format,
            "national": nat_format,
            "country_code": country_code,
            "location": geo_location or "International",
            "carrier": carrier_name or "Carrier Not Public",
            "line_type": line_type,
            "is_voip": is_voip,
            "spam_risk": spam_risk,
            "is_valid": True,
            "dork_links": dork_links,
        }
    except Exception as exc:
        logger.debug(f"PhoneInfoga error for {phone_str}: {exc}")
    return None


# ============================================================================
# Deep OSINT Tool: Email Data Breach Intelligence (HIBP / MOSINT)
# ============================================================================
def run_email_breach_osint(email: str) -> Dict[str, Any]:
    """Check email compromised status across breach databases (Have I Been Pwned / MOSINT)."""
    clean_email = email.strip().lower()
    q_email = quote(clean_email)
    
    return {
        "email": clean_email,
        "hibp_url": f"https://haveibeenpwned.com/account/{q_email}",
        "dehashed_url": f"https://dehashed.com/search?query={q_email}",
        "leakcheck_url": f"https://leakcheck.io/search?query={q_email}",
        "intelx_url": f"https://intelx.io/?s={q_email}",
        "pastebin_leak_url": f"https://www.google.com/search?q=site:pastebin.com+%22{q_email}%22",
        "risk_level": "ELEVATED RISK - CHECK BREACH REPOSITORIES",
        "summary": f"Target email '{clean_email}' should be checked against HIBP and paste dumps for password reuse.",
        "recommendation": "Perform credential audit and verify multi-factor authentication (MFA) across all services.",
    }


# ============================================================================
# Deep OSINT Tool: Automated Google Dorks Generator (SiteDorks / ReconSpider)
# ============================================================================
def generate_google_dorks(username: str, email: Optional[str] = None) -> List[Dict[str, Any]]:
    """Automate search engine reconnaissance dorks (SiteDorks / ReconSpider / Epieos)."""
    clean_u = username.strip()
    u_quote = quote(f'"{clean_u}"')
    
    dorks = [
        {
            "category": "Document Leaks",
            "title": "Confidential Documents & Spreadsheets",
            "query": f'"{clean_u}" filetype:pdf OR filetype:doc OR filetype:xls OR filetype:xlsx OR filetype:csv',
            "url": f'https://www.google.com/search?q={u_quote}+filetype:pdf+OR+filetype:doc+OR+filetype:xls+OR+filetype:xlsx+OR+filetype:csv',
            "icon": "📄",
        },
        {
            "category": "Developer Credentials",
            "title": "Git Repositories & Exposed API Keys",
            "query": f'site:github.com OR site:gitlab.com "{clean_u}" (filename:.env OR filename:credentials OR filename:config)',
            "url": f'https://www.google.com/search?q=site:github.com+OR+site:gitlab.com+{u_quote}+(filename:.env+OR+filename:credentials+OR+filename:config)',
            "icon": "🔑",
        },
        {
            "category": "Paste & Dump Intelligence",
            "title": "Pastebin, Rentry & Data Dumps",
            "query": f'site:pastebin.com OR site:rentry.co OR site:ghostbin.com OR site:justpaste.it "{clean_u}"',
            "url": f'https://www.google.com/search?q=site:pastebin.com+OR+site:rentry.co+OR+site:ghostbin.com+OR+site:justpaste.it+{u_quote}',
            "icon": "📋",
        },
        {
            "category": "Forums & Social Discussions",
            "title": "Reddit, HackerNews & Medium Footprint",
            "query": f'site:reddit.com OR site:news.ycombinator.com OR site:medium.com "{clean_u}"',
            "url": f'https://www.google.com/search?q=site:reddit.com+OR+site:news.ycombinator.com+OR+site:medium.com+{u_quote}',
            "icon": "💬",
        },
        {
            "category": "Identity Profiling (Epieos)",
            "title": "Google Account & Gaia ID Footprint",
            "query": f'Epieos lookup for {clean_u}',
            "url": f'https://epieos.com/?q={quote(email if email else clean_u)}',
            "icon": "🔍",
        },
    ]

    if email:
        em_quote = quote(f'"{email.strip()}"')
        dorks.append({
            "category": "Credential Breaches",
            "title": "Email Leaks & Password Lists",
            "query": f'"{email}" (password OR leak OR breach OR database OR dump)',
            "url": f'https://www.google.com/search?q={em_quote}+(password+OR+leak+OR+breach+OR+database+OR+dump)',
            "icon": "⚡",
        })

    return dorks


# ============================================================================
# OSINT Framework Interactive Directory Data
# ============================================================================
OSINT_FRAMEWORK_DATA = [
    {
        "category": "Username Reconnaissance",
        "icon": "👤",
        "description": "Multi-platform presence and handle enumeration tools",
        "tools": [
            {"name": "Sherlock", "url": "https://github.com/sherlock-project/sherlock", "desc": "Check username across 480+ platforms"},
            {"name": "WhatsMyName", "url": "https://whatsmyname.app", "desc": "Fast JSON-based username lookup across 500+ services"},
            {"name": "socid_extractor", "url": "https://github.com/soxoj/socid-extractor", "desc": "Extract account IDs from user pages"},
            {"name": "Namechk", "url": "https://namechk.com", "desc": "Check username and domain availability"},
            {"name": "UserSearch", "url": "https://usersearch.org", "desc": "Social network username finder"},
        ],
    },
    {
        "category": "Email & Account Breaches",
        "icon": "📧",
        "description": "Account registration probers and leak databases",
        "tools": [
            {"name": "Holehe", "url": "https://github.com/megadose/holehe", "desc": "Checks email registration on 120+ platforms"},
            {"name": "Have I Been Pwned", "url": "https://haveibeenpwned.com", "desc": "Check if an email has been exposed in data breaches"},
            {"name": "Epieos", "url": "https://epieos.com", "desc": "Google Account, Gaia ID, reviews & photos without notifying"},
            {"name": "Hunter.io", "url": "https://hunter.io", "desc": "Corporate email domain patterns and employee contacts"},
            {"name": "MOSINT", "url": "https://github.com/alpkeskin/mosint", "desc": "Automated email OSINT framework"},
            {"name": "DeHashed", "url": "https://dehashed.com", "desc": "Compromised credential asset search engine"},
        ],
    },
    {
        "category": "Social Media Intelligence (SOCMINT)",
        "icon": "🌐",
        "description": "Deep extraction from Instagram, Snapchat, Reddit & TikTok",
        "tools": [
            {"name": "Toutatis", "url": "https://github.com/megadose/toutatis", "desc": "Extracts Instagram account IDs and public info"},
            {"name": "Osintgram", "url": "https://github.com/Datalux/Osintgram", "desc": "Collect and analyze Instagram profile data"},
            {"name": "SnapIntel", "url": "https://www.snapchat.com", "desc": "Snapchat public profile & Bitmoji forensics"},
            {"name": "Instaloader", "url": "https://instaloader.github.io", "desc": "Instagram profile and metadata archiving"},
            {"name": "Social Analyzer", "url": "https://github.com/qeeqbox/social-analyzer", "desc": "Profile analysis across 1000+ social sites"},
        ],
    },
    {
        "category": "Phone Number & Caller Intelligence",
        "icon": "📞",
        "description": "International phone lookup, carrier, line-type, messaging & spam risk",
        "tools": [
            {"name": "PhoneInfoga", "url": "https://github.com/sundowndev/phoneinfoga", "desc": "Information gathering framework for international phone numbers"},
            {"name": "OSINT Industries", "url": "https://www.osint.industries/post/osint-phone-number-investigations-how-to-use-phone-osint-tools", "desc": "Scans 100s of online services, social networks, and breach databases"},
            {"name": "Epieos Phone", "url": "https://epieos.com", "desc": "Pivots from phone number to uncover linked Google accounts, Gaia IDs & reviews"},
            {"name": "PhoneIntel", "url": "https://github.com/phoneintel/phoneintel", "desc": "Validation, Spam/Tellows risk checks, carrier lookups & OSM mapping"},
            {"name": "OSINT Phone Lookup", "url": "https://osint-ui.com/en/tools/phone-number-lookup", "desc": "Browser-based analyzer for line type, carrier, and data leak exposure"},
            {"name": "Ignorant", "url": "https://github.com/megadose/ignorant", "desc": "Checks if phone number is registered on online services (Instagram, Snapchat, Amazon)"},
            {"name": "TrueCaller", "url": "https://www.truecaller.com", "desc": "Global caller ID, business profiles and directory search"},
            {"name": "Sync.me", "url": "https://sync.me", "desc": "Caller ID and social profile matching"},
        ],
    },
    {
        "category": "Geolocation, Satellite & Scene Intelligence",
        "icon": "🌍",
        "description": "AI scene recognition, IP tracking, satellite imagery & live camera feeds",
        "tools": [
            {"name": "Geospy", "url": "https://geospy.ai", "desc": "AI-based visual geolocation from photos (analyzing architecture, landscape & sky)"},
            {"name": "GhostTrack", "url": "https://sourceforge.net/projects/ghosttrack.mirror/", "desc": "CLI tool for IP geolocation, phone number analysis, and username reconnaissance"},
            {"name": "OSIRIS", "url": "https://github.com/theblackcat102/OSIRIS", "desc": "Aggregates live public cameras, aircraft, satellite feeds & global events"},
            {"name": "Max Intel", "url": "https://maxintel.org", "desc": "Suite featuring over 85 free OSINT tools for identity, domain & geolocation"},
            {"name": "ExifTool", "url": "https://exiftool.org", "desc": "Read and write image/video metadata & GPS coordinates"},
            {"name": "DualMaps", "url": "https://www.dualmaps.com", "desc": "Synchronized combined view of Google Maps, Street View, and Aerial Imagery"},
            {"name": "Mapillary", "url": "https://www.mapillary.com", "desc": "Street-level imagery platform powered by computer vision"},
            {"name": "Google Earth", "url": "https://earth.google.com", "desc": "3D satellite imagery and geospatial analysis platform"},
            {"name": "IPWho.is", "url": "https://ipwho.is", "desc": "Fast IP geolocation, ISP lookup, ASN data, and network intelligence"},
            {"name": "Photon", "url": "https://github.com/s0md3v/Photon", "desc": "Incredibly fast crawler designed for OSINT and endpoint mapping"},
        ],
    },
    {
        "category": "Image, Video & Visual Forensics",
        "icon": "📷",
        "description": "Metadata extraction, reverse image search and geotag analysis",
        "tools": [
            {"name": "Google Lens", "url": "https://lens.google.com", "desc": "Visual reverse search and object recognition"},
            {"name": "Yandex Images", "url": "https://yandex.com/images", "desc": "High accuracy facial and reverse image search"},
            {"name": "TinEye", "url": "https://tineye.com", "desc": "Reverse image search and duplicate tracking"},
            {"name": "FotoForensics", "url": "https://fotoforensics.com", "desc": "Error Level Analysis (ELA) for image tampering"},
        ],
    },
    {
        "category": "Domain, IP & Network Recon",
        "icon": "🛡️",
        "description": "Infrastructure, DNS and exposed device search engines",
        "tools": [
            {"name": "Shodan", "url": "https://www.shodan.io", "desc": "Search engine for Internet-connected devices"},
            {"name": "Censys", "url": "https://censys.io", "desc": "Attack surface mapping and certificates"},
            {"name": "Subfinder", "url": "https://github.com/projectdiscovery/subfinder", "desc": "Fast passive subdomain enumeration"},
            {"name": "Findomain", "url": "https://github.com/Findomain/Findomain", "desc": "Subdomain discovery tool"},
            {"name": "Wayback Machine", "url": "https://archive.org/web/", "desc": "Historical internet snapshots and archives"},
        ],
    },
]


