"""
Cross-Platform Entity Resolution
================================
Merged module (former social_finder + social_linker): probes a username
across online platforms and links confirmed profiles into a single entity.

  - input  : username
  - step 1 : probe the username across the configured platforms
  - step 2 : link the confirmed profiles into a single entity and score the
             resolution with a heuristic confidence value

Platform quirks (calibrated by live probing): LinkedIn returns HTTP 999
(blocked); Twitch/Steam/Telegram serve "soft 404" pages; Reddit is probed
through old.reddit.com and TikTok through its oEmbed API; YouTube needs a
consent cookie; Instagram/Spotify/Pinterest/Snapchat return 200 for missing
profiles - those are reported as "unknown" rather than confirmed, so they
do not inflate the confidence score.
"""

import re
from concurrent.futures import ThreadPoolExecutor

import requests

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

# Maximum page bytes read when looking for soft-404 markers.
# Bounding the read keeps memory/time in check on JS-heavy sites
# (X, Instagram, Twitch can serve 1MB+ of HTML for real profiles).
MAX_PAGE_BYTES = 512_000

# Per-site extra config used by check_site:
#   cookies          - extra cookies needed to bypass consent walls (YouTube)
#   api_url          - JSON endpoint that answers profile existence
#                      (TikTok oEmbed: 200 = exists, 400/404 = missing)
#   follow_redirects - follow 3xx (Wikipedia case-canonicalization)
SOCIAL_MEDIA = [
    {"name": "GitHub", "url": "https://github.com/{username}"},
    {"name": "Instagram", "url": "https://www.instagram.com/{username}/"},
    {"name": "X", "url": "https://x.com/{username}"},
    {"name": "Reddit", "url": "https://old.reddit.com/user/{username}"},
    {"name": "Facebook", "url": "https://www.facebook.com/{username}"},
    {
        "name": "YouTube",
        "url": "https://www.youtube.com/@{username}",
        "cookies": {"SOCS": "CAI"},
    },
    {"name": "Telegram", "url": "https://t.me/{username}"},
    {
        "name": "TikTok",
        "url": "https://www.tiktok.com/@{username}",
        "api_url": "https://www.tiktok.com/oembed?url=https://www.tiktok.com/@{username}",
    },
    {"name": "Pinterest", "url": "https://www.pinterest.com/{username}/"},
    {"name": "Steam", "url": "https://steamcommunity.com/id/{username}"},
    {"name": "Twitch", "url": "https://www.twitch.tv/{username}"},
    {"name": "Linktree", "url": "https://linktr.ee/{username}"},
    {"name": "LinkedIn", "url": "https://www.linkedin.com/in/{username}"},
    {"name": "Medium", "url": "https://medium.com/@{username}"},
    {"name": "Mastodon", "url": "https://mastodon.social/@{username}"},
    {"name": "Flickr", "url": "https://www.flickr.com/people/{username}"},
    {"name": "DeviantArt", "url": "https://www.deviantart.com/{username}"},
    {"name": "Behance", "url": "https://www.behance.net/{username}"},
    {"name": "Dribbble", "url": "https://dribbble.com/{username}"},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{username}"},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{username}"},
    {"name": "Snapchat", "url": "https://www.snapchat.com/add/{username}"},
    {"name": "VK", "url": "https://vk.com/{username}"},
    {
        "name": "Wikipedia",
        "url": "https://en.wikipedia.org/wiki/User:{username}",
        "follow_redirects": True,
    },
]

REDIRECT_CODES = (301, 302, 303, 307, 308)

# Soft-404 behaviour per site, calibrated by live probing:
#   missing_markers  - page text fragments that mean "profile not found"
#   title_markers    - <title> fragments meaning "profile not found" (Telegram)
#   username_in_page - found profiles must contain the username (Twitch)
#   soft404_possible - site returns 200 for missing profiles AND for found
#                      ones (JS shells), so a 200 can never be trusted
SOFT_404_CHECKS = {
    "Steam": {"missing_markers": ["the specified profile could not be found"]},
    "Twitch": {"username_in_page": True},
    "Pinterest": {"soft404_possible": True},
    "Instagram": {"soft404_possible": True},
    "Telegram": {
        "title_markers": ["telegram: contact"],
        "missing_markers": ["this page doesn't seem to exist"],
    },
    "Spotify": {"soft404_possible": True},
    "Facebook": {
        "missing_markers": ["this content isn't available"],
        "soft404_possible": True,
    },
    "YouTube": {"missing_markers": ["this page isn't available"]},
    "X": {"missing_markers": ["this account doesn't exist"]},
    "VK": {"missing_markers": ["page not found"]},
    "Medium": {"missing_markers": ["page not found"]},
    "Mastodon": {"missing_markers": ["page not found", "does not exist"]},
    "Wikipedia": {"missing_markers": ["does not have a user page"]},
    "Snapchat": {"soft404_possible": True},
}


def _page_soft404(name, username, page_text):
    checks = SOFT_404_CHECKS.get(name)
    if not checks:
        return False
    low = page_text.lower()
    if checks.get("missing_markers"):
        if any(marker in low for marker in checks["missing_markers"]):
            return True
    if checks.get("title_markers"):
        title = re.search(r"<title[^>]*>(.*?)</title>", page_text, re.S | re.I)
        if title and any(marker in title.group(1).lower() for marker in checks["title_markers"]):
            return True
    if checks.get("username_in_page"):
        # Word-boundary match: avoids false soft-404s when the username
        # is a substring of unrelated words (e.g. "tim" inside "time").
        if not re.search(rf"(?<!\w){re.escape(username.lower())}(?!\w)", low):
            return True
    return False


def _get(url, timeout, cookies=None, follow_redirects=False, max_bytes=None):
    """GET with bounded body read; returns (Response, decoded text)."""
    resp = requests.get(
        url,
        headers={"User-Agent": USER_AGENT},
        timeout=timeout,
        allow_redirects=follow_redirects,
        stream=True,
        cookies=cookies or {},
    )
    try:
        if max_bytes is None:
            return resp, resp.content.decode("utf-8", errors="replace")
        chunks = []
        total = 0
        for chunk in resp.iter_content(chunk_size=16_384):
            if not chunk:
                continue
            chunks.append(chunk)
            total += len(chunk)
            if total >= max_bytes:
                break
        return resp, b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        resp.close()


def check_site(name, url, username="", timeout=10, site_config=None):
    """Check whether a profile exists at url.

    Returns a dict with: exists (True/False/None), status_code, tag (a
    human-readable reason for the outcome) and note (details)."""
    cfg = site_config or {}
    result = {"name": name, "url": url}

    api_url = cfg.get("api_url")
    if api_url:
        api_url = api_url.format(username=username)
        result["api_url"] = api_url
        try:
            aresp, _ = _get(api_url, timeout, cookies=cfg.get("cookies"))
        except requests.RequestException as exc:
            result["exists"] = None
            result["status_code"] = "error"
            result["tag"] = "ERROR (request failed)"
            result["note"] = f"API request failed: {exc}"
            return result
        code = aresp.status_code
        result["status_code"] = code
        if code == 200:
            result["exists"] = True
            result["tag"] = "FOUND (API)"
            result["note"] = "Profile found (API)"
        elif code in (400, 404):
            result["exists"] = False
            result["tag"] = "NOT FOUND (API)"
            result["note"] = "Profile not found (API)"
        else:
            result["exists"] = None
            result["tag"] = f"UNKNOWN (API HTTP {code})"
            result["note"] = f"API returned HTTP {code} - existence unknown"
        return result

    try:
        resp, page_text = _get(
            url,
            timeout,
            cookies=cfg.get("cookies"),
            follow_redirects=cfg.get("follow_redirects", False),
            max_bytes=MAX_PAGE_BYTES,
        )
    except requests.RequestException as exc:
        result["exists"] = None
        result["status_code"] = "error"
        result["tag"] = "ERROR (request failed)"
        result["note"] = f"Request failed: {exc}"
        return result

    status = resp.status_code
    result["status_code"] = status

    if status == 200:
        soft404 = _page_soft404(name, username, page_text)
        if soft404:
            result["exists"] = False
            result["tag"] = "NOT FOUND (soft 404)"
            result["note"] = "Soft 404 - profile not found despite HTTP 200"
        elif SOFT_404_CHECKS.get(name, {}).get("soft404_possible"):
            result["exists"] = None
            result["tag"] = "UNKNOWN (200 ambiguous)"
            result["note"] = "HTTP 200 but this site may return 200 for missing profiles - verify manually"
        else:
            result["exists"] = True
            result["tag"] = "FOUND"
            result["note"] = "Profile found"
    elif status == 404:
        result["exists"] = False
        result["tag"] = "NOT FOUND (404)"
        result["note"] = "Profile not found"
    elif status == 410:
        result["exists"] = False
        result["tag"] = "NOT FOUND (410 - removed)"
        result["note"] = "Profile removed (Gone)"
    elif status in REDIRECT_CODES:
        location = resp.headers.get("Location", "")
        result["exists"] = None
        result["redirect_to"] = location
        if "login" in location.lower() or "authwall" in location.lower():
            result["tag"] = "UNKNOWN (login wall)"
            result["note"] = "Redirected to login wall - existence unknown without session"
        else:
            result["tag"] = "UNKNOWN (redirect)"
            result["note"] = f"Redirected to {location} - existence unknown"
    elif status == 403:
        result["exists"] = None
        result["tag"] = "UNKNOWN (bot protection)"
        result["note"] = "Blocked by bot protection (403)"
    elif status == 999:
        result["exists"] = None
        result["tag"] = "UNKNOWN (blocked by site)"
        result["note"] = "Blocked by site (LinkedIn 999)"
    else:
        result["exists"] = None
        result["tag"] = f"UNKNOWN (HTTP {status})"
        result["note"] = f"Unexpected HTTP {status}"
    return result


def find_social(username, sites=None):
    sites = sites or SOCIAL_MEDIA
    results = {}
    for site in sites:
        url = site["url"].format(username=username)
        results[site["name"]] = check_site(
            site["name"], url, username=username, site_config=site
        )
    return results


def _probe(username: str, platforms, timeout: int) -> list:
    """Probe a username against the given platform list (parallel)."""
    def probe_one(site):
        url = site["url"].format(username=username)
        return check_site(
            site["name"], url, username=username, timeout=timeout, site_config=site
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        return list(executor.map(probe_one, platforms))


def resolve_entity(username=None, platforms=None, timeout=10) -> dict:
    """
    Link a username to profiles across platforms.

    - username  : the username to search for (required)
    - platforms : optional list of platform names to restrict the scan
    - timeout   : per-request HTTP timeout in seconds

    Returns a dict with the resolved username, all probe results, the linked
    profile count and a heuristic confidence score (0-95%).
    """
    if not username:
        return {"error": "Provide a username to search for."}

    username = username.lower().strip()
    if not username:
        return {"error": "Provide a username to search for."}

    # Validate / filter the platform list
    if platforms:
        known = {site["name"] for site in SOCIAL_MEDIA}
        unknown = [p for p in platforms if p not in known]
        if unknown:
            return {"error": f"Unknown platform(s): {', '.join(unknown)}. "
                             f"Known: {', '.join(sorted(known))}"}
        platform_list = [site for site in SOCIAL_MEDIA if site["name"] in platforms]
    else:
        platform_list = list(SOCIAL_MEDIA)

    # Probe the username across the platform list
    best_candidate = username
    best_probes = _probe(username, platform_list, timeout)

    confirmed = [p for p in best_probes if p.get("exists") is True]
    unknown = [p for p in best_probes if p.get("exists") is None]

    # Heuristic confidence: 60% base for one confirmed profile, +10% per
    # additional profile (cap 90%), +5% for an explicit username search
    confidence = 0
    if confirmed:
        confidence = min(60 + 10 * (len(confirmed) - 1), 90)
        confidence = min(confidence + 5, 95)

    if confirmed:
        summary = (f"Resolved '{best_candidate}' - linked to {len(confirmed)} "
                   f"platform(s) (confidence {confidence}%).")
    else:
        summary = f"No profiles found for username: {username}."

    return {
        "username": username,
        "resolved_username": best_candidate,
        "profiles": best_probes,
        "profile_count": len(confirmed),
        "unverified_count": len(unknown),
        "confidence": confidence,
        "summary": summary,
    }


def _print_site(p):
    """Print one probe result with a specific, human-readable outcome tag."""
    tag = p.get("tag", "UNKNOWN")
    print(f"  [{tag}]  {p['name']:<11} {p['url']}")
    print(f"              HTTP {p.get('status_code')} - {p.get('note')}")


def main():
    print("[*] Cross-platform social media search")
    username = input("Enter the username to investigate: ").strip()

    result = resolve_entity(username=username)

    if "error" in result:
        print(f"[-] Error: {result['error']}")
        return

    print(f"\n[+] {result['summary']}")
    print("-" * 78)
    print("Sites checked:")
    for p in result["profiles"]:
        _print_site(p)
    print("-" * 78)


if __name__ == "__main__":
    main()
