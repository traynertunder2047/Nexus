import requests

#working, exception Linkedin that return 999 as "Blocked and twitch, steam that return soft 404"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

SOCIAL_MEDIA = [
    {"name": "GitHub", "url": "https://github.com/{username}"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{username}/"},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{username}"},
    {"name": "Steam", "url": "https://steamcommunity.com/id/{username}"},
    {"name": "Twitch", "url": "https://www.twitch.tv/{username}"},
    {"name": "Linktree", "url": "https://linktr.ee/{username}"},
    {"name": "LinkedIn", "url": "https://www.linkedin.com/in/{username}"},
]

REDIRECT_CODES = (301, 302, 303, 307, 308)

SOFT_404_CHECKS = {
    "Steam": {"missing_markers": ["the specified profile could not be found"]},
    "Twitch": {"username_in_page": True},
    "Pinterest": {"soft404_possible": True},
}


def _page_soft404(name, username, page_text):
    checks = SOFT_404_CHECKS.get(name)
    if not checks:
        return False
    low = page_text.lower()
    if checks.get("missing_markers"):
        if any(marker in low for marker in checks["missing_markers"]):
            return True
    if checks.get("username_in_page"):
        if username.lower() not in low:
            return True
    return False


def check_site(name, url, username="", timeout=10):
    result = {"name": name, "url": url}
    try:
        resp = requests.get(
            url,
            headers = {"User-Agent": USER_AGENT},
            timeout = timeout,
            allow_redirects = False,
        )
    except requests.RequestException as exc:
        result["exists"] = None
        result["status_code"] = "error"
        result["note"] = f"Request failed: {exc}"
        return result

    status = resp.status_code
    result["status_code"] = status

    if status == 200:
        soft404 = _page_soft404(name, username, resp.text)
        if soft404:
            result["exists"] = False
            result["note"] = "Soft 404 - profile not found despite HTTP 200"
        elif SOFT_404_CHECKS.get(name, {}).get("soft404_possible"):
            result["exists"] = None
            result["note"] = "HTTP 200 but this site may return 200 for missing profiles - verify manually"
        else:
            result["exists"] = True
            result["note"] = "Profile found"
    elif status == 404:
        result["exists"] = False
        result["note"] = "Profile not found"
    elif status in REDIRECT_CODES:
        location = resp.headers.get("Location", "")
        result["exists"] = None
        result["redirect_to"] = location
        if "login" in location.lower() or "authwall" in location.lower():
            result["note"] = "Redirected to login wall - existence unknown without session"
        else:
            result["note"] = f"Redirected to {location} - existence unknown"
    elif status == 403:
        result["exists"] = None
        result["note"] = "Blocked by bot protection (403)"
    elif status == 999:
        result["exists"] = None
        result["note"] = "Blocked by site (LinkedIn 999)"
    else:
        result["exists"] = None
        result["note"] = f"Unexpected HTTP {status}"
    return result


def find_social(username, sites=None):
    sites = sites or SOCIAL_MEDIA
    results = {}
    for site in sites:
        url = site["url"].format(username=username)
        results[site["name"]] = check_site(site["name"], url, username=username)
    return results


def _print_results(username, results):
    print(f"\n[*] Social media scan for username: {username}")
    print("-" * 60)
    for name, data in results.items():
        status = data["status_code"]
        if data["exists"] is True:
            flag = f"[FOUND]    {status}"
        elif data["exists"] is False:
            flag = f"[NOT FOUND]{status}"
        else:
            flag = f"[UNKNOWN]  {status}"
        print(f"{flag}  {name:<10} -> {data['url']}")
        print(f"             {data['note']}")
    print("-" * 60)


def main():
    username = input("Enter the username to investigate: ").strip()
    if not username:
        print("[-] Username cannot be blank.")
        return
    _print_results(username, find_social(username))


if __name__ == "__main__":
    main()
