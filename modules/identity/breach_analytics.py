"""
Breach Analytics Module
=======================
Fetches detailed breach analytics for an email address from the free
XposedOrNot API (https://www.xposedornot.com), the analytics sibling of
breach_checker.py - same service, richer per-email statistics.

API endpoint : https://api.xposedornot.com/v1/breach-analytics?email={email}
Authentication: none required for the free tier

Response structure (verified live, 2026):
- BreachMetrics  : risk score, password strength, industry breakdown,
                   year-wise history, exposed-data tree
- BreachesSummary: "site" field holding a ";"-separated list of breach names
- ExposedBreaches: "breaches_details" list with one record per breach
- ExposedPastes / PasteMetrics / PastesSummary: paste exposure data (null/0
                   when the email was never found in pastes)

IMPORTANT - not-found detection: unlike the /v1/check-email endpoint, which
replies with {"Error":"Not found"}, this endpoint replies with HTTP 200 and
BreachMetrics/ExposedBreaches set to null. Both null-checks are required.

Known quirk: category names in the exposed-data tree contain emoji
(e.g. "U+1F512 Security Practices"). Python handles them fine in data,
but printing them on a legacy Windows console (cp1252) raises
UnicodeEncodeError - the CLI block strips them for display.
"""

import re
import requests

BASE_URL = "https://api.xposedornot.com/v1/breach-analytics"

USER_AGENT = "OSINTBot-BreachAnalytics/1.0"

SERVER_ERROR_CODES = (502, 503)

# Approximate labels for the 4-letter industry codes used by the API.
# Authoritative full names are present in each record of ExposedBreaches.
INDUSTRY_NAMES = {
    "elec": "Electronics", "misc": "Miscellaneous", "mini": "Mining",
    "musi": "Music", "manu": "Manufacturing", "ener": "Energy",
    "news": "News/Media", "ente": "Entertainment", "hosp": "Hospitality",
    "heal": "Health", "food": "Food", "phar": "Pharmaceuticals",
    "educ": "Education", "cons": "Construction", "agri": "Agriculture",
    "tele": "Telecommunications", "info": "Information Technology",
    "tran": "Transportation", "aero": "Aerospace", "fina": "Financial",
    "reta": "Retail", "nonp": "Non-profit", "govt": "Government",
    "spor": "Sports", "envi": "Environment",
}

EMOJI_RE = re.compile(r"[\U0001F000-\U0001FAFF\u2600-\u27BF\uFE0F]")


def _flatten_industries(raw):
    """Flatten the triple-nested [ [ ["code", count], ... ] ] structure."""
    industries = []
    for group in raw or []:
        for pair in group:
            if isinstance(pair, list) and len(pair) >= 2:
                code = pair[0]
                industries.append({"code": code, "count": pair[1]})
    industries.sort(key=lambda x: x["count"], reverse=True)
    return industries


def _parse_yearwise(raw):
    """Convert [{"y2007":0,"y2015":1,...}] into a sorted list of {year, count}."""
    years = []
    for key, count in (raw or [{}])[0].items():
        if key.startswith("y") and count:
            try:
                years.append({"year": int(key[1:]), "count": count})
            except ValueError:
                continue
    years.sort(key=lambda x: x["year"])
    return years


def _parse_exposed_data(raw):
    """
    Walk the exposed-data tree. Nodes holding "children" are branches
    (root has none, level-2 categories have names), nodes without
    children are leaves with a "name" (prefixed "data_") and a "value".
    """
    categories = {}
    order = []

    def walk(nodes, category):
        for node in nodes or []:
            children = node.get("children")
            name = node.get("name", "")
            if children:
                walk(children, name)
            else:
                item = name[len("data_"):] if name.startswith("data_") else name
                if category not in categories:
                    categories[category] = []
                    order.append(category)
                categories[category].append({"name": item, "count": node.get("value", 0)})

    walk(raw, "")
    return [{"category": cat, "items": categories[cat]} for cat in order]


def not_found_result(email: str) -> dict:
    """Shared result shape for emails with no breach analytics data."""
    return {
        "email": email,
        "found": False,
        "breach_count": 0,
        "risk": None,
        "summary": "No breach analytics available for this email.",
    }


def run(email: str, timeout: int = 10) -> dict:
    """
    Queries the XposedOrNot breach-analytics API for the given email and
    returns risk, password-strength, industry, year-wise and per-breach
    statistics. Returns a dict with an "error" key on any failure.
    """
    clean_email = email.lower().strip()
    if "@" not in clean_email:
        return {"error": "Invalid email address format."}

    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}

    try:
        response = requests.get(
            BASE_URL, params={"email": clean_email}, headers=headers, timeout=timeout
        )
    except requests.RequestException as e:
        return {"error": f"Failed to connect to XposedOrNot API: {e}"}

    if response.status_code == 404:
        return not_found_result(clean_email)
    if response.status_code == 401:
        return {"error": "Unauthorized - invalid or missing API key."}
    if response.status_code == 429:
        return {"error": "Rate limit exceeded on XposedOrNot API."}
    if response.status_code in SERVER_ERROR_CODES:
        return {"error": "XposedOrNot server error, please retry later."}

    try:
        response.raise_for_status()
    except requests.RequestException as e:
        return {"error": f"XposedOrNot API returned HTTP {response.status_code}: {e}"}

    try:
        data = response.json()
    except ValueError:
        return {"error": "Invalid JSON response from XposedOrNot API."}

    # The API replies 200 with null sections when no data exists
    metrics = data.get("BreachMetrics")
    breaches = data.get("ExposedBreaches")
    if metrics is None or breaches is None:
        return not_found_result(clean_email)

    # --- Risk ---
    risk_raw = metrics.get("risk") or []
    risk = None
    if risk_raw:
        risk = {"label": risk_raw[0].get("risk_label"), "score": risk_raw[0].get("risk_score")}

    # --- Breaches ---
    breach_records = breaches.get("breaches_details") or []
    sites_raw = data.get("BreachesSummary", {}).get("site", "")
    sites = sorted({s for s in sites_raw.split(";") if s})

    # --- Password strength ---
    pw_raw = metrics.get("passwords_strength") or [{}]
    password_strength = {
        "easy_to_crack": pw_raw[0].get("EasyToCrack", 0),
        "plain_text": pw_raw[0].get("PlainText", 0),
        "strong_hash": pw_raw[0].get("StrongHash", 0),
        "unknown": pw_raw[0].get("Unknown", 0),
    }

    # --- Aggregates ---
    industries = _flatten_industries(metrics.get("industry"))
    years = _parse_yearwise(metrics.get("yearwise_details"))
    exposed_data = _parse_exposed_data(metrics.get("xposed_data"))
    total_records = sum(b.get("xposed_records") or 0 for b in breach_records)
    pastes = data.get("ExposedPastes")
    paste_count = data.get("PastesSummary", {}).get("cnt", 0)

    # --- Human-readable summary ---
    parts = [f"{len(breach_records)} breach(es)"]
    if risk:
        parts.append(f"risk {risk['label']} ({risk['score']}/100)")
    if total_records:
        parts.append(f"{total_records:,} exposed records".replace(",", " "))
    if any(password_strength.values()):
        pw = password_strength
        parts.append(
            f"passwords: {pw['easy_to_crack']} easy-to-crack, "
            f"{pw['plain_text']} plaintext, {pw['strong_hash']} hashed"
        )
    if paste_count:
        parts.append(f"{paste_count} paste exposure(s)")

    return {
        "email": clean_email,
        "found": True,
        "breach_count": len(breach_records),
        "sites": sites,
        "risk": risk,
        "password_strength": password_strength,
        "industries": industries,
        "years": years,
        "exposed_data": exposed_data,
        "total_exposed_records": total_records,
        "paste_count": paste_count,
        "breaches": breach_records,
        "summary": " | ".join(parts),
    }


def main():
    email = input("Enter the email address to analyze: ").strip()
    if not email:
        print("[-] Email cannot be blank.")
        return

    result = run(email)

    if "error" in result:
        print(f"[-] Error: {result['error']}")
        return

    print(f"\n[*] Breach analytics for: {result['email']}")
    print("-" * 60)
    if not result["found"]:
        print(result["summary"])
        return

    risk = result["risk"]
    if risk:
        print(f"Risk:       {risk['label']} ({risk['score']}/100)")
    print(f"Breaches:   {result['breach_count']}")
    if result["sites"]:
        print(f"Sites:      {', '.join(result['sites'][:10])}" + ("..." if len(result["sites"]) > 10 else ""))
    pw = result["password_strength"]
    print(f"Passwords:  {pw['easy_to_crack']} easy-to-crack | {pw['plain_text']} plaintext | {pw['strong_hash']} hashed | {pw['unknown']} unknown")

    if result["industries"]:
        print("\nIndustries (top 5):")
        for ind in result["industries"][:5]:
            label = INDUSTRY_NAMES.get(ind["code"], ind["code"])
            print(f"  - {label}: {ind['count']}")

    if result["years"]:
        print("\nYear-wise exposure:")
        print("  " + ", ".join(f"{y['year']}:{y['count']}" for y in result["years"]))

    if result["exposed_data"]:
        print("\nExposed data types:")
        for cat in result["exposed_data"]:
            label = EMOJI_RE.sub("", cat["category"]).strip()
            items = ", ".join(f"{i['name']} x{i['count']}" for i in cat["items"])
            print(f"  - {label}: {items}")

    if result["breaches"]:
        print("\nBreach details (first 5):")
        for b in result["breaches"][:5]:
            print(f"  - {b.get('breach')} ({b.get('xposed_date') or '?'}, "
                  f"{b.get('xposed_records') or 0:,} records)".replace(",", " "))
            if b.get("details"):
                print(f"    {b['details']}")

    print(f"\nSummary: {result['summary']}")
    print("-" * 60)


if __name__ == "__main__":
    main()
