"""
Breach Checker Module
=====================
Checks whether an email address appears in known data breaches by querying
the free XposedOrNot API (https://www.xposedornot.com) - a free OSINT service
that indexes breached email addresses (a continuation of the classic
"Have I Been Pwned" style services).

API endpoint : https://api.xposedornot.com/v1/check-email/{email}
Authentication: none required for the free tier
Found reply : HTTP 200 -> {"status":"success","email":"...","breaches":[["Breach1","Breach2",...]]}
Not found  : HTTP 200 -> {"Error":"Not found","email":null}
              (official docs claim HTTP 404, but the live API actually
              replies 200 with the Error field - handled both ways below)

The "breaches" field is a NESTED list of lists, so it is flattened and
de-duplicated before being returned to the caller.
"""

import requests

# Free tier endpoint, no API key needed (Plus API v3 uses an x-api-key header)
BASE_URL = "https://api.xposedornot.com/v1/check-email/{email}"

USER_AGENT = "OSINTBot-BreachChecker/1.0"

SERVER_ERROR_CODES = (502, 503)


def not_found_result(email: str) -> dict:
    """Shared result shape for emails with no breach history."""
    return {
        "email": email,
        "breached": False,
        "breach_count": 0,
        "breaches": [],
        "summary": "No breaches found for this email.",
    }


def run(email: str, timeout: int = 10) -> dict:
    """
    Queries the XposedOrNot free API for the given email address and returns
    the list of data breaches it appears in (if any), plus a human-readable
    summary. Returns a dict with an "error" key on any failure.
    """
    clean_email = email.lower().strip()
    if "@" not in clean_email:
        return {"error": "Invalid email address format."}

    url = BASE_URL.format(email=clean_email)
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }

    try:
        response = requests.get(url, headers=headers, timeout=timeout)
    except requests.RequestException as e:
        return {"error": f"Failed to connect to XposedOrNot API: {e}"}

    # Specific status codes first, so we can give accurate error messages
    if response.status_code == 404:
        # Defensive: docs say "no data found" returns 404 on some setups
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

    # Live API replies HTTP 200 with {"Error":"Not found","email":null}
    # when the email has no breach history - check the body, not just the code
    if data.get("Error") is not None or data.get("status") == "not found":
        return not_found_result(clean_email)

    if data.get("status") != "success":
        return {"error": f"Unexpected API response: {data}"}

    # Flatten the nested list of lists and de-duplicate, keeping order
    seen = set()
    breach_names = []
    for group in data.get("breaches", []):
        for name in group:
            if name not in seen:
                seen.add(name)
                breach_names.append(name)

    if not breach_names:
        return not_found_result(clean_email)

    return {
        "email": clean_email,
        "breached": True,
        "breach_count": len(breach_names),
        "breaches": breach_names,
        "summary": (
            f"Found in {len(breach_names)} data breach(es): "
            f"{', '.join(breach_names)}"
        ),
    }


def main():
    email = input("Enter the email address to check: ").strip()
    if not email:
        print("[-] Email cannot be blank.")
        return

    result = run(email)

    if "error" in result:
        print(f"[-] Error: {result['error']}")
        return

    print(f"\n[*] Breach lookup for: {result['email']}")
    print("-" * 60)
    print(f"Breached:   {'YES' if result['breached'] else 'No'}")
    if result["breached"]:
        print(f"Found in {result['breach_count']} breach(es):")
        for name in result["breaches"]:
            print(f"  - {name}")
    print(f"Summary:    {result['summary']}")
    print("-" * 60)


if __name__ == "__main__":
    main()
