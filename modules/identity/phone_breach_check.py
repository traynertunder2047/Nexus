"""
Phone Breach Check Module
=========================
Queries the Leak-Lookup API (https://leak-lookup.com/docs/search) to find
data breaches that contain a given phone number.

API endpoint : https://leak-lookup.com/api/search (POST, form-encoded)
Parameters   : key, type ("phone"), query
Authentication: API key is read from the LEAK_LOOKUP_API_KEY environment
                 variable (loaded from .env via python-dotenv) - the key is
                 NEVER hardcoded in source code.

Public-key reply : {"error":"false","message":{"breach_name_1":[], ...}}
Private-key reply: {"error":"false","message":{"breach_name_1":[{...}], ...}}
Error reply      : {"error":"true","message":"<MESSAGE>"}

The "message" field is a dict whose KEYS are the breach names, so both
public and private responses are flattened into a simple breach-name list.

Validation and number normalization are delegated to the
phone_validator.search_phone_pipeline() function (same package).
"""

import os

import requests
from dotenv import load_dotenv

from phone_validator import search_phone_pipeline

SEARCH_URL = "https://leak-lookup.com/api/search"
QUERY_TYPE = "phone"
USER_AGENT = "OSINTBot-PhoneBreachCheck/1.0"

# Load .env once at import time so os.getenv() finds the key
load_dotenv()


def _load_api_key() -> str:
    """Reads the Leak-Lookup API key from the environment (never hardcoded)."""
    key = os.getenv("LEAK_LOOKUP_API_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "LEAK_LOOKUP_API_KEY is not set. Add it to the .env file "
            "(see .env.example)."
        )
    return key


def not_found_result(phone: str) -> dict:
    """Shared result shape for phone numbers with no breach history."""
    return {
        "phone": phone,
        "breached": False,
        "breach_count": 0,
        "breaches": [],
        "summary": "No breaches found for this phone number.",
    }


def run(phone: str, default_region: str = "US", timeout: int = 10) -> dict:
    """
    Searches Leak-Lookup for data breaches containing the given phone number.

    The number is validated and normalized by
    phone_validator.search_phone_pipeline() (E164 + digits-only search key),
    because breach dumps typically store numbers as plain digits. Returns a
    dict with an "error" key on any failure.
    """
    # --- Stage 1 & 2: validate & normalize via phone_validator ---
    pipeline = search_phone_pipeline(phone, default_region)
    if pipeline.get("status") != "success":
        return {"error": pipeline.get("message", "Invalid phone number.")}

    e164 = pipeline["search_keys"]["e164"]
    query_key = pipeline["search_keys"]["msisdn"]  # digits only, e.g. 12025550111

    # --- Stage 3: Load the API key (never hardcoded) ---
    try:
        api_key = _load_api_key()
    except RuntimeError as e:
        return {"error": str(e)}

    # --- Stage 4: Query the Leak-Lookup API (POST form data) ---
    try:
        response = requests.post(
            SEARCH_URL,
            data={"key": api_key, "type": QUERY_TYPE, "query": query_key},
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            timeout=timeout,
        )
    except requests.RequestException as e:
        return {"error": f"Failed to connect to Leak-Lookup API: {e}"}

    if response.status_code == 401:
        return {"error": "Unauthorized - invalid API key."}
    if response.status_code == 429:
        return {"error": "Rate limit exceeded on Leak-Lookup API."}

    try:
        response.raise_for_status()
    except requests.RequestException as e:
        return {"error": f"Leak-Lookup API returned HTTP {response.status_code}: {e}"}

    try:
        data = response.json()
    except ValueError:
        return {"error": "Invalid JSON response from Leak-Lookup API."}

    if not isinstance(data, dict):
        return {"error": f"Unexpected API response format: {data!r}"}

    # --- Stage 5: Interpret the response ---
    # The API reports failures as {"error":"true",...} with HTTP 200, so the
    # body must be inspected, not just the status code.
    if str(data.get("error", "")).strip().lower() == "true":
        message = str(data.get("message") or "Unknown error")
        return {"error": f"Leak-Lookup API error: {message}"}

    message = data.get("message")
    if not isinstance(message, dict) or not message:
        return not_found_result(e164)

    breach_names = [str(name) for name in message.keys() if name]
    if not breach_names:
        return not_found_result(e164)

    return {
        "phone": e164,
        "breached": True,
        "breach_count": len(breach_names),
        "breaches": breach_names,
        "summary": (
            f"Found in {len(breach_names)} data breach(es): "
            f"{', '.join(breach_names)}"
        ),
    }


def main():
    phone = input("Enter the phone number to check: ").strip()
    if not phone:
        print("[-] Phone number cannot be blank.")
        return

    result = run(phone)

    if "error" in result:
        print(f"[-] Error: {result['error']}")
        return

    print(f"\n[*] Breach lookup for: {result['phone']}")
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
