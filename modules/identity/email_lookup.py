import requests

#must be checked, library may not work

def run(email: str, EMAILREP_API_KEY: str = None) -> dict:
    """
    Queries EmailRep.io to assess an email address's threat reputation,
    checking for reported phishing, malicious activity, and leak history.
    """
    clean_email = email.lower().strip()
    if "@" not in clean_email:
        return {"error": "Invalid email address format."}

    # EmailRep.io endpoint
    url = f"https://emailrep.io/{clean_email}"

    # EmailRep requires a descriptive User-Agent header
    headers = {
        "User-Agent": "OSINTBot-ThreatChecker/1.0",
        "Accept": "application/json"
    }

    if EMAILREP_API_KEY:
        headers["Key"] = EMAILREP_API_KEY

    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        # Handle API status codes
        if response.status_code == 400:
            return {"error": "Bad request or invalid email syntax."}
        elif response.status_code == 401:
            return {"error": "Invalid or missing EmailRep API key."}
        elif response.status_code == 403:
            return {"error": "Access forbidden by EmailRep API."}
        elif response.status_code == 404:
            return {"error": "No reputation data found for this email."}
        elif response.status_code == 429:
            return {"error": "Rate limit exceeded on EmailRep API."}
        
        response.raise_for_status()

        try:
            data = response.json()
        except ValueError:
            return {"error": "Invalid JSON response from EmailRep API."}

        # Extract nested details safely
        details = data.get("details", {})

        flags = {
            "blacklisted": details.get("blacklisted", False),
            "malicious_activity": details.get("malicious_activity", False),
            "credentials_leaked": details.get("credentials_leaked", False),
            "data_breach": details.get("data_breach", False),
            "disposable": details.get("disposable", False),
            "spam": details.get("spam", False)
        }

        if data.get("suspicious"):
            summary = "High Risk / Phishing History"
        elif any(flags.values()):
            triggered = [name.replace("_", " ") for name, active in flags.items() if active]
            summary = f"Caution: {', '.join(triggered)}"
        else:
            summary = "Low Suspicion"

        return {
            "email": clean_email,
            "reputation": data.get("reputation", "unknown"),
            "suspicious": data.get("suspicious", False),
            "references": data.get("references", 0),
            "flags": flags,
            "sources": details.get("sources", []),
            "summary": summary
        }

    except requests.RequestException as e:
        return {"error": f"Failed to connect to EmailRep threat database: {e}"}


# Standalone testing block
if __name__ == "__main__":
    print("[*] Testing Email Threat Lookup module...\n")
    test_target = "test@example.com"
    result = run(test_target)
    
    if "error" in result:
        print(f"[-] Error: {result['error']}")
    else:
        print(f"Target:       {result['email']}")
        print(f"Reputation:   {result['reputation'].upper()}")
        print(f"Suspicious:   {result['suspicious']}")
        print(f"Risk Assessment: {result['summary']}")
        print("Threat Flags:")
        for flag, status in result["flags"].items():
            print(f"  - {flag}: {status}")