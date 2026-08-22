
#Must check code functionality and integrity
#Fai email generator per fare phishing e email lookup per checkare. Domain email security analyser?

def run(first_name: str, last_name: str, domain: str) -> dict:
    """
    Scope: Generates common corporate email address pattern permutations 
    based on a target's first name, last name, and domain name.
    """
    fn = first_name.lower().strip()
    ln = last_name.lower().strip()
    dom = domain.lower().strip()

    # Input validation
    if not fn or not ln or not dom:
        return {"error": "First name, last name, and domain are required."}

    # Clean out any @ symbols if the user typed '@company.com' instead of 'company.com'
    dom = dom.lstrip("@")

    # Common corporate email syntax permutations
    predictions = [
        f"{fn}.{ln}@{dom}",      # jane.doe@company.com
        f"{fn}{ln}@{dom}",       # janedoe@company.com
        f"{fn[0]}{ln}@{dom}",    # jdoe@company.com
        f"{fn}{ln[0]}@{dom}",    # janed@company.com
        f"{fn}@{dom}",          # jane@company.com
        f"{ln}@{dom}",          # doe@company.com
        f"{ln}.{fn}@{dom}",      # doe.jane@company.com
        f"{fn}_{ln}@{dom}",      # jane_doe@company.com
        f"{fn[0]}.{ln}@{dom}",   # j.doe@company.com
    ]

    return {
        "target_name": f"{first_name.title()} {last_name.title()}",
        "domain": dom,
        "total_generated": len(predictions),
        "predicted_emails": predictions
    }


# Standalone testing block
if __name__ == "__main__":
    print("[*] Testing Email Predictor module locally...\n")
    results = run("Jane", "Doe", "acme.com")
    
    if "error" in results:
        print(f"[-] Error: {results['error']}")
    else:
        print(f"Target: {results['target_name']} ({results['domain']})")
        print(f"Generated {results['total_generated']} potential email combinations:")
        for email in results["predicted_emails"]:
            print(f"  [+] {email}")