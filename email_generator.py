import random
import re

COMMON_DOMAINS = [
    "gmail.com",
    "outlook.com",
    "yahoo.com",
    "protonmail.com",
    "icloud.com",
    "hotmail.com",
    "mail.com",
    "aol.com",
    "zoho.com",
    "fastmail.com",
]


def generate_email_addresses(name: str, domain: str = None) -> dict:
    """Generate email address variants from a name string.

    With a domain, all variants use it. Without one, each variant gets a
    common provider so the options are distinct.
    """
    name = name.strip()
    if not name:
        return {"error": "A name is required."}

    tokens = re.findall(r"[a-zA-Z0-9]+", name.lower())
    if not tokens:
        return {"error": "Name must contain letters or digits."}

    fn = tokens[0]
    ln = tokens[-1] if len(tokens) > 1 else ""

    if ln:
        patterns = [
            f"{fn}.{ln}",
            f"{fn}{ln}",
            f"{fn[0]}{ln}",
            f"{fn}{ln[0]}",
            f"{ln}.{fn}",
            f"{fn}_{ln}",
            f"{fn[0]}.{ln}",
            f"{ln}.{fn[0]}",
            f"{ln}_{fn}",
            f"{fn}",
        ]
    else:
        patterns = [
            f"{fn}",
            f"{fn}{random.randint(1, 99)}",
            f"{fn}1990",
            f"{fn}.{random.randint(1, 99)}",
            f"{fn}_{random.randint(1, 99)}",
            f"{fn}{random.randint(100, 999)}",
            f"{fn}.mail",
            f"{fn}.work",
            f"{fn}.official",
            f"{fn}.io",
        ]

    if domain:
        dom = domain.strip().lstrip("@").lower()
        variants = [f"{p}@{dom}" for p in patterns]
    else:
        variants = []
        for i, p in enumerate(patterns):
            d = COMMON_DOMAINS[i % len(COMMON_DOMAINS)]
            variants.append(f"{p}@{d}")

    return {
        "input_name": name,
        "domain": domain.strip().lstrip("@").lower() if domain else "multiple",
        "total_generated": len(variants),
        "emails": variants,
    }


def generate_email_text(need: str, context: dict) -> dict:
    """Generate a formatted email based on the selected need.

    context may contain: name, recipient, company, subject, body, details.
    """
    need = need.strip().lower()
    name = context.get("name", "[Your Name]")
    recipient = context.get("recipient", "[Recipient]")
    company = context.get("company", "[Company Name]")
    details = context.get("details", "")

    templates = {
        "company": {
            "subject": f"Professional correspondence from {name}",
            "body": (
                f"Dear {recipient},\n\n"
                f"My name is {name} from {company}. I am writing to you regarding "
                f"{details or 'a matter of mutual interest'}.\n\n"
                "I would appreciate the opportunity to discuss this further at your "
                "earliest convenience.\n\n"
                "Thank you for your time and consideration."
            ),
        },
        "notification": {
            "subject": f"Notification from {company}",
            "body": (
                f"Dear {recipient},\n\n"
                f"This is a notification from {company} regarding {details or 'a recent change'}.\n\n"
                "If you have any questions, please do not hesitate to contact us.\n\n"
                "Best regards,"
            ),
        },
        "report": {
            "subject": f"Report summary - {details or 'Overview'}",
            "body": (
                f"Dear {recipient},\n\n"
                f"Please find below a summary of the report prepared by {name} "
                f"at {company}.\n\n"
                f"{details or 'The report covers the requested topics and includes all relevant findings.'}\n\n"
                "The full report is available upon request.\n\n"
                "Kind regards,"
            ),
        },
        "outreach": {
            "subject": f"Introduction - {name} ({company})",
            "body": (
                f"Dear {recipient},\n\n"
                f"I am {name} from {company}. I am reaching out because "
                f"{details or 'I believe we may have common interests'}.\n\n"
                "I would be happy to schedule a short call if you are interested.\n\n"
                "Looking forward to hearing from you."
            ),
        },
        "custom": {
            "subject": context.get("subject", f"Message from {name}"),
            "body": context.get("body", ""),
        },
    }

    if need not in templates:
        return {"error": f"Unknown need '{need}'. Choose from: {', '.join(sorted(templates))}."}

    subject = templates[need]["subject"]
    body = templates[need]["body"]

    signature = f"\n\nBest regards,\n{name}\n{company}" if need != "custom" else ""

    return {
        "need": need,
        "subject": subject,
        "body": body + signature,
    }


def main():
    print("[*] Email Generator")
    print("    Generate email addresses from a name, or a formatted email text.\n")

    while True:
        print("Options:")
        print("  1) Generate email address from a name")
        print("  2) Generate 10 email options and choose one")
        print("  3) Generate email text")
        print("  4) Exit")
        choice = input("> ").strip()

        if choice == "1":
            name = input("Name: ").strip()
            domain = input("Domain (optional, Enter for random): ").strip() or None
            result = generate_email_addresses(name, domain)
            if "error" in result:
                print(f"[-] {result['error']}\n")
            else:
                print(f"[+] Generated {result['total_generated']} emails:")
                for email in result["emails"]:
                    print(f"    {email}")
                print()
        elif choice == "2":
            name = input("Name: ").strip()
            result = generate_email_addresses(name)
            if "error" in result:
                print(f"[-] {result['error']}\n")
                continue
            print(f"\n[+] Pick one of {result['total_generated']} options:")
            for i, email in enumerate(result["emails"], 1):
                print(f"  {i}) {email}")
            pick = input("\nPick a number (Enter to skip): ").strip()
            if pick.isdigit() and 1 <= int(pick) <= len(result["emails"]):
                print(f"[+] You chose: {result['emails'][int(pick) - 1]}\n")
            else:
                print("[-] No selection made.\n")
        elif choice == "3":
            print("\nText types: company | notification | report | outreach | custom")
            need = input("What should the text be? ").strip()
            context = {}
            context["name"] = input("Your name: ").strip() or "[Your Name]"
            context["recipient"] = input("Recipient: ").strip() or "[Recipient]"
            if need.lower() != "custom":
                context["company"] = input("Company: ").strip() or "[Company Name]"
                context["details"] = input("Details: ").strip()
            else:
                context["subject"] = input("Subject: ").strip()
                context["body"] = input("Message body: ").strip()
            result = generate_email_text(need, context)
            if "error" in result:
                print(f"[-] {result['error']}\n")
            else:
                print(f"\n[+] Subject: {result['subject']}")
                print(f"[+] Body:\n{result['body']}\n")
        elif choice == "4":
            print("[*] Goodbye.")
            break
        else:
            print("[-] Invalid option.\n")


if __name__ == "__main__":
    main()
