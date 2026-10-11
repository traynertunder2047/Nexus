from __future__ import annotations

import json
import sys


def _usage() -> str:
    return (
        "Usage: python -m modules.identity <subcommand> [args]\n"
        "\n"
        "Subcommands:\n"
        "  breach-check      <email>                 XposedOrNot breach lookup\n"
        "  analytics         <email>                 XposedOrNot breach analytics\n"
        "  email-lookup      <email>                 EmailRep reputation\n"
        "  password-check    <password>              XposedOrNot anon password check\n"
        "  password-strength <password>              Local strength scorer\n"
        "  assess            [password]              Strength + breach fusion (masked prompt if omitted)\n"
        "  phone-validate    <phone>                 Phone validation + metadata\n"
        "  phone-breach      <phone>                 Leak-Lookup phone breach check\n"
        "  social            <username>              Cross-platform username probe\n"
        "\n"
        "Each subcommand accepts --json and --timeout SEC (and subcommand-specific flags):\n"
        "  phone-validate/phone-breach: --region CC\n"
        "  social: --platforms GitHub,Reddit\n"
        "\n"
        "Examples:\n"
        "  python -m modules.identity breach-check victim@example.com --json\n"
        "  python -m modules.identity social johndoe --platforms GitHub,Reddit\n"
    )


# Map subcommand -> module import path + main() entrypoint
_SUBCOMMANDS = {
    "breach-check": "modules.identity.breach_checker",
    "analytics": "modules.identity.breach_analytics",
    "email-lookup": "modules.identity.email_lookup",
    "password-check": "modules.identity.password_checker",
    "password-strength": "modules.identity.strong_password",
    "assess": "modules.identity.password_assessor",
    "phone-validate": "modules.identity.phone_validator",
    "phone-breach": "modules.identity.phone_breach_check",
    "social": "modules.identity.social_linker",
}


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(_usage())
        return 0 if argv and argv[0] in ("-h", "--help", "help") else 1

    sub = argv[0].lower()
    # Allow aliases
    aliases = {
        "breach": "breach-check",
        "breach_checker": "breach-check",
        "breach-checker": "breach-check",
        "breach_analytics": "analytics",
        "breach-analytics": "analytics",
        "email_lookup": "email-lookup",
        "strong_password": "password-strength",
        "strong-password": "password-strength",
        "password_assessor": "assess",
        "password-assessor": "assess",
        "assess-password": "assess",
        "assess_password": "assess",
        "phone_validator": "phone-validate",
        "phone-validator": "phone-validate",
        "phone_breach": "phone-breach",
        "phone_breach_check": "phone-breach",
        "social_linker": "social",
        "social-linker": "social",
    }
    sub = aliases.get(sub, sub)
    if sub not in _SUBCOMMANDS:
        print(f"Unknown subcommand: {sub}\n", file=sys.stderr)
        print(_usage(), file=sys.stderr)
        return 2

    mod_path = _SUBCOMMANDS[sub]
    try:
        import importlib

        mod = importlib.import_module(mod_path)
    except Exception as e:
        print(f"Failed to import {mod_path}: {e}", file=sys.stderr)
        return 1

    # Delegate to the sub-module's main() with the remaining argv
    return mod.main(argv[1:])


if __name__ == "__main__":
    sys.exit(main())
