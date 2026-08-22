"""
Password Strength Verifier
==========================
Checks whether a user-supplied password is strong, using local heuristic
analysis - no network calls, the password never leaves the machine and is
never included in the result dict.

Scoring model (0-100):
- length tier (0-50 pts):   >=16 chars -> 50, >=12 -> 38, >=8 -> 25, >=6 -> 12, else 6
- character variety (0-25): points for how many of {lower, upper, digit, symbol} are present
- entropy estimate (0-25):  length * log2(estimated charset size), tiered
- penalties:                common passwords, sequential runs, repeated
                            characters, embedded years, single-class-only

Labels: 80+ Very Strong | 60+ Strong | 40+ Fair | 20+ Weak | else Very Weak.

Integration note: strength is only half the story - a "Strong" password that
has already leaked is still dangerous. Pair this module with password_checker
(XposedOrNot breach lookup) for the full picture.
"""

import getpass
import math
import re
import sys

# Well-known weak passwords (checked case-insensitively, with trailing
# digits/symbols stripped, so "Password123!" is also caught)
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "1234567", "111111", "1234567890", "123123", "abc123", "password1",
    "iloveyou", "1234", "000000", "qwerty123", "1q2w3e4r", "admin",
    "letmein", "welcome", "monkey", "dragon", "master", "sunshine",
    "princess", "football", "superman", "batman", "trustno1", "zaq12wsx",
    "p@ssw0rd", "passw0rd", "qazwsx", "qwertyuiop", "zxcvbnm", "asdfgh",
    "987654321", "654321", "123321", "password123", "admin123", "changeme",
    "hello", "love", "jesus", "ninja", "whatever", "baseball", "shadow",
    "michael", "test", "test123", "guest", "root", "hunter2", "welcome1",
    "pass", "access", "secret", "abc", "google", "facebook", "internet",
    "mypassword", "password2", "passw0rd!", "loveme", "maggie", "cheese",
    "freedom", "whatever1", "harley", "ginger", "letmein1", "qwerty12",
    "password!", "adminadmin", "mustang", "tigger", "charlie", "jordan",
}

SEQUENCES = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "!@#$%^&*()",
)

REPEATED_RE = re.compile(r"(.)\1{2,}")
YEAR_RE = re.compile(r"(19|20)\d{2}")

CHARSETS = {
    "lowercase": set("abcdefghijklmnopqrstuvwxyz"),
    "uppercase": set("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    "digits": set("0123456789"),
    "symbols": set(" !@#$%^&*()-_=+[]{};:,.<>/?~`|\\\"'"),
}


def _length_points(length: int) -> int:
    if length >= 16:
        return 50
    if length >= 12:
        return 38
    if length >= 8:
        return 25
    if length >= 6:
        return 12
    return 6


def _variety_points(classes: list) -> int:
    return {1: 5, 2: 13, 3: 20, 4: 25}.get(len(classes), 0)


def _entropy_points(length: int, classes: list) -> tuple:
    charset_size = sum(len(CHARSETS[c]) for c in classes)
    bits = length * math.log2(max(charset_size, 1))
    if bits >= 70:
        return 25, bits
    if bits >= 55:
        return 18, bits
    if bits >= 40:
        return 10, bits
    return 0, bits


def _is_common(password: str) -> bool:
    lower = password.lower()
    candidates = {lower, lower.rstrip("0123456789!@#$%^&*")}
    return bool(candidates & COMMON_PASSWORDS)


def _has_sequential(password: str) -> bool:
    lower = password.lower()
    reversed_lower = lower[::-1]
    for seq in SEQUENCES:
        for i in range(len(seq) - 2):
            run = seq[i:i + 3]
            if run in lower or run in reversed_lower:
                return True
    return False


def _masked_input(prompt: str = "", get_key=None) -> str:
    """
    Read a password from the console, masking every keystroke as '*' the
    moment it is pressed (no echo, no visible plaintext).

    Key-by-key reading requires a real interactive terminal:
    - Windows : msvcrt.getwch() (per-keystroke, no echo)
    - Unix    : termios/tty cbreak mode + select
    - non-tty : falls back to getpass

    `get_key` is an injectable key source for tests.
    """
    interactive = get_key is not None or sys.stdin.isatty()

    if not interactive:
        return getpass.getpass(prompt)

    print(prompt, end="", flush=True)

    win32 = sys.platform == "win32"
    fd = None
    old_attrs = None
    if get_key is None and not win32:
        import select
        import termios
        import tty
        fd = sys.stdin.fileno()
        old_attrs = termios.tcgetattr(fd)
        tty.setcbreak(fd)
    elif get_key is None:
        import msvcrt

    buffer = []
    skip_next = False
    try:
        while True:
            if get_key is not None:
                ch = get_key()
            elif win32:
                ch = msvcrt.getwch()
            else:
                if not select.select([sys.stdin], [], [], 0.1)[0]:
                    continue
                ch = sys.stdin.read(1)
                if not ch:  # EOF
                    continue

            if skip_next:
                skip_next = False
                continue
            if ch in ("\r", "\n"):
                print(flush=True)
                return "".join(buffer)
            if ch == "\x03":
                print(flush=True)
                raise KeyboardInterrupt
            if ch in ("\x00", "\xe0"):
                skip_next = True  # Windows: arrow/function key - swallow the 2nd byte too
                continue
            if ch in ("\b", "\x7f"):
                if buffer:
                    buffer.pop()
                    print("\b \b", end="", flush=True)
                continue
            buffer.append(ch)
            print("*", end="", flush=True)
    finally:
        if old_attrs is not None:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_attrs)


def run(password: str) -> dict:
    """
    Assess the strength of `password`. Returns a dict with a numeric score,
    a strength label, an entropy estimate, per-class breakdown, the issues
    found and actionable suggestions. The password itself is never returned.
    """
    if not isinstance(password, str):
        return {"error": "Password must be a string."}
    if not password:
        return {"error": "Password cannot be empty."}

    length = len(password)
    issues = []

    # Character class detection
    chars = set(password)
    classes = [name for name, charset in CHARSETS.items() if chars & charset]
    if not classes:
        classes = ["symbols"]  # non-ASCII / exotic input counts as symbols

    # --- Scoring ---
    score = _length_points(length) + _variety_points(classes)
    entropy_points, entropy_bits = _entropy_points(length, classes)
    score += entropy_points

    # --- Penalties ---
    if _is_common(password):
        score = min(score, 15)
        issues.append("This is one of the most common passwords.")
    if _has_sequential(password):
        score -= 15
        issues.append("Contains a sequential run (e.g. 'abc' or '12345').")
    if REPEATED_RE.search(password):
        score -= 10
        issues.append("Contains repeated characters (e.g. 'aaa').")
    if YEAR_RE.search(password):
        score -= 10
        issues.append("Contains a year or date.")
    if len(classes) == 1 and length < 12:
        score -= 10
        issues.append("Uses only one character type.")

    score = max(0, min(100, score))

    # --- Label ---
    if score >= 80:
        label = "Very Strong"
    elif score >= 60:
        label = "Strong"
    elif score >= 40:
        label = "Fair"
    elif score >= 20:
        label = "Weak"
    else:
        label = "Very Weak"

    # --- Suggestions (only the relevant ones) ---
    suggestions = []
    if length < 12:
        suggestions.append("Use at least 12 characters - length matters most.")
    if len(classes) < 3:
        suggestions.append("Mix lowercase, uppercase, digits and symbols.")
    if "This is one of the most common passwords." in issues:
        suggestions.append("Never use a known leaked/common password.")
    if "Contains a sequential run (e.g. 'abc' or '12345')." in issues:
        suggestions.append("Avoid keyboard patterns and counting sequences.")
    if "Contains repeated characters (e.g. 'aaa')." in issues:
        suggestions.append("Avoid repeating the same character.")
    if "Contains a year or date." in issues:
        suggestions.append("Avoid personal details like birth years.")
    if score < 60:
        suggestions.append("Consider a passphrase or a password manager.")

    return {
        "score": score,
        "label": label,
        "entropy_bits": round(entropy_bits, 1),
        "length": length,
        "character_classes": {name: (name in classes) for name in CHARSETS},
        "issues": issues,
        "suggestions": suggestions,
        "summary": f"Password strength: {label} ({score}/100), "
                   f"~{round(entropy_bits)} bits of entropy.",
    }


def main():
    try:
        password = _masked_input("Enter the password to assess: ")
    except KeyboardInterrupt:
        print("\n[-] Aborted.")
        return

    result = run(password)

    if "error" in result:
        print(f"[-] Error: {result['error']}")
        return

    print(f"\n[*] {result['summary']}")
    print("-" * 60)
    print(f"Length:     {result['length']} characters")
    print(f"Entropy:    ~{result['entropy_bits']} bits")
    classes = result["character_classes"]
    present = [name for name, ok in classes.items() if ok]
    print(f"Classes:    {', '.join(present) if present else 'none'}")
    if result["issues"]:
        print("Issues:")
        for issue in result["issues"]:
            print(f"  - {issue}")
    if result["suggestions"]:
        print("Suggestions:")
        for suggestion in result["suggestions"]:
            print(f"  + {suggestion}")
    print("-" * 60)


if __name__ == "__main__":
    main()
