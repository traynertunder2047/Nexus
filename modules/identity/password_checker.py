#use XposedOrNot api endpoint for password check.
"""
This endpoint checks whether a password has appeared in known breaches without revealing the password itself.
You compute the SHA3 Keccak-512 hash of the password locally and send only its first 10 characters,
so the password and the full hash never leave your machine. The response indicates a match or no match.
"""

"""
Password Checker Module
=======================
Checks whether a password has been exposed in known breaches using the
XposedOrNot anonymous password API (https://passwords.xposedornot.com).

API endpoint : https://passwords.xposedornot.com/api/v1/pass/anon/{hash_prefix}
Privacy model : k-anonymity. The password is hashed LOCALLY with SHA3
                Keccak-512 and only the first 10 hex characters of the digest
                (prefix) are sent. Neither the password nor the full hash
                ever leaves the machine.

Match reply  : HTTP 200 -> {"SearchPassAnon":{"anon":"<prefix>","char":"D:0;A:4;S:0;L:4","count":"35434","wordlist":0}}
No-match     : HTTP 404 -> {"Error":"Not found"}

Response fields:
- anon      : the prefix sent, echoed back
- char      : password composition, format "D:;A:;S:;L:" = digits, alphabetic, special, length
- count     : how many times the password was observed in breaches (STRING in practice)
- wordlist  : 1 if the password came from a known wordlist, else 0

WARNING - SHA3-512 != Keccak-512: hashlib.sha3_512() implements the NIST
SHA-3 padding (0x06) and produces DIFFERENT digests than the original Keccak
padding (0x01) this API uses (verified: sha3_512("test") != Keccak-512("test")).
A pure-Python Keccak-512 is therefore implemented below and validated against
the official XposedOrNot test vectors.
"""

import requests

BASE_URL = "https://passwords.xposedornot.com/api/v1/pass/anon/{prefix}"

USER_AGENT = "OSINTBot-PasswordChecker/1.0"

SERVER_ERROR_CODES = (502, 503)

# ---------------------------------------------------------------------------
# Pure-Python SHA3 Keccak-512 (original Keccak padding 0x01, not NIST SHA-3)
# ---------------------------------------------------------------------------
_MASK64 = (1 << 64) - 1

_RHO = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)

_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)


def _rotl64(value, shift):
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_f(state):
    for rnd in range(24):
        # Theta
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
             for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(0, 25, 5):
                state[x + y] ^= d[x]
        # Rho + Pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + ((2 * x + 3 * y) % 5) * 5] = _rotl64(state[x + 5 * y], _RHO[x][y])
        # Chi
        for x in range(5):
            for y in range(0, 25, 5):
                state[x + y] = b[x + y] ^ ((_MASK64 ^ b[(x + 1) % 5 + y]) & b[(x + 2) % 5 + y])
        # Iota
        state[0] ^= _ROUND_CONSTANTS[rnd]
    return state


def _keccak_512(data: bytes) -> str:
    """Return the Keccak-512 hex digest (128 chars) of `data`."""
    rate = 72  # 1600 - 2 * 512 bits = 576 bits
    state = [0] * 25
    pos = 0

    while True:
        remaining = len(data) - pos
        if remaining < rate:
            # Last block: absorb remainder, then pad10*1 with Keccak domain byte 0x01.
            # NOTE: when the data is an exact multiple of rate, this block is
            # empty but still required (Keccak always appends a full pad block).
            chunk = data[pos:]
            for i in range(0, len(chunk), 8):
                state[i // 8] ^= int.from_bytes(chunk[i:i + 8], "little")
            state[len(chunk) // 8] ^= 0x01 << (8 * (len(chunk) % 8))
            state[(rate - 1) // 8] ^= 0x80 << (8 * ((rate - 1) % 8))
            _keccak_f(state)
            break
        chunk = data[pos:pos + rate]
        for i in range(0, len(chunk), 8):
            state[i // 8] ^= int.from_bytes(chunk[i:i + 8], "little")
        _keccak_f(state)
        pos += rate

    out = b""
    while len(out) < 64:
        for lane in state:
            out += lane.to_bytes(8, "little")
            if len(out) >= 64:
                break
        if len(out) < 64:
            _keccak_f(state)
    return out[:64].hex()


def _parse_char(char_str):
    """Parse 'D:0;A:4;S:0;L:4' into {"digits":0,"alpha":4,"special":0,"length":4}."""
    if not char_str:
        return None
    fields = {}
    for part in str(char_str).split(";"):
        if ":" in part:
            key, value = part.split(":", 1)
            fields[key] = value
    return {
        "digits": int(fields.get("D", 0)),
        "alpha": int(fields.get("A", 0)),
        "special": int(fields.get("S", 0)),
        "length": int(fields.get("L", 0)),
    }


def safe_result(prefix: str) -> dict:
    """Result for passwords never seen in the breach database."""
    return {
        "hash_prefix": prefix,
        "exposed": False,
        "count": 0,
        "wordlist": False,
        "characteristics": None,
        "summary": "Password not found in known breaches.",
    }


def run(password: str, timeout: int = 10) -> dict:
    """
    Hashes the password locally with Keccak-512, sends only the first 10 hex
    characters of the digest to XposedOrNot, and reports whether the password
    appears in known breaches. The password itself is never sent, stored or
    included in the returned dict. Returns a dict with an "error" key on
    any failure.
    """
    if not isinstance(password, str) or not password.strip():
        return {"error": "Password must be a non-empty string."}

    # Hash locally, extract the 10-character prefix (k-anonymity)
    digest = _keccak_512(password.encode("utf-8"))
    prefix = digest[:10]

    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}

    try:
        response = requests.get(
            BASE_URL.format(prefix=prefix), headers=headers, timeout=timeout
        )
    except requests.RequestException as e:
        return {"error": f"Failed to connect to XposedOrNot password API: {e}"}

    # 404 means the password is not in the breach database
    if response.status_code == 404:
        return safe_result(prefix)
    if response.status_code == 401:
        return {"error": "Unauthorized - invalid or missing API key."}
    if response.status_code == 429:
        return {"error": "Rate limit exceeded on XposedOrNot password API."}
    if response.status_code in SERVER_ERROR_CODES:
        return {"error": "XposedOrNot server error, please retry later."}

    try:
        response.raise_for_status()
    except requests.RequestException as e:
        return {"error": f"XposedOrNot API returned HTTP {response.status_code}: {e}"}

    try:
        data = response.json()
    except ValueError:
        return {"error": "Invalid JSON response from XposedOrNot password API."}

    payload = data.get("SearchPassAnon")
    if not payload:
        return {"error": f"Unexpected API response: {data}"}

    # The API returns "count" as a STRING (e.g. "35434") - coerce defensively
    try:
        count = int(payload.get("count", 0))
    except (TypeError, ValueError):
        count = 0

    return {
        "hash_prefix": prefix,
        "exposed": count > 0,
        "count": count,
        "wordlist": bool(payload.get("wordlist", 0)),
        "characteristics": _parse_char(payload.get("char")),
        "summary": (
            f"Password found in breach databases {count} time(s) - "
            "do NOT reuse it."
            if count > 0
            else "Password not found in known breaches."
        ),
    }


def main():
    password = input("Enter the password to check: ")
    if not password:
        print("[-] Password cannot be blank.")
        return

    result = run(password)

    if "error" in result:
        print(f"[-] Error: {result['error']}")
        return

    print(f"\n[*] Password check (hash prefix: {result['hash_prefix']}...)")
    print("-" * 60)
    print(f"Exposed:    {'YES' if result['exposed'] else 'No'}")
    if result["exposed"]:
        print(f"Occurrences: {result['count']}")
        print(f"Wordlist:   {'yes' if result['wordlist'] else 'no'}")
    if result["characteristics"]:
        ch = result["characteristics"]
        print(f"Composition: {ch['length']} chars | {ch['alpha']} alpha | {ch['digits']} digits | {ch['special']} special")
    print(f"Summary:    {result['summary']}")
    print("-" * 60)


if __name__ == "__main__":
    main()
