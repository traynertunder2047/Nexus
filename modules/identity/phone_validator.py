"""
Poi phone lookup se lo vuoi aggiungere se è classico non ha molto senso,
per aggiungerlo ci sta farlo con revers engineering in modo che dal numero di telefono risale magari a qualche account nei data breach
"""
#for validation and number formatting [164]
import phonenumbers
from phonenumbers import geocoder, carrier

def search_phone_pipeline(raw_input: str, default_region: str = "US") -> dict:
    # --- STAGE 1 & 2: Sanitize & Validate ---
    try:
        parsed_num = phonenumbers.parse(raw_input, default_region)
        if not phonenumbers.is_valid_number(parsed_num):
            return {"status": "error", "message": "Invalid phone number structure."}
    except phonenumbers.NumberParseException as e:
        return {"status": "error", "message": f"Parsing failed: {e}"}

    # --- STAGE 3: Normalize Search Keys ---
    e164_key = phonenumbers.format_number(parsed_num, phonenumbers.PhoneNumberFormat.E164)
    msisdn_key = e164_key.lstrip("+")
    
    # Extract metadata offline
    country = geocoder.description_for_number(parsed_num, "en") or "Unknown"
    net_carrier = carrier.name_for_number(parsed_num, "en") or "Unknown"

    # --- STAGE 4: Database Lookup (Simulated) ---
    db_results = query_database(e164_key=e164_key, fallback_key=msisdn_key)

    # --- STAGE 5: Aggregate Results ---
    return {
        "status": "success",
        "search_keys": {
            "e164": e164_key,
            "msisdn": msisdn_key
        },
        "metadata": {
            "country": country,
            "carrier": net_carrier
        },
        "database_hits": db_results
    }


def query_database(e164_key: str, fallback_key: str) -> list:
    """Mock database query layer."""
    # In real code, execute your SQL SELECT or API requests here
    return []