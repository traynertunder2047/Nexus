"""Atlas configuration from environment variables / .env file."""

import os
from dataclasses import dataclass, field

try:
    import dotenv
    dotenv.load_dotenv()
except ImportError:
    pass


@dataclass
class AtlasConfig:
    keys: dict = field(default_factory=dict)
    nominatim_ua: str = "OSINTNexusBot/1.0"
    geocode_limit: int = 5
    max_candidates: int = 8
    cluster_radius_km: float = 5.0
    nearby_radius_m: int = 2000
    overpass_timeout: int = 15
    probe_timeout: float = 10.0
    use_country_prior: bool = True


def load_config() -> AtlasConfig:
    """Read optional stage keys/flags from environment variables."""
    env = os.environ
    return AtlasConfig(
        keys={"google_geocoding": env.get("GOOGLE_GEOCODING_API_KEY", "")},
        nominatim_ua=env.get("NOMINATIM_USER_AGENT", "OSINTNexusBot/1.0"),
        use_country_prior=env.get("ATLAS_USE_COUNTRY_PRIOR", "1") == "1",
    )