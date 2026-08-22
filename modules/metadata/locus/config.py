"""Pipeline configuration from environment variables / .env file."""

import os
from dataclasses import dataclass, field

try:
    import dotenv
    dotenv.load_dotenv()
except ImportError:
    pass


@dataclass
class PipelineConfig:
    keys: dict = field(default_factory=dict)
    nominatim_ua: str = "OSINTNexusBot/1.0"
    use_geoclip: bool = False
    use_solar: bool = False
    strong_phash_gate: int = 10
    weak_phash_gate: int = 25
    max_probe_workers: int = 8
    probe_timeout: float = 10.0
    tesseract_lang: str = "ita+eng"
    overpass_timeout: int = 15
    geoclip_top_k: int = 5
    max_reverse_matches: int = 10


def load_config() -> PipelineConfig:
    """Read optional stage keys/flags from environment variables."""
    env = os.environ
    return PipelineConfig(
        keys={
            "google_vision": env.get("GOOGLE_VISION_API_KEY", ""),
            "serpapi": env.get("SERPAPI_API_KEY", ""),
            "tineye_public": env.get("TINEYE_PUBLIC_KEY", ""),
            "tineye_private": env.get("TINEYE_PRIVATE_KEY", ""),
            "saucenao": env.get("SAUCENAO_API_KEY", ""),
        },
        nominatim_ua=env.get("NOMINATIM_USER_AGENT", "OSINTNexusBot/1.0"),
        use_geoclip=env.get("PHOTO_GEOLOC_USE_GEOCLIP", "0") == "1",
        use_solar=env.get("PHOTO_GEOLOC_USE_SOLAR", "0") == "1",
    )