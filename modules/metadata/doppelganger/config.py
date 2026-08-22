"""Doppelgänger configuration from environment variables / .env file."""

import os
from dataclasses import dataclass, field

try:
    import dotenv
    dotenv.load_dotenv()
except ImportError:
    pass


@dataclass
class DoppelConfig:
    keys: dict = field(default_factory=dict)
    nominatim_ua: str = "OSINTNexusBot/1.0"
    face_strong_gate: int = 10
    face_weak_gate: int = 25
    lbph_threshold: float = 80.0
    max_probe_workers: int = 8
    probe_timeout: float = 10.0
    max_matches: int = 10
    max_context_pages: int = 5


def load_config() -> DoppelConfig:
    """Read optional stage keys/flags from environment variables."""
    env = os.environ
    return DoppelConfig(
        keys={
            "google_vision": env.get("GOOGLE_VISION_API_KEY", ""),
            "serpapi": env.get("SERPAPI_API_KEY", ""),
            "tineye_public": env.get("TINEYE_PUBLIC_KEY", ""),
            "tineye_private": env.get("TINEYE_PRIVATE_KEY", ""),
            "saucenao": env.get("SAUCENAO_API_KEY", ""),
        },
        nominatim_ua=env.get("NOMINATIM_USER_AGENT", "OSINTNexusBot/1.0"),
    )