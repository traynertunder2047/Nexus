"""Stage contracts shared by every pipeline module."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class StageResult:
    """Contract every pipeline stage must return."""
    stage: str
    status: str            # ok | no_data | skipped | error
    confidence: float      # 0.0 - 1.0
    data: dict = field(default_factory=dict)
    note: str = ""
    seconds: float = 0.0


@dataclass
class Candidate:
    """One geolocation hypothesis from any stage (lat/lon may be None
    for identity-only matches, e.g. Sherlock image hits)."""
    lat: Optional[float] = None
    lon: Optional[float] = None
    source: str = ""
    confidence: float = 0.0
    url: str = ""
    reason: str = ""