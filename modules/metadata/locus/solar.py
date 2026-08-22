"""Solar position math (built-in NOAA approximation) and its two uses:
the fast-path forgery sanity check and the fallback-path orientation
constraint stage."""

import math
import time
from datetime import datetime
from typing import Optional

from PIL import Image

from .config import PipelineConfig
from .contracts import StageResult


def _sun_position(dt: datetime, lat: float, lon: float) -> dict:
    """NOAA-approximation solar position; azimuth/elevation in degrees.

    Assumes the capture timestamp is in the device's local time (EXIF
    convention). The nominal timezone is inferred from longitude
    (round(lon/15)); DST and timezone anomalies add a small error to
    azimuth/elevation - acceptable for a constraint/forgery check, not
    for precise shadow analysis.
    """
    day = dt.timetuple().tm_yday
    decl = math.radians(23.44 * math.sin(math.radians((360.0 / 365.24) * (day - 81))))
    tz_offset = round(lon / 15.0)
    solar_h = dt.hour + dt.minute / 60.0 + dt.second / 3600.0 - tz_offset + lon / 15.0
    h = math.radians(15.0 * (solar_h - 12.0))
    lat_r = math.radians(lat)
    sin_e = math.sin(lat_r) * math.sin(decl) + math.cos(lat_r) * math.cos(decl) * math.cos(h)
    sin_e = max(-1.0, min(1.0, sin_e))
    elev = math.degrees(math.asin(sin_e))
    cos_a = (math.sin(decl) - math.sin(lat_r) * sin_e) / (math.cos(lat_r) * math.cos(math.asin(sin_e)) + 1e-9)
    az = math.degrees(math.acos(max(-1.0, min(1.0, cos_a))))
    az = 360.0 - az if h > 0 else az
    return {"elevation": round(elev, 1), "azimuth": round(az, 1)}


def _image_brightness(image_path: str) -> Optional[float]:
    """Mean luminance 0-255 via PIL; None if unreadable."""
    try:
        with Image.open(image_path) as img:
            gray = img.convert("L").resize((64, 64))
            px = list(gray.getdata())
            return sum(px) / len(px)
    except Exception:
        return None


def stage05_solar_sanity(image_path: str, gps: dict, exif_timestamps: dict,
                         cfg: PipelineConfig) -> StageResult:
    """Cheap forgery check (fast path): sun elevation at capture time vs
    image brightness. Night-tagged GPS + daylight photo = suspicious EXIF.

    Runs unconditionally: built-in solar math, no external dependency.
    """
    started = time.time()
    ts = (exif_timestamps or {}).get("original")
    if not ts or not gps:
        return StageResult("solar_sanity", "no_data", 0.0, {},
                           "needs capture time + GPS", time.time() - started)
    try:
        dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return StageResult("solar_sanity", "no_data", 0.0, {},
                           f"unparsable timestamp: {ts}", time.time() - started)
    sun = _sun_position(dt, gps["latitude"], gps["longitude"])
    brightness = _image_brightness(image_path)
    night = sun["elevation"] < -12.0
    conflict = night and brightness is not None and brightness > 60
    note = (f"FLAG: sun elevation {sun['elevation']} deg (night) but image brightness "
            f"{brightness:.0f}/255 suggests daylight - EXIF may be edited"
            if conflict else
            f"sun elevation {sun['elevation']} deg at capture time, "
            f"brightness {brightness:.0f}/255 - consistent" if brightness is not None else
            f"sun elevation {sun['elevation']} deg at capture time, brightness unknown")
    return StageResult("solar_sanity", "error" if conflict else "ok",
                       0.9 if conflict else 0.3,
                       {"sun": sun, "brightness": brightness, "conflict": conflict},
                       note, time.time() - started)


def stage2_solar(exif_timestamps: dict, gps: Optional[dict], cfg: PipelineConfig) -> StageResult:
    """Sun position at capture time -> cardinal orientation constraint.

    Fallback path has no GPS by definition, so this usually degrades to
    no_data; its real value is the forgery-flagging in the fast path.
    """
    started = time.time()
    if not cfg.use_solar:
        return StageResult("solar", "skipped", 0.0, {},
                           "disabled (PHOTO_GEOLOC_USE_SOLAR=0)", time.time() - started)
    ts = (exif_timestamps or {}).get("original")
    if not ts:
        return StageResult("solar", "no_data", 0.0, {"sun": None, "azimuth": None},
                           "no capture timestamp available", time.time() - started)
    if not gps:
        return StageResult("solar", "no_data", 0.0, {"sun": None, "azimuth": None},
                           "no GPS - sun position needs coordinates", time.time() - started)
    try:
        dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return StageResult("solar", "error", 0.0, {"sun": None, "azimuth": None},
                           f"unparsable timestamp: {ts}", time.time() - started)
    sun = _sun_position(dt, gps["latitude"], gps["longitude"])
    note = ("daytime" if sun["elevation"] > -6 else
            "civil/astronomical night" if sun["elevation"] > -18 else "astronomical night")
    return StageResult("solar", "ok", 0.3,
                       {"sun": sun, "azimuth": sun["azimuth"]},
                       f"sun elevation {sun['elevation']} deg, azimuth {sun['azimuth']} deg ({note})",
                       time.time() - started)