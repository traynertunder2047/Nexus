"""
EXIF Metadata Extractor
=======================
Extracts the key forensic metadata from an uploaded image:

  - GPS coordinates : latitude, longitude, altitude (with N/S/E/W refs),
                      converted from EXIF rationals to decimal degrees
  - device          : camera make/model, editing software, lens, serial
  - timestamps      : original creation (DateTimeOriginal), digitized
                      (DateTimeDigitized) and last-modified (DateTime)

Works on JPEG/PNG/TIFF/WEBP via Pillow (getexif + GPS IFD). Missing tags
are reported as None rather than errors; unsupported formats and corrupt
files produce a clear "error" dict. Note: the device operating system is
NOT stored in EXIF (it lives in other containers like MP4 or DRM), so it
cannot be extracted from images.
"""

#test dosen't return results, exif data is stripped so further tests are need.

from datetime import datetime
import os

from PIL import Image
from PIL.ExifTags import Base as EXIF_TAGS
from PIL.ExifTags import GPSTAGS

SUPPORTED_FORMATS = {"JPEG", "PNG", "TIFF", "WEBP"}

GPS_IFD_TAG = 0x8825
EXIF_IFD_TAG = 0x8769

GPS_LATITUDE = 0x0002
GPS_LATITUDE_REF = 0x0001
GPS_LONGITUDE = 0x0004
GPS_LONGITUDE_REF = 0x0003
GPS_ALTITUDE = 0x0006
GPS_ALTITUDE_REF = 0x0005

EXIF_DATETIME_ORIGINAL = 0x9003
EXIF_DATETIME_DIGITIZED = 0x9004
DATETIME_MODIFIED = 0x0132
MAKE = 0x010F
MODEL = 0x0110
SOFTWARE = 0x0131
LENS_MODEL = 0xA434
SERIAL_NUMBER = 0xA431


def _parse_gps_rationals(value):
    """Convert EXIF degree/minutes/seconds value to decimal degrees.

    Accepts a single rational, a 3-part (d, m, s) rational tuple, a
    2-part (deg, min) tuple, or a plain number, and returns a float or
    None.
    """
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        pass
    try:
        parts = tuple(float(part) for part in value)
    except (TypeError, ValueError):
        return None
    if len(parts) == 3:
        deg, minutes, seconds = parts
        return deg + minutes / 60.0 + seconds / 3600.0
    if len(parts) == 2:
        deg, minutes = parts
        return deg + minutes / 60.0
    if len(parts) == 1:
        return parts[0]
    return None


def _parse_exif_datetime(raw):
    """Parse the 'YYYY:MM:DD HH:MM:SS' EXIF timestamp into ISO format.

    Returns None when the value is missing or unparseable (some cameras
    add seconds precision or trailing whitespace).
    """
    if not raw:
        return None
    raw = str(raw).strip()
    for fmt in ("%Y:%m:%d %H:%M:%S", "%Y:%m:%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt).isoformat(sep=" ")
        except ValueError:
            continue
    return None


def _gps_hemisphere(ref, decimal):
    """Apply N/S/E/W sign to a decimal coordinate."""
    if decimal is None or not ref:
        return None
    return -abs(decimal) if ref.strip().upper() in ("S", "W") else abs(decimal)


def _extract_gps(exif_ifd):
    """Read the GPS IFD and return normalized coordinates."""
    if exif_ifd is None:
        return {
            "latitude": None,
            "longitude": None,
            "altitude": None,
            "latitude_ref": None,
            "longitude_ref": None,
            "altitude_ref": None,
            "coords": None,
        }
    try:
        gps_ifd = exif_ifd.get_ifd(GPS_IFD_TAG)
    except (KeyError, ValueError, AttributeError):
        gps_ifd = {}

    lat = _parse_gps_rationals(gps_ifd.get(GPS_LATITUDE))
    lon = _parse_gps_rationals(gps_ifd.get(GPS_LONGITUDE))
    alt = _parse_gps_rationals(gps_ifd.get(GPS_ALTITUDE))

    lat_ref = gps_ifd.get(GPS_LATITUDE_REF)
    lon_ref = gps_ifd.get(GPS_LONGITUDE_REF)
    alt_ref = gps_ifd.get(GPS_ALTITUDE_REF)

    if isinstance(alt_ref, bytes):
        alt_ref = int.from_bytes(alt_ref, "little") if alt_ref else 0
    else:
        try:
            alt_ref = int(alt_ref)
        except (TypeError, ValueError):
            alt_ref = None

    latitude = _gps_hemisphere(lat_ref, lat)
    longitude = _gps_hemisphere(lon_ref, lon)

    altitude = None
    if alt is not None:
        altitude = -abs(alt) if alt_ref == 1 else abs(alt)

    return {
        "latitude": latitude,
        "longitude": longitude,
        "altitude": altitude,
        "latitude_ref": str(lat_ref).strip() if lat_ref else None,
        "longitude_ref": str(lon_ref).strip() if lon_ref else None,
        "altitude_ref": "below sea level" if alt_ref == 1 else "above sea level" if alt_ref == 0 else None,
        "coords": [latitude, longitude] if (latitude is not None and longitude is not None) else None,
    }


def _extract_device(exif):
    """Read camera/software tags from the 0th and Exif IFDs."""
    exif_ifd = {}
    try:
        exif_ifd = exif.get_ifd(EXIF_IFD_TAG)
    except (KeyError, ValueError, AttributeError):
        pass

    return {
        "make": exif.get(MAKE),
        "model": exif.get(MODEL),
        "software": exif.get(SOFTWARE),
        "lens_model": exif_ifd.get(LENS_MODEL),
        "serial_number": exif_ifd.get(SERIAL_NUMBER),
    }


def _extract_timestamps(exif):
    """Read the three EXIF timestamps."""
    exif_ifd = {}
    try:
        exif_ifd = exif.get_ifd(EXIF_IFD_TAG)
    except (KeyError, ValueError, AttributeError):
        pass

    return {
        "original": _parse_exif_datetime(exif_ifd.get(EXIF_DATETIME_ORIGINAL)),
        "digitized": _parse_exif_datetime(exif_ifd.get(EXIF_DATETIME_DIGITIZED)),
        "modified": _parse_exif_datetime(exif.get(DATETIME_MODIFIED)),
    }


def run(image_path: str) -> dict:
    """Extract GPS, device and timestamp metadata from an image file."""
    if not image_path:
        return {"error": "No image path provided."}
    if not os.path.isfile(image_path):
        return {"error": f"File not found: {image_path}"}

    try:
        with Image.open(image_path) as img:
            if img.format not in SUPPORTED_FORMATS:
                return {"error": f"Unsupported format: {img.format}. "
                                 f"Supported: {', '.join(sorted(SUPPORTED_FORMATS))}"}
            exif = img.getexif()
    except (OSError, ValueError, SyntaxError, Image.UnidentifiedImageError) as exc:
        return {"error": f"Failed to read image: {exc}"}

    gps = _extract_gps(exif)
    device = _extract_device(exif)
    timestamps = _extract_timestamps(exif)

    has_any = gps["coords"] is not None or any(v is not None for v in device.values()) or \
        any(v is not None for v in timestamps.values())
    if not has_any:
        summary = "No EXIF metadata found in this image."
    else:
        parts = []
        if gps["coords"]:
            parts.append("GPS coordinates present")
        if any(v is not None for v in device.values()):
            parts.append("device info present")
        if any(v is not None for v in timestamps.values()):
            parts.append("timestamps present")
        summary = "Found: " + ", ".join(parts) + "."

    result = {
        "file": {
            "name": os.path.basename(image_path),
            "format": img.format,
            "size_bytes": os.path.getsize(image_path),
        },
        "gps": gps,
        "device": device,
        "timestamps": timestamps,
        "summary": summary,
    }

    if gps["coords"]:
        lat, lon = gps["coords"]
        result["gps"]["maps_url"] = f"https://www.google.com/maps?q={lat},{lon}"

    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python exif_extractor.py <image_path>")
        sys.exit(1)
    print(run(sys.argv[1]))
