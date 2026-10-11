from modules.metadata.exif_extractor import (
    GPS_IFD_TAG,
    EXIF_IFD_TAG,
    _extract_gps,
    _extract_device,
    _extract_timestamps,
    _parse_exif_datetime,
    _gps_hemisphere,
    _parse_gps_rationals,
    run,
)


class StubExif:
    """Minimal Pillow Image.Exif stand-in: get_ifd(EXIF_IFD_TAG) raises,
    get_ifd(GPS_IFD_TAG) returns a GPS dict, plain get() reads 0th IFD tags."""

    def __init__(self, gps=None, tags=None, exif_ifd=None):
        self._gps = gps or {}
        self._tags = tags or {}
        self._exif_ifd = exif_ifd or {}

    def get_ifd(self, tag):
        if tag == EXIF_IFD_TAG:
            return self._exif_ifd
        if tag == GPS_IFD_TAG:
            return self._gps
        raise KeyError(tag)

    def get(self, key, default=None):
        return self._tags.get(key, default)


def test_parse_gps_rationals():
    assert _parse_gps_rationals(None) is None
    assert _parse_gps_rationals(41.5) == 41.5
    # (deg, min, sec)
    assert abs(_parse_gps_rationals((41, 54, 0.0)) - 41.9) < 1e-9
    assert _parse_gps_rationals("garbage") is None


def test_parse_exif_datetime():
    assert _parse_exif_datetime("2021:05:06 12:34:56") == "2021-05-06 12:34:56"
    assert _parse_exif_datetime("2021:05:06 12:34:56.789") == "2021-05-06 12:34:56.789000"
    assert _parse_exif_datetime("") is None
    assert _parse_exif_datetime("nonsense") is None


def test_gps_hemisphere():
    assert abs(_gps_hemisphere("N", 41.9) - 41.9) < 1e-9
    assert abs(_gps_hemisphere("S", 41.9) - (-41.9)) < 1e-9
    assert abs(_gps_hemisphere("E", 12.5) - 12.5) < 1e-9
    assert abs(_gps_hemisphere("W", 12.5) - (-12.5)) < 1e-9
    assert _gps_hemisphere("N", None) is None


def test_extract_gps_rome():
    gps = {
        1: "N",
        2: (41, 54, 0.0),   # 41.9
        3: "E",
        4: (12, 30, 0.0),   # 12.5
        6: 50,              # altitude
        5: 0,               # above sea level
    }
    exif = StubExif(gps=gps)
    out = _extract_gps(exif)
    assert abs(out["latitude"] - 41.9) < 1e-9
    assert abs(out["longitude"] - 12.5) < 1e-9
    assert out["altitude"] == 50.0
    assert out["altitude_ref"] == "above sea level"
    assert out["coords"] is not None


def test_extract_gps_missing():
    out = _extract_gps(StubExif())
    assert out["coords"] is None
    assert out["latitude"] is None


def test_extract_device_and_timestamps():
    exif = StubExif(
        tags={0x010F: "Canon"},
        exif_ifd={0x9003: "2020:01:02 03:04:05", 0xA434: "EF 50mm"},
    )
    dev = _extract_device(exif)
    assert dev["make"] == "Canon"
    assert dev["lens_model"] == "EF 50mm"
    ts = _extract_timestamps(exif)
    assert ts["original"] == "2020-01-02 03:04:05"
    assert ts["digitized"] is None


def test_run_missing_file():
    assert "error" in run("")
    assert "File not found" in run("nonexistent.jpg")["error"]


def test_run_plain_image_no_metadata(tmp_path):
    from PIL import Image

    p = tmp_path / "plain.png"
    Image.new("RGB", (10, 10), (0, 0, 0)).save(p)
    res = run(str(p))
    assert "error" not in res
    assert "No EXIF metadata found" in res["summary"]
    assert res["gps"]["coords"] is None
