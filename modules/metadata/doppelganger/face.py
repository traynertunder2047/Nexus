"""Face detection + comparison primitives.

Detection: OpenCV Haar cascade (bundled with opencv-python). Comparison
uses two independent signals:
  - perceptual hash of the face crop (avhash, reused from Locus Sherlock)
    - near-identical photos (posters, reposts, avatars);
  - LBPH recognizer confidence when cv2.face is available - the same
    person across different crops, lighting and mild pose changes.

cv2 is optional: without it the mode degrades to whole-image hashing
with a clear trace note."""

from typing import Optional

from PIL import Image

from ..locus.sherlock import _avg_hash, _hamming, _is_uniform
from .config import DoppelConfig

try:
    import cv2
except ImportError:
    cv2 = None

try:
    import numpy as np
except ImportError:
    np = None

_CASCADE = None
_LBPH_SIZE = (128, 128)


def _cascade():
    global _CASCADE
    if _CASCADE is None and cv2 is not None:
        try:
            _CASCADE = cv2.CascadeClassifier(
                cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
        except Exception:
            _CASCADE = False
    return _CASCADE if _CASCADE else None


def detect_faces(img: Image.Image) -> list:
    """Detect faces; returns [(x, y, w, h)] in image coordinates."""
    cascade = _cascade()
    if cascade is None or np is None:
        return []
    try:
        gray = cv2.cvtColor(np.array(img.convert("RGB")), cv2.COLOR_RGB2GRAY)
        faces = cascade.detectMultiScale(gray, 1.1, 5, minSize=(48, 48))
        return [tuple(int(v) for v in f) for f in faces]
    except Exception:
        return []


def largest_face(img: Image.Image) -> Optional[Image.Image]:
    """Largest detected face crop with a small margin; None if no face."""
    faces = detect_faces(img)
    if not faces:
        return None
    x, y, w, h = max(faces, key=lambda f: f[2] * f[3])
    margin = int(0.15 * w)
    box = (max(0, x - margin), max(0, y - margin),
           min(img.width, x + w + margin), min(img.height, y + h + margin))
    return img.crop(box)


def face_hash(face: Image.Image) -> str:
    """Perceptual hash of the face crop (avhash; dependency-free)."""
    return _avg_hash(face.convert("RGB"))


def _lbph_distance(src: Image.Image, cand: Image.Image) -> Optional[float]:
    """LBPH recognizer confidence trained on the source face; lower = closer."""
    if cv2 is None or not hasattr(cv2, "face") or np is None:
        return None
    try:
        recognizer = cv2.face.LBPHFaceRecognizer_create()
        def _gray(im):
            return cv2.cvtColor(
                cv2.resize(np.array(im.convert("RGB")), _LBPH_SIZE),
                cv2.COLOR_RGB2GRAY)
        recognizer.train([_gray(src)], np.array([1]))
        label, confidence = recognizer.predict(_gray(cand))
        return float(confidence)
    except Exception:
        return None


def face_verdict(src: Image.Image, cand: Image.Image,
                 cfg: DoppelConfig) -> Optional[dict]:
    """Two-tier face gate: strong (hash) / lbph / weak (hash).

    strong -> face hash distance <= strong gate (near-identical face);
    lbph   -> LBPH confidence below threshold (same person, variant);
    weak   -> hash distance <= weak gate without further proof.
    Returns None when there is no match evidence.
    """
    if _is_uniform(src) or _is_uniform(cand):
        return None
    distance = _hamming(face_hash(src), face_hash(cand))
    if distance <= cfg.face_strong_gate:
        return {"tier": "strong", "distance": distance, "confidence": 0.7}
    lbph = _lbph_distance(src, cand)
    if lbph is not None and lbph <= cfg.lbph_threshold:
        return {"tier": "lbph", "distance": distance, "lbph": round(lbph, 1),
                "confidence": 0.5}
    if distance <= cfg.face_weak_gate:
        return {"tier": "weak", "distance": distance, "confidence": 0.3}
    return None