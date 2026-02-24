from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import numpy as np
import joblib
from thrember.features import PEFeatureExtractor

@dataclass
class InferenceResult:
    detected_type: str
    score_percent: int
    verdict: str
    model_used: str
    reasons: dict

def detect_file_type(file_path: str, mime_type: str | None = None) -> str:
    p = Path(file_path)
    ext = p.suffix.lower()

    if mime_type:
        mt = mime_type.lower()
        if "pdf" in mt:
            return "PDF"
        if "android.package-archive" in mt or "vnd.android.package-archive" in mt:
            return "APK"

    if ext == ".pdf":
        return "PDF"
    if ext == ".apk":
        return "APK"
    return "OTHER"

def verdict_from_score(score_percent: int) -> str:
    if score_percent >= 70:
        return "malicious"
    if score_percent >= 40:
        return "suspicious"
    return "benign"

def load_model(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"Model not found: {path}")
    return joblib.load(path)

def _top_linear_contribs(model, x: np.ndarray, top_k: int = 12):
    if not hasattr(model, "coef_"):
        return []
    w = model.coef_[0]
    contrib = w * x
    idxs = np.argsort(np.abs(contrib))[::-1][:top_k]
    return [
        {"feature": f"f{i}", "value": float(x[i]), "weight": float(w[i]), "contribution": float(contrib[i])}
        for i in idxs
    ]

def predict_bytes(file_bytes: bytes, model_path: Path, model_name: str) -> tuple[int, str, dict]:
    extractor = PEFeatureExtractor()
    vec = np.array(extractor.feature_vector(file_bytes), dtype=np.float32)
    model = load_model(model_path)

    if hasattr(model, "predict_proba"):
        p = float(model.predict_proba(vec.reshape(1, -1))[0, 1])
    else:
        if hasattr(model, "decision_function"):
            z = float(model.decision_function(vec.reshape(1, -1))[0])
            p = 1.0 / (1.0 + np.exp(-z))
        else:
            raise TypeError("Model must support predict_proba or decision_function")

    score = int(round(p * 100))
    verdict = verdict_from_score(score)
    reasons = {
        "model": model_name,
        "top_contributions": _top_linear_contribs(model, vec, top_k=10),
        "notes": [
            "Features are EMBERv3/thrember vectors. 'f0..fN' are vector indices.",
            "For APK/PDF, thrember uses general info + byte stats + string stats (subset of EMBERv3).",
        ],
    }
    return score, verdict, reasons

def infer(file_path: str, mime_type: str, apk_model_path: Path, pdf_model_path: Path) -> InferenceResult:
    ftype = detect_file_type(file_path, mime_type)
    with open(file_path, "rb") as f:
        b = f.read()

    if ftype == "APK":
        score, verdict, reasons = predict_bytes(b, apk_model_path, "apk")
        return InferenceResult("APK", score, verdict, "apk", reasons)

    if ftype == "PDF":
        score, verdict, reasons = predict_bytes(b, pdf_model_path, "pdf")
        return InferenceResult("PDF", score, verdict, "pdf", reasons)

    return InferenceResult("OTHER", 0, "unknown", "", {
        "error": "Unsupported file type for the current MVP. Add a new model+router entry to support it."
    })
