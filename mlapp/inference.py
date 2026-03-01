from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
from thrember.features import PEFeatureExtractor

# NEW: human-readable evidence
from mlapp.evidence import explain_pdf, explain_apk_light


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
        # better UX: do not crash the whole request
        return None
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
    if model is None:
        return 0, "unknown", {"error": f"Model is missing: {model_path.name}. Put it into artifacts/ or retrain."}

    if hasattr(model, "predict_proba"):
        p = float(model.predict_proba(vec.reshape(1, -1))[0, 1])
    elif hasattr(model, "decision_function"):
        z = float(model.decision_function(vec.reshape(1, -1))[0])
        p = 1.0 / (1.0 + np.exp(-z))
    else:
        return 0, "unknown", {"error": "Model must support predict_proba or decision_function"}

    score = int(round(p * 100))
    verdict = verdict_from_score(score)

    reasons = {
        "model": model_name,
        # technical (keep for debug)
        "top_contributions": _top_linear_contribs(model, vec, top_k=10),
        "notes": [
            "Features are EMBERv3/thrember vectors. 'f0..fN' are vector indices.",
            "Human-readable reasons are provided in reasons['user_summary'] (evidence-based).",
        ],
    }
    return score, verdict, reasons


def infer(file_path: str, mime_type: str, apk_model_path: Path, pdf_model_path: Path) -> InferenceResult:
    ftype = detect_file_type(file_path, mime_type)

    with open(file_path, "rb") as f:
        b = f.read()

    if ftype == "APK":
        score, verdict, reasons = predict_bytes(b, apk_model_path, "apk")

        # NEW: human-readable summary
        ev = explain_apk_light(file_path)
        reasons["user_summary"] = {
            "reasons": ev.get("reasons", []),
            "categories": ev.get("categories", []),
            "evidence": ev.get("evidence", {}),
        }

        return InferenceResult("APK", score, verdict, "apk", reasons)

    if ftype == "PDF":
        score, verdict, reasons = predict_bytes(b, pdf_model_path, "pdf")

        # NEW: human-readable summary
        ev = explain_pdf(b)
        reasons["user_summary"] = {
            "reasons": ev.get("reasons", []),
            "categories": ev.get("categories", []),
            "evidence": ev.get("evidence", {}),
        }

        return InferenceResult("PDF", score, verdict, "pdf", reasons)

    return InferenceResult("OTHER", 0, "unknown", "", {
        "error": "Unsupported file type. Add a new model + evidence extractor and update router."
    })
