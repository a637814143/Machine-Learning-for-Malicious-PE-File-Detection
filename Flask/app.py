"""Minimal Flask web service for malware detection.

This application is intentionally self-contained so that it does not depend on
modules outside of the ``Flask`` directory. The service exposes a simple web UI
that lets users upload a Portable Executable (PE) file for analysis. Results are
rendered as a human-readable report that can also be downloaded as JSON.

To connect this UI to a real machine-learning model, update ``MODEL_PATH`` and
extend :func:`ModelWrapper.predict` accordingly.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Tuple

from flask import (
    Flask,
    Response,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from werkzeug.utils import secure_filename

# Directory setup -----------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

# ``MODEL_PATH`` indicates where the trained model should be placed. Replace the
# placeholder path with the real model artifact when integrating with your
# production model.
MODEL_PATH = BASE_DIR / "model" / "malicious_pe_model.pkl"
MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {"exe", "dll", "sys", "drv", "ocx"}
MAX_CONTENT_LENGTH = 25 * 1024 * 1024  # 25 MiB


def create_app() -> Flask:
    """Application factory used by the WSGI server."""
    app = Flask(__name__)
    app.config.update(SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", "malware-ui"))
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

    model = ModelWrapper(MODEL_PATH)

    @app.route("/", methods=["GET", "POST"])
    def index():
        if request.method == "POST":
            file = request.files.get("file")
            if file is None or file.filename == "":
                flash("请先选择需要检测的文件。", "warning")
                return redirect(url_for("index"))

            if not allowed_file(file.filename):
                flash("仅支持上传常见的Windows可执行文件 (exe, dll, sys, drv, ocx)。", "danger")
                return redirect(url_for("index"))

            try:
                payload = file.read()
                if not payload:
                    raise ValueError("上传的文件为空，请提供有效的PE文件。")
                safe_name = secure_filename(file.filename) or "upload.bin"
                timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
                upload_path = UPLOAD_DIR / f"{timestamp}_{safe_name}"
                upload_path.write_bytes(payload)
                report = model.analyse_payload(file.filename, payload)
                report["stored_file"] = str(upload_path)
            except ValueError as exc:
                flash(str(exc), "danger")
                return redirect(url_for("index"))

            stored_report = persist_report(report)
            return render_template(
                "report.html",
                report=report,
                report_file=stored_report.stem,
            )

        return render_template("index.html", model_path=str(MODEL_PATH))

    @app.route("/reports/<path:report_name>.json")
    def download_report(report_name: str) -> Response:
        report_path = REPORT_DIR / f"{report_name}.json"
        if not report_path.is_file():
            flash("报告不存在或已被删除。", "danger")
            return redirect(url_for("index"))
        return send_file(report_path, mimetype="application/json", as_attachment=True)

    return app


class ModelWrapper:
    """Encapsulates the malware detection model.

    The default implementation provides a deterministic heuristic so that the
    application can be executed without the real model. To integrate your model,
    load it inside :meth:`__init__` and replace :meth:`predict` with actual
    inference logic.
    """

    def __init__(self, model_path: Path) -> None:
        self.model_path = model_path
        self.model = self._load_model()

    def _load_model(self) -> Any:
        """Load a trained model from ``self.model_path`` if it exists.

        The method intentionally avoids importing project-specific modules so
        that this file remains self-contained. When integrating your production
        model, feel free to import the necessary libraries here.
        """

        if self.model_path.exists():
            # Placeholder for custom loading logic. The file path is exposed so
            # you can drop in your serialized model artifact.
            # Example:
            #   import joblib
            #   return joblib.load(self.model_path)
            return self.model_path  # sentinel to indicate a real model is present

        # Fallback heuristic (no ML model available).
        return None

    def analyse_payload(self, filename: str, payload: bytes) -> Dict[str, Any]:
        if not payload:
            raise ValueError("上传的文件为空，请提供有效的PE文件。")

        score, label = self.predict(payload)
        sha256 = hashlib.sha256(payload).hexdigest()
        size_kb = len(payload) / 1024

        report = {
            "filename": filename,
            "sha256": sha256,
            "size_kb": round(size_kb, 2),
            "detection_score": round(score, 4),
            "label": label,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "model_path": str(self.model_path),
            "model_loaded": bool(self.model),
        }
        return report

    def predict(self, payload: bytes) -> Tuple[float, str]:
        if self.model is None:
            # Lightweight heuristic: flag files larger than 500KB and containing
            # uncommon byte patterns as suspicious. This logic is only for demo
            # purposes and should be replaced by real inference code.
            entropy = self._shannon_entropy(payload)
            size_score = min(len(payload) / (500 * 1024), 1.0)
            entropy_score = min(entropy / 8.0, 1.0)
            score = 0.6 * size_score + 0.4 * entropy_score
            label = "恶意 (Malicious)" if score >= 0.5 else "良性 (Benign)"
            return score, label

        # If a real model is present, ``self.model`` currently just stores the
        # path. Replace this block with actual predictions.
        # Example:
        #   features = feature_extractor(payload)
        #   proba = self.model.predict_proba([features])[0, 1]
        #   return float(proba), "Malicious" if proba >= 0.5 else "Benign"
        return 0.5, "待接入真实模型 (Pending model integration)"

    @staticmethod
    def _shannon_entropy(payload: bytes) -> float:
        if not payload:
            return 0.0
        byte_counts = [0] * 256
        for b in payload:
            byte_counts[b] += 1
        entropy = 0.0
        length = len(payload)
        for count in byte_counts:
            if count == 0:
                continue
            p = count / length
            entropy -= p * math.log2(p)
        return entropy


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def persist_report(report: Dict[str, Any]) -> Path:
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    original_name = Path(report["filename"]).name
    safe_name = secure_filename(original_name) or "report"
    base = f"{timestamp}_{safe_name}"
    report_path = REPORT_DIR / f"{base}.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report_path


if __name__ == "__main__":
    application = create_app()
    application.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), debug=True)
