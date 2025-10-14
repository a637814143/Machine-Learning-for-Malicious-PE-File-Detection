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
from typing import Any, Dict, Iterable, List, Tuple

import lightgbm as lgb
import numpy as np
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

from ml_pipeline import extract_features, vectorize_features

# Directory setup -----------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

# ``MODEL_PATH`` points to the LightGBM model exported by the training
# pipeline.  By default it expects the project's ``model.txt`` located at the
# repository root, but this can be overridden using the ``MALWARE_MODEL``
# environment variable.
_MODEL_ENV = os.environ.get("MALWARE_MODEL")
if _MODEL_ENV:
    MODEL_PATH = Path(_MODEL_ENV).expanduser()
else:
    MODEL_PATH = BASE_DIR.parent / "model.txt"

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
                report = model.analyse_file(file.filename, upload_path)
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
    """Encapsulates the LightGBM model trained by the project."""

    THRESHOLD = 0.5

    def __init__(self, model_path: Path) -> None:
        self.model_path = model_path
        self.model = self._load_model()

    def _load_model(self) -> Any:
        if self.model_path and self.model_path.exists():
            try:
                return lgb.Booster(model_file=str(self.model_path))
            except Exception as exc:
                print(f"无法加载 LightGBM 模型 {self.model_path}: {exc}")
        return None

    def analyse_file(self, filename: str, file_path: Path) -> Dict[str, Any]:
        if not file_path.is_file():
            raise ValueError("上传文件保存失败，请重试。")

        payload = file_path.read_bytes()
        if not payload:
            raise ValueError("上传的文件为空，请提供有效的PE文件。")

        features = extract_features(file_path)
        vector = vectorize_features(features).astype(np.float32)

        score, label = self.predict(vector, features)
        sha256 = features.get("sha256") or hashlib.sha256(payload).hexdigest()
        md5 = features.get("md5") or hashlib.md5(payload).hexdigest()
        size_kb = len(payload) / 1024

        insights = self._build_analysis(features, score)

        report = {
            "filename": filename,
            "sha256": sha256,
            "md5": md5,
            "size_kb": round(size_kb, 2),
            "detection_score": round(score, 4),
            "label": label,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "model_path": str(self.model_path),
            "model_loaded": bool(self.model),
            "stored_file": str(file_path),
            "insights": insights,
        }
        return report

    def predict(self, vector: np.ndarray, features: Dict[str, Any]) -> Tuple[float, str]:
        if self.model is not None:
            try:
                probability = float(self.model.predict(vector.reshape(1, -1))[0])
            except Exception:
                raw_score = float(self.model.predict(vector.reshape(1, -1), raw_score=True)[0])
                probability = self._sigmoid(raw_score)
        else:
            probability = self._heuristic_probability(vector, features)

        label = "恶意 (Malicious)" if probability >= self.THRESHOLD else "良性 (Benign)"
        return probability, label

    @staticmethod
    def _sigmoid(value: float) -> float:
        return 1.0 / (1.0 + math.exp(-value))

    def _heuristic_probability(self, vector: np.ndarray, features: Dict[str, Any]) -> float:
        general = features.get("general", {}) or {}
        strings = features.get("strings", {}) or {}
        sections = features.get("section", {}).get("sections", []) or []

        size_score = min(float(general.get("size", 0)) / (600 * 1024), 1.0)
        suspicious_strings = len(strings.get("suspicious_strings", []))
        string_score = min(suspicious_strings / 5.0, 1.0)
        high_entropy_sections = sum(1 for section in sections if float(section.get("entropy", 0)) >= 7.5)
        entropy_score = min(high_entropy_sections / max(len(sections), 1), 1.0)

        combined = 0.4 * size_score + 0.35 * string_score + 0.25 * entropy_score
        return max(0.0, min(combined, 1.0))

    def _build_analysis(self, features: Dict[str, Any], score: float) -> Dict[str, Any]:
        strings = features.get("strings", {}) or {}
        sections = features.get("section", {}) or {}
        imports = features.get("imports", {}) or {}
        general = features.get("general", {}) or {}

        suspicious_strings: List[str] = strings.get("suspicious_strings", [])[:6]
        high_entropy_sections = [
            section
            for section in sections.get("sections", []) or []
            if float(section.get("entropy", 0)) >= 7.5
        ]
        total_imports = sum(len(entries) for entries in imports.values() if isinstance(entries, Iterable))
        has_signature = bool(general.get("has_signature"))

        bullets: List[str] = []
        if score >= self.THRESHOLD:
            bullets.append("模型判定恶意概率较高，请谨慎处理该文件。")
            if suspicious_strings:
                bullets.append("检测到潜在恶意命令片段，例如：" + "；".join(suspicious_strings[:3]))
            if high_entropy_sections:
                bullets.append(f"发现 {len(high_entropy_sections)} 个高熵节区，疑似存在壳或加密。")
            if total_imports > 300:
                bullets.append(f"导入函数数量达到 {total_imports} 个，复杂度异常。")
        else:
            bullets.append("模型判定倾向于良性，未发现显著恶意特征。")
            if has_signature:
                bullets.append("文件包含数字签名，提高可信度。")
            if not high_entropy_sections:
                bullets.append("节区熵值平稳，未见明显壳特征。")
            if total_imports and total_imports < 80:
                bullets.append(f"导入函数数量较少（约 {total_imports} 个），符合轻量级程序特征。")

        insights = {
            "headline": bullets[0] if bullets else "",
            "bullets": bullets,
            "suspicious_strings": suspicious_strings,
            "top_imports": self._top_imports(imports),
            "high_entropy_sections": [section.get("name") for section in high_entropy_sections[:5]],
        }
        return insights

    def _top_imports(self, imports: Dict[str, Iterable[str]], limit: int = 5) -> List[str]:
        ranked: List[Tuple[int, str]] = []
        for library, entries in imports.items():
            if isinstance(entries, Iterable):
                count = len(list(entries)) if not isinstance(entries, list) else len(entries)
            else:
                count = 0
            ranked.append((count, str(library)))
        ranked.sort(key=lambda item: item[0], reverse=True)
        return [f"{name} ({count})" for count, name in ranked[:limit] if name]


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
