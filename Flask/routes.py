"""HTTP routes for the Flask service."""
from __future__ import annotations

import json
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, MutableMapping

import numpy as np
from flask import Blueprint, Flask, jsonify, render_template, request
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from core.report_builder import build_markdown_report
from scripts.D import DEFAULT_MODEL, DEFAULT_THRESHOLD, predict_file_with_features

MODEL_PATH = str(DEFAULT_MODEL)
THRESHOLD = float(DEFAULT_THRESHOLD)

bp = Blueprint("pe_detection", __name__)


def _service_description() -> dict[str, Any]:
    """Return metadata describing the available HTTP endpoints."""

    return {
        "service": "Machine Learning PE Detector",
        "description": "REST API mirroring the GUI's malicious file analysis pipeline.",
        "endpoints": {
            "GET /health": "Service heartbeat.",
            "POST /predict": "Analyse an uploaded PE file or an existing file path.",
        },
        "model_path": MODEL_PATH,
        "threshold": THRESHOLD,
    }


def register_routes(app: Flask) -> None:
    """Attach all routes to *app*.

    Using a blueprint keeps the view functions easy to test and the
    registration logic explicit.
    """

    app.register_blueprint(bp)


@bp.get("/")
def index() -> Any:
    """Serve the neon "hacker" interface or JSON metadata for API clients."""

    accepts = request.accept_mimetypes
    wants_json = accepts["application/json"] >= accepts["text/html"] and accepts["application/json"] > 0
    if wants_json:
        return jsonify(_service_description())

    return render_template("index.html", current_year=datetime.now().year)


@bp.get("/service-info")
def service_info() -> Any:
    """Expose endpoint metadata for API discovery tools."""

    return jsonify(_service_description())


@bp.get("/health")
def health() -> Any:
    """Simple heartbeat endpoint used for monitoring."""

    return jsonify({"status": "ok"})


@bp.post("/predict")
def predict() -> Any:
    """Analyse a PE file with the same logic as the desktop GUI."""

    payload = _extract_payload(request)
    if payload.error:
        return jsonify({"error": payload.error}), payload.status

    try:
        result = predict_file_with_features(
            payload.file_path,
            model_path=MODEL_PATH,
            threshold=THRESHOLD,
        )
    except FileNotFoundError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # pragma: no cover - defensive runtime safeguard
        return jsonify({"error": f"分析失败: {exc}"}), 500
    finally:
        if payload.cleanup:
            try:
                Path(payload.cleanup).unlink(missing_ok=True)
            except Exception:
                pass

    clean_result = _to_builtin_types(result)

    display_path = payload.display_path or clean_result.get("file_path")
    if display_path:
        clean_result["file_path"] = str(display_path)

    report_markdown = ""
    report_filename = None
    try:
        if display_path:
            report_markdown = build_markdown_report(Path(display_path), clean_result)
            report_filename = _report_filename(display_path)
    except Exception:
        report_markdown = ""
        report_filename = None

    clean_result["report_markdown"] = report_markdown
    if report_filename:
        clean_result["report_filename"] = report_filename
    else:
        clean_result["report_filename"] = _report_filename(display_path or "report")
    clean_result["report_generated_at"] = datetime.now().isoformat(timespec="seconds")

    return jsonify(clean_result)


class Payload:
    """Container describing what should be analysed."""

    __slots__ = ("file_path", "display_path", "cleanup", "status", "error")

    def __init__(
        self,
        file_path: str | None = None,
        *,
        display_path: str | None = None,
        cleanup: str | None = None,
        status: int = 200,
        error: str | None = None,
    ) -> None:
        self.file_path = file_path
        self.display_path = display_path or file_path
        self.cleanup = cleanup
        self.status = status
        self.error = error


class RequestPayload(Payload):
    """Helper that bundles parsing results."""


def _extract_payload(req) -> RequestPayload:
    """Parse the incoming HTTP request.

    The GUI allows users to analyse a file from disk. The HTTP interface mirrors
    this flow: clients can either upload a file or provide an existing path in
    JSON/form fields while the service supplies the bundled model and threshold.
    """

    if req.files:
        uploaded = req.files.get("file")
        if not isinstance(uploaded, FileStorage) or uploaded.filename == "":
            return RequestPayload(status=400, error="未接收到有效的文件上传。")

        raw_name = Path(uploaded.filename or "upload.bin").name
        filename = secure_filename(raw_name) or "upload.bin"
        suffix = Path(filename).suffix or ".bin"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            uploaded.save(tmp)
            temp_path = tmp.name
        return RequestPayload(temp_path, display_path=raw_name, cleanup=temp_path)

    data = {}
    if req.is_json:
        data = req.get_json(silent=True) or {}
    elif req.form:
        data = req.form

    path_value = data.get("path") if isinstance(data, MutableMapping) else None
    if not path_value:
        return RequestPayload(status=400, error="请上传文件或提供 'path' 字段。")

    expanded = Path(path_value).expanduser()
    return RequestPayload(str(expanded), display_path=str(expanded))


def _report_filename(file_path: str | Path) -> str:
    """Build a friendly markdown filename for download."""

    base = Path(file_path).stem if file_path else "report"
    safe = secure_filename(base) or (base.strip() or "report")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{safe}-report-{stamp}.md"


def _to_builtin_types(data: Any) -> Any:
    """Recursively convert data into JSON serialisable Python builtins."""

    if isinstance(data, dict):
        return {str(key): _to_builtin_types(value) for key, value in data.items()}
    if isinstance(data, (list, tuple, set)):
        return [_to_builtin_types(item) for item in data]
    if isinstance(data, (str, int, bool)) or data is None:
        return data
    if isinstance(data, float):
        if np.isnan(data) or np.isinf(data):
            return float(0)
        return float(data)
    if isinstance(data, np.generic):
        return data.item()
    if isinstance(data, Path):
        return str(data)
    try:
        return json.loads(json.dumps(data))
    except Exception:
        return str(data)


__all__ = ["register_routes", "bp"]
