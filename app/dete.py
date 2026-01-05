#!/usr/bin/env python3
"""One-click PE detection GUI (static ML + dynamic sandbox)."""

from __future__ import annotations

import json
import sys
from html import escape
from pathlib import Path
from typing import Any, Dict

import requests
from PyQt5 import QtCore, QtGui, QtWidgets

# Ensure project root is importable when running as a script
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.D import DETECTION_MODES, resolve_detection_mode, predict_file_with_features  # noqa: E402
from app.ui.dynamic_analysis_dialog import DynamicAnalysisDialog  # noqa: E402


def _normalise_sandbox_url(raw: str) -> str:
    """Turn user input like 127.0.0.1:5000 into a full /upload endpoint."""
    value = raw.strip()
    if not value:
        raise ValueError("请输入沙箱服务地址和端口")
    if not (value.startswith("http://") or value.startswith("https://")):
        value = "http://" + value
    value = value.rstrip("/")
    if not value.lower().endswith("/upload"):
        value = f"{value}/upload"
    return value


class DetectionWorker(QtCore.QThread):
    """Background worker that runs static prediction and dynamic sandbox call."""

    completed = QtCore.pyqtSignal(dict)
    failed = QtCore.pyqtSignal(str)

    def __init__(self, file_path: str, sandbox_target: str, mode_key: str, parent: QtCore.QObject | None = None):
        super().__init__(parent)
        self._file_path = Path(file_path)
        self._sandbox_target = sandbox_target
        self._mode_key = mode_key

    def run(self) -> None:  # pragma: no cover - GUI thread
        try:
            payload = self._perform_detection()
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))
        else:
            self.completed.emit(payload)

    def _perform_detection(self) -> Dict[str, Any]:
        if not self._file_path.exists() or not self._file_path.is_file():
            raise FileNotFoundError(f"未找到需要检测的文件: {self._file_path}")

        result: Dict[str, Any] = {"file": str(self._file_path), "mode_key": self._mode_key}

        try:
            mode = resolve_detection_mode(self._mode_key)
            result["static"] = predict_file_with_features(
                str(self._file_path),
                threshold=mode.threshold,
                mode_key=self._mode_key,
            )
        except Exception as exc:  # noqa: BLE001
            result["static_error"] = str(exc)

        try:
            url = _normalise_sandbox_url(self._sandbox_target)
            result["dynamic"] = self._call_sandbox(url)
        except Exception as exc:  # noqa: BLE001
            result["dynamic_error"] = str(exc)

        return result

    def _call_sandbox(self, url: str) -> Dict[str, Any]:
        try:
            with self._file_path.open("rb") as fh:
                files = {"file": (self._file_path.name, fh)}
                response = requests.post(url, files=files, timeout=600)
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as exc:  # pragma: no cover - network guarded by UI
            raise RuntimeError(f"动态检测服务不可用: {exc}") from exc
        except ValueError as exc:  # pragma: no cover - malformed response
            raise RuntimeError("动态检测返回值不是有效的 JSON") from exc

        if isinstance(data, dict) and data.get("error"):
            raise RuntimeError(str(data["error"]))
        if not isinstance(data, dict):
            raise RuntimeError("动态检测返回了未知的数据格式")
        return data


class DetectionWindow(QtWidgets.QWidget):
    """Compact window combining static ML prediction with sandbox upload."""

    def __init__(self) -> None:
        super().__init__()
        self._worker: DetectionWorker | None = None
        self._formatter = DynamicAnalysisDialog(self)
        self._formatter.hide()
        self._build_ui()
        self._apply_style()

    # ------------------------------------------------------------------ UI setup
    def _build_ui(self) -> None:
        self.setWindowTitle("PE 文件一键检测")
        self.setMinimumSize(1080, 720)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        header = QtWidgets.QLabel("PE 文件一键检测")
        header.setAlignment(QtCore.Qt.AlignCenter)
        header.setStyleSheet("font-size:28px; font-weight:700; letter-spacing:1px;")
        layout.addWidget(header)

        sub = QtWidgets.QLabel("静态机器学习 + 动态沙箱，点击一次立即获取结论")
        sub.setAlignment(QtCore.Qt.AlignCenter)
        sub.setWordWrap(True)
        sub.setStyleSheet("color:#94a3b8; font-size:14px;")
        layout.addWidget(sub)

        form_card = QtWidgets.QFrame()
        form_card.setObjectName("card")
        form_layout = QtWidgets.QGridLayout(form_card)
        form_layout.setContentsMargins(18, 18, 18, 18)
        form_layout.setHorizontalSpacing(14)
        form_layout.setVerticalSpacing(10)

        lbl_file = QtWidgets.QLabel("PE 文件路径")
        self.edit_file = QtWidgets.QLineEdit()
        self.edit_file.setPlaceholderText("选择或粘贴待检测的 .exe/.dll 路径")
        self.edit_file.setClearButtonEnabled(True)
        btn_browse = QtWidgets.QPushButton("浏览")
        btn_browse.clicked.connect(self._select_file)

        lbl_sandbox = QtWidgets.QLabel("沙箱地址:端口")
        self.edit_sandbox = QtWidgets.QLineEdit()
        self.edit_sandbox.setPlaceholderText("例如 127.0.0.1:5000 或 http://192.168.1.10:6000/upload")
        self.edit_sandbox.setClearButtonEnabled(True)

        lbl_mode = QtWidgets.QLabel("检测模式")
        self.combo_mode = QtWidgets.QComboBox()
        self._populate_modes()

        self.btn_detect = QtWidgets.QPushButton("一键检测")
        self.btn_detect.setObjectName("primary")
        self.btn_detect.setMinimumHeight(46)
        self.btn_detect.clicked.connect(self._trigger_detection)

        form_layout.addWidget(lbl_file, 0, 0)
        form_layout.addWidget(self.edit_file, 0, 1)
        form_layout.addWidget(btn_browse, 0, 2)
        form_layout.addWidget(lbl_sandbox, 1, 0)
        form_layout.addWidget(self.edit_sandbox, 1, 1)
        form_layout.addWidget(QtWidgets.QLabel(""), 1, 2)
        form_layout.addWidget(lbl_mode, 2, 0)
        form_layout.addWidget(self.combo_mode, 2, 1)
        form_layout.addWidget(self.btn_detect, 3, 0, 1, 3)

        layout.addWidget(form_card)

        self.status_label = QtWidgets.QLabel("准备就绪")
        self.status_label.setStyleSheet("color:#a5b4fc; font-weight:600;")
        layout.addWidget(self.status_label)

        self.result_browser = QtWidgets.QTextBrowser()
        self.result_browser.setOpenExternalLinks(True)
        layout.addWidget(self.result_browser, 1)

    def _apply_style(self) -> None:
        palette = self.palette()
        palette.setColor(QtGui.QPalette.Window, QtGui.QColor("#0b1221"))
        palette.setColor(QtGui.QPalette.Base, QtGui.QColor("#0b1221"))
        palette.setColor(QtGui.QPalette.Text, QtGui.QColor("#e2e8f0"))
        self.setPalette(palette)

        self.setStyleSheet(
            """
            QWidget { color:#e2e8f0; font-family:'Segoe UI','Microsoft YaHei',sans-serif; background-color:#0b1221; }
            QFrame#card { background: rgba(255,255,255,0.03); border:1px solid #1f2937; border-radius:12px; }
            QLabel { font-size:14px; }
            QLineEdit { background: rgba(255,255,255,0.06); border:1px solid #334155; border-radius:10px; padding:10px 12px; font-size:14px; }
            QComboBox { background: rgba(255,255,255,0.06); border:1px solid #334155; border-radius:10px; padding:10px 12px; font-size:14px; }
            QComboBox::drop-down { width:24px; }
            QPushButton { background:#1f2937; border:1px solid #334155; border-radius:10px; padding:10px 16px; font-weight:600; }
            QPushButton:hover { border-color:#4f46e5; color:#c7d2fe; }
            QPushButton#primary { background:#2563eb; border-color:#1d4ed8; color:#f8fafc; }
            QPushButton#primary:hover { background:#1d4ed8; }
            QTextBrowser { background:rgba(255,255,255,0.04); border:1px solid #1f2937; border-radius:14px; padding:16px; font-size:14px; }
            """
        )

    def _populate_modes(self) -> None:
        self.combo_mode.clear()
        for key, mode in DETECTION_MODES.items():
            display = f"{mode.label} · 阈值 {mode.threshold:.4f}"
            idx = self.combo_mode.count()
            self.combo_mode.addItem(display, key)
            self.combo_mode.setItemData(idx, mode.description, QtCore.Qt.ToolTipRole)
        if self.combo_mode.count():
            self.combo_mode.setCurrentIndex(0)

    # ------------------------------------------------------------------ Actions
    def _select_file(self) -> None:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "选择 PE 文件",
            "",
            "PE Files (*.exe *.dll *.sys *.bin *.scr *.ocx);;All Files (*)",
        )
        if path:
            self.edit_file.setText(path)

    def _trigger_detection(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return

        file_path = self.edit_file.text().strip()
        sandbox_target = self.edit_sandbox.text().strip()

        if not file_path:
            self._show_status("请选择需要检测的 PE 文件", error=True)
            return
        if not sandbox_target:
            self._show_status("请输入沙箱服务地址及端口", error=True)
            return

        mode_key = self.combo_mode.currentData() or next(iter(DETECTION_MODES.keys()))

        self.result_browser.clear()
        self._show_status("正在检测，请稍候…", busy=True)
        self.btn_detect.setEnabled(False)
        self.btn_detect.setText("检测中…")

        self._worker = DetectionWorker(file_path, sandbox_target, mode_key, self)
        self._worker.completed.connect(self._handle_completed)
        self._worker.failed.connect(self._handle_failed)
        self._worker.finished.connect(self._reset_state)
        self._worker.start()

    def _reset_state(self) -> None:
        self.btn_detect.setEnabled(True)
        self.btn_detect.setText("一键检测")
        self._worker = None

    def _handle_failed(self, message: str) -> None:
        self._show_status(f"检测失败：{message}", error=True)
        self.result_browser.setHtml(f"<p style='color:#ef4444;'>{escape(message)}</p>")

    def _handle_completed(self, payload: Dict[str, Any]) -> None:
        static_result = payload.get("static")
        dynamic_result = payload.get("dynamic")
        static_error = payload.get("static_error")
        dynamic_error = payload.get("dynamic_error")

        sections: list[str] = []
        sections.append("<h2 style='margin-top:0;'>检测综述</h2>")
        sections.append(
            "<p style='color:#94a3b8;'>静态机器学习判定与动态沙箱行为分析将同时呈现在下方。</p>"
        )

        sections.append(self._render_static_section(static_result, static_error))
        sections.append(self._render_dynamic_section(dynamic_result, dynamic_error))

        html = "\n".join(sections)
        self.result_browser.setHtml(html)

        if dynamic_error and not static_result:
            self._show_status("检测完成：动态检测不可用，已输出错误信息", error=True)
        elif dynamic_error:
            self._show_status("检测完成：静态结果可用，动态检测出现错误", error=True)
        else:
            self._show_status("检测完成", error=False)

    # ------------------------------------------------------------------ Rendering helpers
    def _render_static_section(self, result: Dict[str, Any] | None, error: str | None) -> str:
        if error:
            return (
                "<div style='background:#2b1b1b;border:1px solid #ef4444;padding:12px;border-radius:10px;'>"
                "<h3 style='color:#fca5a5;margin:0 0 6px 0;'>静态检测</h3>"
                f"<p style='color:#fca5a5;margin:0;'>{escape(error)}</p></div>"
            )

        if not result:
            return (
                "<div style='background:#111827;border:1px solid #1f2937;padding:12px;border-radius:10px;'>"
                "<h3 style='margin:0 0 6px 0;'>静态检测</h3>"
                "<p style='color:#94a3b8;margin:0;'>暂无静态检测结果</p></div>"
            )

        verdict = escape(str(result.get("verdict", "未知")))
        display_prob = float(result.get("display_probability", 0.0) or 0.0)
        raw_prob = float(result.get("probability", 0.0) or 0.0)
        threshold = float(result.get("threshold", 0.0) or 0.0)
        mode_info = result.get("detection_mode") or {}
        mode_label = escape(str(mode_info.get("label", "默认模式")))
        headline = result.get("reasoning", {}).get("headline") or ""
        bullets = result.get("reasoning", {}).get("bullets") or []

        lines = [
            "<div style='background:#0f172a;border:1px solid #1f2937;padding:14px;border-radius:12px;'>",
            "<h3 style='margin:0 0 8px 0;'>静态检测</h3>",
            f"<p style='margin:0 0 8px 0;color:#cbd5f5;'>判定：<strong>{verdict}</strong> ｜ "
            f"展示概率 {display_prob:.4f}% ｜ 原始得分 {raw_prob:.6f} ｜ 阈值 {threshold:.4f}</p>",
            f"<p style='margin:0 0 8px 0;color:#94a3b8;'>模式：{mode_label}</p>",
        ]

        if headline:
            lines.append(f"<p style='margin:0 0 6px 0;font-weight:600;'>{escape(headline)}</p>")
        if bullets:
            lines.append("<ul style='margin:0;padding-left:20px;color:#e2e8f0;'>")
            for item in bullets:
                lines.append(f"<li>{escape(item)}</li>")
            lines.append("</ul>")

        lines.append("</div>")
        return "\n".join(lines)

    def _render_dynamic_section(self, result: Dict[str, Any] | None, error: str | None) -> str:
        if error:
            return (
                "<div style='background:#2b1b1b;border:1px solid #ef4444;padding:12px;border-radius:10px;'>"
                "<h3 style='color:#fca5a5;margin:0 0 6px 0;'>动态检测</h3>"
                f"<p style='color:#fca5a5;margin:0;'>{escape(error)}</p></div>"
            )

        if not result:
            return (
                "<div style='background:#111827;border:1px solid #1f2937;padding:12px;border-radius:10px;'>"
                "<h3 style='margin:0 0 6px 0;'>动态检测</h3>"
                "<p style='color:#94a3b8;margin:0;'>暂无动态检测数据</p></div>"
            )

        try:
            dynamic_html = self._formatter._format_result_html(result)  # type: ignore[attr-defined]
        except Exception:
            pretty = escape(json.dumps(result, indent=2, ensure_ascii=False))
            dynamic_html = (
                "<pre style='background:#0f172a;padding:12px;border-radius:10px;border:1px solid #1f2937;'>"
                f"{pretty}</pre>"
            )

        return (
            "<div style='background:#0f172a;border:1px solid #1f2937;padding:14px;border-radius:12px;'>"
            "<h3 style='margin:0 0 8px 0;'>动态检测</h3>"
            f"{dynamic_html}</div>"
        )

    def _show_status(self, text: str, error: bool = False, busy: bool = False) -> None:
        color = "#fca5a5" if error else "#a5b4fc" if busy else "#cbd5e1"
        self.status_label.setStyleSheet(f"color:{color}; font-weight:600;")
        self.status_label.setText(text)


def main() -> None:
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("PE 文件一键检测")
    app.setApplicationVersion("1.0.0")
    window = DetectionWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
