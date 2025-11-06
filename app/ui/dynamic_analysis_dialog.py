
"""Dynamic analysis dialog integrating remote sandbox results."""

from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Any

from collections.abc import Iterable

import requests
from PyQt5 import QtCore, QtWidgets


class DynamicAnalysisWorker(QtCore.QThread):
    """Perform the blocking HTTP upload in a worker thread."""

    completed = QtCore.pyqtSignal(dict)
    failed = QtCore.pyqtSignal(str)

    def __init__(self, url: str, file_path: Path, parent: QtCore.QObject | None = None):
        super().__init__(parent)
        self._url = url
        self._file_path = file_path

    def run(self) -> None:  # pragma: no cover - GUI worker thread
        try:
            with self._file_path.open("rb") as fh:
                files = {"file": (self._file_path.name, fh)}
                response = requests.post(self._url, files=files, timeout=600)
            response.raise_for_status()
            data = response.json()
        except Exception as exc:  # noqa: BLE001 - bubble to GUI
            self.failed.emit(str(exc))
        else:
            self.completed.emit(data)


class DynamicAnalysisDialog(QtWidgets.QDialog):
    """Collect connection info, trigger analysis and display formatted results."""

    analysisCompleted = QtCore.pyqtSignal(str)
    analysisFailed = QtCore.pyqtSignal(str)

    def __init__(self, parent: QtWidgets.QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("动态检测")
        self.resize(720, 640)
        self.setModal(False)

        self._worker: DynamicAnalysisWorker | None = None
        self._latest_raw_data: dict[str, Any] | None = None
        self._latest_summary: dict[str, Any] | None = None
        self._build_ui()

    # ------------------------------------------------------------------
    # UI helpers
    def _build_ui(self) -> None:
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        grid = QtWidgets.QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(8)

        lbl_ip = QtWidgets.QLabel("服务器 IP")
        self.edit_ip = QtWidgets.QLineEdit()
        self.edit_ip.setPlaceholderText("例如：192.168.0.10")

        lbl_port = QtWidgets.QLabel("端口")
        self.edit_port = QtWidgets.QLineEdit()
        self.edit_port.setPlaceholderText("例如：5000")

        lbl_file = QtWidgets.QLabel("样本路径")
        self.edit_file = QtWidgets.QLineEdit()
        self.edit_file.setPlaceholderText("请选择需要上传的 .exe 文件")
        self.btn_browse = QtWidgets.QPushButton("浏览…")
        self.btn_browse.clicked.connect(self._select_file)

        grid.addWidget(lbl_ip, 0, 0)
        grid.addWidget(self.edit_ip, 0, 1, 1, 2)
        grid.addWidget(lbl_port, 1, 0)
        grid.addWidget(self.edit_port, 1, 1, 1, 2)
        grid.addWidget(lbl_file, 2, 0)
        grid.addWidget(self.edit_file, 2, 1)
        grid.addWidget(self.btn_browse, 2, 2)

        layout.addLayout(grid)

        self.btn_start = QtWidgets.QPushButton("开始动态检测")
        self.btn_start.clicked.connect(self._start_analysis)
        layout.addWidget(self.btn_start)

        self.result_browser = QtWidgets.QTextBrowser()
        self.result_browser.setOpenExternalLinks(False)
        layout.addWidget(self.result_browser, 1)

        self.status_label = QtWidgets.QLabel()
        layout.addWidget(self.status_label)

    # ------------------------------------------------------------------
    # Public API
    def set_file_path(self, path: str) -> None:
        if path:
            self.edit_file.setText(path)

    # ------------------------------------------------------------------
    # Slots
    def _select_file(self) -> None:
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "选择需要动态检测的样本",
            "",
            "Executable Files (*.exe);;All Files (*)",
        )
        if file_path:
            self.edit_file.setText(file_path)

    def _start_analysis(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return

        ip = self.edit_ip.text().strip()
        port = self.edit_port.text().strip()
        file_text = self.edit_file.text().strip()

        if not ip:
            self._show_error("请填写服务器 IP 地址。")
            return
        if not port.isdigit():
            self._show_error("端口必须为数字。")
            return
        if not file_text:
            self._show_error("请选择需要上传的可执行文件。")
            return

        file_path = Path(file_text)
        if not file_path.exists():
            self._show_error("指定的文件不存在。")
            return

        url = f"http://{ip}:{port}/upload"
        self.status_label.setText(f"正在向 {url} 上传样本…")
        self.result_browser.clear()
        self.btn_start.setEnabled(False)

        self._worker = DynamicAnalysisWorker(url, file_path, self)
        self._worker.completed.connect(self._handle_success)
        self._worker.failed.connect(self._handle_failure)
        self._worker.finished.connect(lambda: self.btn_start.setEnabled(True))
        self._worker.start()

    def _handle_success(self, data: dict) -> None:  # pragma: no cover - GUI slot
        self._latest_raw_data = data
        self._latest_summary = self._summarise_behavior(data)
        html = self._format_result_html(data)
        self.result_browser.setHtml(html)
        self.status_label.setText("动态检测完成。")
        self.analysisCompleted.emit(html)

    def _handle_failure(self, message: str) -> None:  # pragma: no cover - GUI slot
        self._show_error(f"动态检测失败：{message}")
        self.analysisFailed.emit(f"动态检测失败：{message}")

    # ------------------------------------------------------------------
    # Helpers
    def _show_error(self, message: str) -> None:
        self.status_label.setText(message)
        self.result_browser.append(f"<span style='color:#d32f2f;'>{escape(message)}</span>")

    def latest_analysis(self) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """Return the most recent raw result and derived summary."""

        return self._latest_raw_data, self._latest_summary

    def _format_result_html(self, data: dict[str, Any]) -> str:
        """Render the returned JSON into a readable HTML report."""

        summary = self._summarise_behavior(data)

        sections: list[str] = [
            "<h2 style='margin-bottom:12px;'>动态检测结果</h2>",
            "<p style='color:#666;'>以下内容来自远程沙箱返回的行为报告。</p>",
            "<div style='background:#f9fbff;border:1px solid #d0e3ff;padding:12px;border-radius:8px;margin-bottom:16px;'>",
            f"<p><strong>风险评级：</strong>{escape(summary['risk_level'])}"
            f"（行为得分 {summary['score']:.1f}/10，事件总数 {summary['total_events']}）</p>",
        ]

        if summary["guidance"]:
            sections.append(f"<p style='color:#555;'>{escape(summary['guidance'])}</p>")

        sections.append("</div>")

        sections.append(
            "<table style='border-collapse:collapse;width:100%;margin-bottom:16px;'>"
            "<thead><tr style='background:#eef4ff;'><th style='text-align:left;padding:6px;border:1px solid #d0e3ff;'>行为类别" 
            "</th><th style='text-align:left;padding:6px;border:1px solid #d0e3ff;'>事件数量</th></tr></thead><tbody>"
        )
        for entry in summary["counts"]:
            sections.append(
                "<tr>"
                f"<td style='padding:6px;border:1px solid #d0e3ff;'>{escape(entry['title'])}</td>"
                f"<td style='padding:6px;border:1px solid #d0e3ff;'>{entry['count']}</td>"
                "</tr>"
            )
        sections.append("</tbody></table>")

        if summary["highlights"]:
            sections.append("<h3>关键事件</h3>")
            sections.append("<ul style='padding-left:18px;'>")
            for item in summary["highlights"]:
                sections.append(f"<li>{item}</li>")
            sections.append("</ul>")

        if summary["errors"]:
            sections.append("<h3>执行异常</h3>")
            sections.append("<ul style='padding-left:18px;color:#d32f2f;'>")
            for item in summary["errors"]:
                sections.append(f"<li>{item}</li>")
            sections.append("</ul>")

        key_mapping = {
            "api_calls": "原始 API 事件",
            "file_operations": "文件操作",
            "network_activity": "网络行为",
            "registry_changes": "注册表改动",
            "process_creations": "进程创建",
            "errors": "异常信息",
        }

        for key, title in key_mapping.items():
            entries = data.get(key)
            sections.append(self._render_section(title, entries))

        if extra := {
            k: v for k, v in data.items() if k not in key_mapping
        }:
            sections.append("<h3>其他字段</h3>")
            pretty = escape(json.dumps(extra, indent=2, ensure_ascii=False))
            sections.append(
                "<pre style='background:#f5f5f5;padding:12px;border-radius:6px;'>"
                f"{pretty}"
                "</pre>"
            )

        return "\n".join(sections)

    def _summarise_behavior(self, data: dict[str, Any]) -> dict[str, Any]:
        mapping = {
            "file_operations": ("文件操作", 0.25, 12),
            "network_activity": ("网络通信", 0.6, 12),
            "registry_changes": ("注册表改动", 0.35, 12),
            "process_creations": ("进程创建", 0.5, 10),
        }

        counts: list[dict[str, Any]] = []
        highlights: list[str] = []
        score = 0.0
        total_events = 0

        def _normalise(entries: Any) -> list[Any]:
            if not entries:
                return []
            if isinstance(entries, Iterable) and not isinstance(entries, (str, bytes, dict)):
                return list(entries)
            return [entries]

        for key, (title, weight, cap) in mapping.items():
            entries = _normalise(data.get(key))
            count = len(entries)
            total_events += count
            counts.append({"title": title, "count": count})
            score += min(count, cap) * weight
            for entry in entries[: min(3, len(entries))]:
                highlights.append(f"<strong>{escape(title)}</strong>：{self._render_entry(entry)}")

        errors = [self._render_entry(item) for item in _normalise(data.get("errors"))]

        # 如果原始 API 调用数量巨大，适当提升得分
        api_events = _normalise(data.get("api_calls"))
        if api_events:
            total_events += len(api_events)
            score += min(len(api_events), 25) * 0.1

        score = min(10.0, round(score, 2))
        if score >= 6.5:
            risk_level = "高风险"
            guidance = "捕获到大量潜在恶意行为，建议立即隔离并提取IOC。"
        elif score >= 3.2:
            risk_level = "中等风险"
            guidance = "存在可疑的系统改动与网络活动，请结合静态特征进一步研判。"
        else:
            risk_level = "低风险"
            guidance = "动态行为较少，仍需配合模型结果综合评估。"

        return {
            "counts": counts,
            "score": score,
            "risk_level": risk_level,
            "guidance": guidance,
            "highlights": highlights,
            "errors": errors,
            "total_events": total_events,
        }

    def _render_section(self, title: str, entries: Any) -> str:
        if not entries:
            return f"<h3>{escape(title)}</h3><p>暂无数据。</p>"

        lines: list[str] = [f"<h3>{escape(title)}</h3>"]
        lines.append("<ul style='padding-left:18px;'>")

        if isinstance(entries, Iterable) and not isinstance(entries, (str, bytes, dict)):
            iterable_entries = entries
        else:
            iterable_entries = [entries]

        for entry in iterable_entries:
            lines.append("<li>" + self._render_entry(entry) + "</li>")

        lines.append("</ul>")
        return "".join(lines)

    def _render_entry(self, entry: Any) -> str:
        if isinstance(entry, dict):
            parts = [
                f"<b>{escape(str(k))}</b>: {escape(self._stringify(v))}"
                for k, v in entry.items()
            ]
            return "； ".join(parts)
        if isinstance(entry, (list, tuple, set)):
            return "，".join(escape(self._stringify(v)) for v in entry)
        return escape(self._stringify(entry))

    @staticmethod
    def _stringify(value: Any) -> str:
        if isinstance(value, (dict, list, tuple)):
            return json.dumps(value, ensure_ascii=False)
        return str(value)
