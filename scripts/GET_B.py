"""Dialog for presenting benign sample resources and generating safe placeholder executables."""

from __future__ import annotations

import base64
from datetime import datetime
from pathlib import Path
from typing import Iterable, List

from PyQt5 import QtCore, QtWidgets


# Pre-built minimal PE32 stub that immediately calls ExitProcess.
# The binary is a hand-crafted, no-op console program designed to be safe.
_BENIGN_STUB_B64 = (
    "TVoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAFRoaXMgcHJvZ3JhbSBpcyBhIGJlbmlnbiBwbGFjZWhv"
    "bGRlci4NCiQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQRQAATAEBAAAAAAAAAAAAAAAAAOAADwELAQABAAIAAAAAAAAAAAAAABAAAAAQAAAAAAAAAABAAAAQAAAAAgAA"
    "BAAAAAAAAAAEAAAAACAAAAACAAAAAAAAAwAAAAAAEAAAEAAAAAAQAAAQAAAAAAAAEAAAAAAAAAAAAAAAQBAAACgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC50ZXh0AAAA"
    "AAIAAAAQAAAAAgAAAAIAAAAAAAAAAAAAAAAAACAAAGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAxyVGhMBBAAP/QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFAQAAAAAAAAAAAAAAAAAABQEAAAAAAAAAAAAAAAAAAA"
    "IBAAAAAAAAAAAAAAXBAAAAAARXhpdFByb2Nlc3MAUk5FTDMyLmRsbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
)

_BENIGN_TEMPLATE_BYTES = base64.b64decode(_BENIGN_STUB_B64)


class BenignResourceDialog(QtWidgets.QDialog):
    """Dialog that lists benign sample resources and generates safe executables."""

    WINDOW_SIZE = QtCore.QSize(800, 600)

    def __init__(self, parent: QtWidgets.QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("良性样本资源中心")
        self.resize(self.WINDOW_SIZE)
        self.setModal(False)

        self._build_ui()
        self._populate_resources()

    # ------------------------------------------------------------------
    # UI construction helpers
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        header = QtWidgets.QLabel(
            "<h2>获取良性样本</h2>"
            "<p>以下资源提供经过社区验证或官方发布的良性 PE 文件。"
            "建议在下载后使用哈希校验和数字签名进行确认。</p>"
        )
        header.setWordWrap(True)
        layout.addWidget(header)

        self.resourceBrowser = QtWidgets.QTextBrowser()
        self.resourceBrowser.setOpenExternalLinks(True)
        self.resourceBrowser.setMinimumHeight(260)
        layout.addWidget(self.resourceBrowser)

        generator_group = QtWidgets.QGroupBox("批量生成占位良性 EXE")
        generator_layout = QtWidgets.QGridLayout(generator_group)
        generator_layout.setVerticalSpacing(8)
        generator_layout.setHorizontalSpacing(10)

        description = QtWidgets.QLabel(
            "该工具会在指定目录生成一组用于测试流程的占位 EXE。"
            "文件内部包含一个最小化的 Windows 控制台程序，只会立即退出，不含任何恶意逻辑。"
        )
        description.setWordWrap(True)
        generator_layout.addWidget(description, 0, 0, 1, 3)

        output_label = QtWidgets.QLabel("输出目录:")
        self.outputEdit = QtWidgets.QLineEdit()
        browse_button = QtWidgets.QPushButton("浏览…")
        browse_button.clicked.connect(self._select_output_directory)
        generator_layout.addWidget(output_label, 1, 0)
        generator_layout.addWidget(self.outputEdit, 1, 1)
        generator_layout.addWidget(browse_button, 1, 2)

        count_label = QtWidgets.QLabel("生成数量:")
        self.countSpin = QtWidgets.QSpinBox()
        self.countSpin.setRange(1, 50)
        self.countSpin.setValue(5)
        generator_layout.addWidget(count_label, 2, 0)
        generator_layout.addWidget(self.countSpin, 2, 1)

        prefix_label = QtWidgets.QLabel("文件前缀:")
        self.prefixEdit = QtWidgets.QLineEdit("benign_sample")
        generator_layout.addWidget(prefix_label, 3, 0)
        generator_layout.addWidget(self.prefixEdit, 3, 1)

        self.generateButton = QtWidgets.QPushButton("生成占位 EXE")
        self.generateButton.clicked.connect(self._handle_generate)
        generator_layout.addWidget(self.generateButton, 4, 0, 1, 3)

        self.statusLabel = QtWidgets.QLabel()
        generator_layout.addWidget(self.statusLabel, 5, 0, 1, 3)

        layout.addWidget(generator_group)

    def _populate_resources(self) -> None:
        resources = self._benign_resources()
        lines = [
            "<ul>",
        ]
        for entry in resources:
            lines.append(
                "<li><b>{name}</b> - {desc}"
                "<br/><a href=\"{url}\">{url}</a></li>".format(
                    name=entry["name"], desc=entry["description"], url=entry["url"]
                )
            )
        lines.append("</ul>")
        self.resourceBrowser.setHtml("\n".join(lines))

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------
    def _select_output_directory(self) -> None:
        directory = QtWidgets.QFileDialog.getExistingDirectory(self, "选择输出目录")
        if directory:
            self.outputEdit.setText(directory)

    def _handle_generate(self) -> None:
        target_dir = self.outputEdit.text().strip()
        if not target_dir:
            self._set_status("请选择输出目录。", error=True)
            return

        directory = Path(target_dir)
        if not directory.exists():
            try:
                directory.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                self._set_status(f"无法创建目录: {exc}", error=True)
                return

        count = self.countSpin.value()
        prefix = self.prefixEdit.text().strip() or "benign_sample"
        generated_files, error_message = self._generate_files(directory, prefix, count)
        if error_message:
            self._set_status(error_message, error=True)
            return

        if generated_files:
            rel_paths = "<br/>".join(str(path) for path in generated_files)
            self._set_status(
                f"已生成 {len(generated_files)} 个占位 EXE:<br/>{rel_paths}", error=False
            )
        else:
            self._set_status("没有生成任何文件。", error=True)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _generate_files(self, directory: Path, prefix: str, count: int) -> tuple[List[Path], str | None]:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        created: List[Path] = []
        error_message: str | None = None
        for idx in range(1, count + 1):
            file_name = f"{prefix}_{timestamp}_{idx:02d}.exe"
            target_path = directory / file_name
            try:
                target_path.write_bytes(_BENIGN_TEMPLATE_BYTES)
            except OSError as exc:
                error_message = f"写入 {target_path.name} 失败: {exc}"
                break
            else:
                created.append(target_path)
        return created, error_message

    def _set_status(self, message: str, *, error: bool) -> None:
        color = "#d9534f" if error else "#28a745"
        self.statusLabel.setText(f"<span style='color:{color};'>{message}</span>")

    @staticmethod
    def _benign_resources() -> Iterable[dict[str, str]]:
        return [
            {
                "name": "Microsoft 官方示例程序",
                "description": "Windows SDK 和 Visual Studio 附带的演示程序，适合用于白样本基线。",
                "url": "https://learn.microsoft.com/zh-cn/windows/win32/samples/"
            },
            {
                "name": "PortableApps 平台",
                "description": "提供大量开源、可移植的绿色软件，可作为良性可执行文件样本。",
                "url": "https://portableapps.com/apps"
            },
            {
                "name": "Win64 PE Samples (Github)",
                "description": "社区维护的小型合法 PE 样本集合，便于模型调试。",
                "url": "https://github.com/hasherezade/minimal_pe"
            },
            {
                "name": "FossHub",
                "description": "托管经过审核的开源软件安装包，可用于构建白样本集。",
                "url": "https://www.fosshub.com/"
            },
            {
                "name": "Npackd",
                "description": "Windows 软件包管理器，支持批量下载经过签名的应用程序。",
                "url": "https://www.npackd.org/"
            },
        ]