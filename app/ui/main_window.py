from datetime import datetime
from pathlib import Path

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QFileDialog

from .progress_dialog import Worker
from .report_view import ReportManager
from scripts.GET_B import BenignResourceDialog
from scripts.SENDBOX import SandboxDialog
from core.utils.logger import set_log
from scripts.FILE_NAME import GET_TIME
from scripts.D import predict_file_with_features


class MachineLearningPEUI(QtWidgets.QDialog):
    """基于机器学习的恶意PE文件检测系统主窗口"""

    def __init__(self):
        super().__init__()
        self.workers = {}
        self.report_manager = ReportManager()
        self._benign_dialog = None
        self._sandbox_dialog = None
        self.setupUi()

    def setupUi(self):
        """设置用户界面"""
        self.setObjectName("MainDialog")
        self.resize(1280, 840)
        self.setMinimumSize(1120, 720)
        self.setWindowTitle("基于机器学习的恶意PE文件检测系统")
        self.setWindowFlags(self.windowFlags() & ~QtCore.Qt.WindowContextHelpButtonHint)
        self.setAttribute(QtCore.Qt.WA_StyledBackground, True)

        self.mainLayout = QtWidgets.QVBoxLayout(self)
        self.mainLayout.setContentsMargins(24, 24, 24, 24)
        self.mainLayout.setSpacing(18)

        self._setup_title_section()
        self._setup_input_output_section()
        self._setup_center_section()
        self._setup_footer_section()
        self._bind_events()

    # --- 现代化界面分区构建 ---
    def _setup_title_section(self):
        """设置标题区域"""
        title_card = QtWidgets.QFrame(self)
        title_card.setObjectName("Card")
        title_layout = QtWidgets.QVBoxLayout(title_card)
        title_layout.setContentsMargins(32, 28, 32, 32)
        title_layout.setSpacing(6)

        title_label = QtWidgets.QLabel("基于机器学习的恶意PE文件检测系统", title_card)
        title_label.setObjectName("TitleLabel")
        title_label.setAlignment(QtCore.Qt.AlignCenter)
        title_label.setWordWrap(True)

        subtitle_label = QtWidgets.QLabel("Malicious Portable Executable Analyzer", title_card)
        subtitle_label.setObjectName("SubtitleLabel")
        subtitle_label.setAlignment(QtCore.Qt.AlignCenter)
        subtitle_label.setWordWrap(True)

        title_layout.addWidget(title_label)
        title_layout.addWidget(subtitle_label)

        self.mainLayout.addWidget(title_card)
        self.titleLabel = title_label
        self.subtitleLabel = subtitle_label

    def _setup_input_output_section(self):
        """设置输入输出区域"""
        io_card = QtWidgets.QFrame(self)
        io_card.setObjectName("Card")
        io_layout = QtWidgets.QGridLayout(io_card)
        io_layout.setContentsMargins(28, 24, 28, 24)
        io_layout.setHorizontalSpacing(16)
        io_layout.setVerticalSpacing(12)

        input_label = QtWidgets.QLabel("输入路径", io_card)
        input_label.setObjectName("CaptionLabel")
        io_layout.addWidget(input_label, 0, 0)

        self.inputLineEdit = QtWidgets.QLineEdit(io_card)
        self.inputLineEdit.setPlaceholderText("选择需要分析的文件或文件夹…")
        io_layout.addWidget(self.inputLineEdit, 0, 1)

        self.selectInputButton = QtWidgets.QPushButton("选择", io_card)
        self.selectInputButton.setProperty("variant", "secondary")
        io_layout.addWidget(self.selectInputButton, 0, 2)

        self.useInputCheckBox = QtWidgets.QCheckBox("使用", io_card)
        io_layout.addWidget(self.useInputCheckBox, 0, 3)

        output_label = QtWidgets.QLabel("输出路径", io_card)
        output_label.setObjectName("CaptionLabel")
        io_layout.addWidget(output_label, 1, 0)

        self.outputLineEdit = QtWidgets.QLineEdit(io_card)
        self.outputLineEdit.setPlaceholderText("选择保存结果的文件夹…")
        io_layout.addWidget(self.outputLineEdit, 1, 1)

        self.selectOutputButton = QtWidgets.QPushButton("选择", io_card)
        self.selectOutputButton.setProperty("variant", "secondary")
        io_layout.addWidget(self.selectOutputButton, 1, 2)

        self.useOutputCheckBox = QtWidgets.QCheckBox("使用", io_card)
        io_layout.addWidget(self.useOutputCheckBox, 1, 3)

        io_layout.setColumnStretch(1, 1)
        io_layout.setColumnStretch(2, 0)
        io_layout.setColumnStretch(3, 0)

        self.mainLayout.addWidget(io_card)

    def _setup_center_section(self):
        """设置主内容区域"""
        content_layout = QtWidgets.QHBoxLayout()
        content_layout.setSpacing(18)

        # 左侧：运行结果
        result_card = QtWidgets.QFrame(self)
        result_card.setObjectName("Card")
        result_layout = QtWidgets.QVBoxLayout(result_card)
        result_layout.setContentsMargins(28, 28, 28, 28)
        result_layout.setSpacing(18)

        result_header = QtWidgets.QLabel("运行结果", result_card)
        result_header.setObjectName("SectionTitle")
        result_layout.addWidget(result_header)

        self.resultTextBrowser = QtWidgets.QTextBrowser(result_card)
        self.resultTextBrowser.setObjectName("PrimaryTextBrowser")
        self.resultTextBrowser.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.resultTextBrowser.setOpenExternalLinks(True)
        result_layout.addWidget(self.resultTextBrowser, 1)

        action_row = QtWidgets.QHBoxLayout()
        action_row.setSpacing(12)

        self.btn_download_report = QtWidgets.QPushButton("下载报告", result_card)
        self.btn_download_report.setMinimumHeight(44)
        self.btn_view_logs = QtWidgets.QPushButton("查看日志", result_card)
        self.btn_view_logs.setProperty("variant", "secondary")
        self.btn_view_logs.setMinimumHeight(44)
        self.btn_clear_text = QtWidgets.QPushButton("清空文本", result_card)
        self.btn_clear_text.setProperty("variant", "secondary")
        self.btn_clear_text.setMinimumHeight(44)

        action_row.addWidget(self.btn_download_report)
        action_row.addWidget(self.btn_view_logs)
        action_row.addWidget(self.btn_clear_text)

        result_layout.addLayout(action_row)

        content_layout.addWidget(result_card, 2)

        # 右侧：进度与功能
        sidebar_card = QtWidgets.QFrame(self)
        sidebar_card.setObjectName("Card")
        sidebar_layout = QtWidgets.QVBoxLayout(sidebar_card)
        sidebar_layout.setContentsMargins(28, 28, 28, 28)
        sidebar_layout.setSpacing(18)

        progress_header = QtWidgets.QLabel("任务控制中心", sidebar_card)
        progress_header.setObjectName("SectionTitle")
        sidebar_layout.addWidget(progress_header)

        tasks_container = QtWidgets.QWidget(sidebar_card)
        tasks_layout = QtWidgets.QVBoxLayout(tasks_container)
        tasks_layout.setContentsMargins(0, 0, 0, 0)
        tasks_layout.setSpacing(12)

        task_specs = [
            ("文件信息", "progress_file_info", "btn_file_info"),
            ("数据清洗", "progress_data_cleaning", "btn_data_cleaning"),
            ("提取特征", "progress_extract_feature", "btn_extract_feature"),
            ("特征转换", "progress_feature_transform", "btn_feature_transform"),
            ("训练模型", "progress_train_model", "btn_model_train"),
            ("测试模型", "progress_test_model", "btn_model_test"),
            ("模型预测", "progress_model_predict", "btn_model_predict"),
            ("获取良性", "progress_get_benign", "btn_get_benign"),
            ("沙箱检测", "progress_sandbox", "btn_sandbox"),
            ("安装依赖", "progress_install_deps", "btn_install_deps"),
        ]

        self.progressBars = {}
        self.button_task_map = {}
        for label_text, progress_attr, button_attr in task_specs:
            row_frame = QtWidgets.QFrame(tasks_container)
            row_frame.setObjectName("ProgressRow")
            row_layout = QtWidgets.QHBoxLayout(row_frame)
            row_layout.setContentsMargins(20, 14, 20, 14)
            row_layout.setSpacing(16)

            label = QtWidgets.QLabel(label_text, row_frame)
            label.setObjectName("TaskLabel")
            label.setMinimumWidth(88)

            progress = QtWidgets.QProgressBar(row_frame)
            progress.setObjectName("ProgressBar")
            progress.setMinimum(0)
            progress.setMaximum(100)
            progress.setValue(0)
            progress.setTextVisible(False)
            progress.setFixedHeight(16)

            button = QtWidgets.QPushButton(label_text, row_frame)
            button.setMinimumHeight(36)
            button.setMinimumWidth(132)
            button.setProperty("variant", "ghost")

            row_layout.addWidget(label)
            row_layout.addWidget(progress, 1)
            row_layout.addWidget(button)

            tasks_layout.addWidget(row_frame)

            setattr(self, progress_attr, progress)
            setattr(self, button_attr, button)
            self.progressBars[label_text] = progress
            self.button_task_map[button] = label_text

        tasks_layout.addStretch(1)
        sidebar_layout.addWidget(tasks_container)

        thread_layout = QtWidgets.QHBoxLayout()
        thread_layout.setSpacing(12)

        self.threadCountLabel = QtWidgets.QLabel("线程数", sidebar_card)
        self.threadCountLabel.setObjectName("CaptionLabel")
        self.threadCountSpinBox = QtWidgets.QSpinBox(sidebar_card)
        self.threadCountSpinBox.setMinimum(1)
        self.threadCountSpinBox.setMaximum(100)
        self.threadCountSpinBox.setValue(4)
        self.threadCountSpinBox.setToolTip("设置特征提取使用的线程数（1-16）")

        thread_layout.addWidget(self.threadCountLabel)
        thread_layout.addWidget(self.threadCountSpinBox)
        thread_layout.addStretch(1)

        sidebar_layout.addLayout(thread_layout)
        sidebar_layout.addStretch(1)

        content_layout.addWidget(sidebar_card, 1)

        self.mainLayout.addLayout(content_layout, 1)

        # 设置交互控件的指针样式
        interactive_widgets = [
            self.selectInputButton,
            self.selectOutputButton,
            self.useInputCheckBox,
            self.useOutputCheckBox,
            self.btn_download_report,
            self.btn_view_logs,
            self.btn_clear_text,
            *self.button_task_map.keys(),
        ]
        pointing_cursor = QtGui.QCursor(QtCore.Qt.PointingHandCursor)
        for widget in interactive_widgets:
            widget.setCursor(pointing_cursor)

    def _setup_footer_section(self):
        """设置底部信息区域"""
        footer_card = QtWidgets.QFrame(self)
        footer_card.setObjectName("Card")
        footer_layout = QtWidgets.QVBoxLayout(footer_card)
        footer_layout.setContentsMargins(28, 24, 28, 24)
        footer_layout.setSpacing(12)

        footer_header = QtWidgets.QLabel("系统信息", footer_card)
        footer_header.setObjectName("SectionTitle")
        footer_layout.addWidget(footer_header)

        self.infoTextBrowser = QtWidgets.QTextBrowser(footer_card)
        self.infoTextBrowser.setObjectName("SecondaryTextBrowser")
        self.infoTextBrowser.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.infoTextBrowser.setOpenExternalLinks(True)
        self.infoTextBrowser.setHtml(
            "<p>大理大学 · 数学与计算机学院 22级 信息安全班 蒋添麒<br/>"
            "项目主页：<a href='https://github.com/a637814143/Machine-Learning-for-Mailcious-PE-File-Detection'>"
            "GitHub</a></p>"
        )

        footer_layout.addWidget(self.infoTextBrowser)
        self.mainLayout.addWidget(footer_card)

    def _bind_events(self):
        """绑定事件"""
        self.selectInputButton.clicked.connect(self.select_input_file)
        self.selectOutputButton.clicked.connect(self.select_output_file)

        for button, task_name in self.button_task_map.items():
            button.clicked.connect(lambda checked, tn=task_name: self.start_task(tn))

        self.btn_download_report.clicked.connect(self.download_report)
        self.btn_view_logs.clicked.connect(self.view_logs)
        self.btn_clear_text.clicked.connect(self.clear_result_text)

    # --- 文件选择槽 ---
    def select_input_file(self):
        """选择输入文件"""
        set_log(GET_TIME("[DEBUG] select_input_file called"))
        path, _ = QFileDialog.getOpenFileName(self, "选择输入文件")
        if path:
            self.inputLineEdit.setText(path)

    def select_output_file(self):
        """选择输出文件夹"""
        set_log(GET_TIME("[DEBUG] select_output_file called"))
        path = QFileDialog.getExistingDirectory(self, "选择输出文件夹")
        if path:
            self.outputLineEdit.setText(path)

    def _get_params(self):
        """获取参数"""
        params = []
        if self.useInputCheckBox.isChecked():
            params.append(self.inputLineEdit.text())
        if self.useOutputCheckBox.isChecked():
            params.append(self.outputLineEdit.text())

        thread_count = self.threadCountSpinBox.value()
        params.append(str(thread_count))

        return tuple(params)

    def start_task(self, task_name: str):
        """启动任务"""
        if task_name == "获取良性":
            self.open_benign_resources()
            return

        if task_name == "沙箱检测":
            self.open_sandbox_helper()
            return

        params = self._get_params()

        if task_name == "文件信息" and not self.useInputCheckBox.isChecked():
            self._append_result_text("请选择输入文件")
            return

        if task_name in ["提取特征", "特征转换", "训练模型"] and not (
            self.useInputCheckBox.isChecked() and self.useOutputCheckBox.isChecked()
        ):
            self._append_result_text("请选择输入和输出路径")
            return

        if task_name in self.progressBars:
            self.progressBars[task_name].setValue(0)

        worker = Worker(task_name, params)
        self.workers[task_name] = worker

        if task_name in self.progressBars:
            worker.progress_signal.connect(self.progressBars[task_name].setValue)

        worker.text_signal.connect(self._append_result_text_or_html)

        thread_info = (
            f"（线程数: {self.threadCountSpinBox.value()}）"
            if task_name in ["提取特征", "特征转换", "训练模型"]
            else ""
        )
        self._append_result_text(f"启动任务: {task_name} {thread_info}")
        worker.start()

    def open_benign_resources(self):
        """打开良性资源窗口。"""
        if self._benign_dialog is None:
            self._benign_dialog = BenignResourceDialog(self)
        self._benign_dialog.show()
        self._benign_dialog.raise_()
        self._benign_dialog.activateWindow()
        if "获取良性" in self.progressBars:
            self.progressBars["获取良性"].setValue(100)
        self._append_result_text("已打开良性样本资源窗口。")

    def open_sandbox_helper(self):
        """打开沙箱检测指导窗口。"""
        if self._sandbox_dialog is None:
            self._sandbox_dialog = SandboxDialog(self)
        self._sandbox_dialog.show()
        self._sandbox_dialog.raise_()
        self._sandbox_dialog.activateWindow()
        if "沙箱检测" in self.progressBars:
            self.progressBars["沙箱检测"].setValue(100)
        self._append_result_text("已打开沙箱检测指南窗口。")

    def _append_result_text_or_html(self, txt: str):
        """如果是HTML就渲染，否则追加文本"""
        if txt.strip().startswith("<html>") or txt.strip().startswith("<p"):
            self.resultTextBrowser.setHtml(txt)
        else:
            self.resultTextBrowser.append(txt)

    def _append_result_text(self, txt: str):
        """添加结果文本"""
        self.resultTextBrowser.append(txt)

    def download_report(self):
        """下载报告"""
        file_path = self.inputLineEdit.text().strip()
        if not file_path:
            self._append_result_text("请先选择需要生成报告的 PE 文件。")
            return

        target = Path(file_path)
        if not target.exists() or not target.is_file():
            self._append_result_text("所选路径不是有效的文件，请重新选择。")
            return

        self._append_result_text(f"正在分析 {target.name} ……")

        try:
            result = predict_file_with_features(str(target))
        except FileNotFoundError as exc:
            self._append_result_text(str(exc))
            return
        except ImportError as exc:
            self._append_result_text(f"缺少依赖: {exc}")
            return
        except Exception as exc:  # pragma: no cover - UI runtime feedback
            self._append_result_text(f"生成报告失败: {exc}")
            return

        verdict = result.get("verdict", "未知")
        display_prob = result.get("display_probability", 0.0)
        raw_prob = result.get("probability", 0.0)
        threshold = result.get("threshold")

        summary_line = (
            f"模型判定: {verdict} (恶意概率 {display_prob:.4f}%"
            f"，原始得分 {raw_prob:.6f})"
        )
        if threshold is not None:
            summary_line += f"，判定阈值 {threshold:.4f}"
        self._append_result_text(summary_line)

        markdown_content = self._build_markdown_report(Path(result.get("file_path", target)), result)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"{target.stem}_report_{timestamp}.md"
        report_path = self.report_manager.create_markdown_report(markdown_content, report_name=report_name)

        if report_path:
            self._append_result_text(f"报告已生成: {report_path}")
            self.report_manager.log_message(f"生成报告 {report_path}")
        else:
            self._append_result_text("报告生成失败，请检查日志。")

    def view_logs(self):
        """查看日志"""
        self._append_result_text("查看日志：占位（未实现）")

    def clear_result_text(self):
        """清空文件信息展示区"""
        self.resultTextBrowser.clear()

    def _build_markdown_report(self, file_path: Path, result: dict) -> str:
        """根据预测结果构建 Markdown 报告内容。"""
        summary = result.get("summary", {})
        reasoning = result.get("reasoning", {})
        general = summary.get("general", {})
        strings = summary.get("strings", {})
        suspicious_hits = summary.get("suspicious_api_hits", [])
        high_entropy_sections = summary.get("high_entropy_sections", [])
        section_overview = summary.get("section_overview", [])
        dll_usage = summary.get("dll_usage", [])
        header_info = summary.get("header", {})
        risk_info = summary.get("risk_assessment", {})
        mitigations = risk_info.get("mitigations", [])
        risk_factors = risk_info.get("factors", [])
        string_samples = summary.get("string_samples", {})
        active_data_dirs = summary.get("active_data_directories", [])
        exports = summary.get("exports", [])
        packer_sections = summary.get("packer_sections", [])
        entry_section = summary.get("entry_section")

        avg_string_length = float(strings.get("avlength", 0.0) or 0.0)
        printable_strings = int(strings.get("printables", 0) or 0)
        mz_count = int(strings.get("MZ", 0) or 0)

        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        verdict = result.get("verdict", "未知")
        display_prob = result.get("display_probability", 0.0)
        raw_prob = result.get("probability", 0.0)
        threshold = result.get("threshold", 0.0)
        model_path = result.get("model_path", "未知")

        risk_score = float(risk_info.get("score", 0.0) or 0.0)
        risk_level = risk_info.get("level", "未知")

        lines = [
            "# 恶意 PE 文件检测报告",
            "",
            f"- **生成时间**: {generated_at}",
            f"- **文件名**: `{file_path.name}`",
            f"- **文件路径**: `{file_path}`",
            f"- **模型文件**: `{model_path}`",
            "",
            "## 预测结果",
            "",
            f"- 模型判定: **{verdict}**",
            f"- 恶意概率 (展示): **{display_prob:.4f}%**",
            f"- 原始模型得分: {raw_prob:.6f}",
            f"- 判定阈值: {threshold:.4f}",
            "",
            "## 模型信心与风险评估",
            "",
            f"- 综合风险等级: **{risk_level}**",
            f"- 综合风险得分: **{risk_score:.1f} / 10**",
        ]

        margin = abs(raw_prob - threshold)
        if margin >= 0.25:
            confidence = "非常高"
        elif margin >= 0.15:
            confidence = "较高"
        elif margin >= 0.07:
            confidence = "中等"
        else:
            confidence = "谨慎"
        lines.extend([f"- 判定信心: **{confidence}** (与阈值差距 {margin:.4f})", ""])

        if risk_factors:
            lines.extend([
                "| 主要恶意信号 | 贡献分值 | 说明 |",
                "| --- | --- | --- |",
            ])
            for factor in risk_factors:
                weight = float(factor.get("weight", 0.0) or 0.0)
                title = factor.get("title", "未知")
                detail = factor.get("detail", "")
                lines.append(f"| {title} | {weight:.2f} | {detail} |")
            lines.append("")

        if mitigations:
            lines.extend([
                "**潜在缓解因素**",
                "",
            ])
            for item in mitigations:
                title = item.get("title", "未知")
                detail = item.get("detail", "")
                lines.append(f"- {title}: {detail}")
            lines.append("")

        lines.extend([
            "## 判定依据",
            "",
        ])

        headline = reasoning.get("headline")
        if headline:
            lines.append(headline)

        bullets = reasoning.get("bullets", [])
        if bullets:
            lines.extend(f"- {item}" for item in bullets)
        else:
            lines.append("- 模型未提供额外判定依据。")

        lines.extend([
            "",
            "## 文件特征概览",
            "",
            f"- 文件大小: {general.get('size', '未知')} 字节",
            f"- 虚拟大小 (SizeOfImage): {general.get('vsize', '未知')}",
            f"- 是否包含数字签名: {'是' if general.get('has_signature') else '否'}",
            f"- 导入函数数量: {summary.get('total_imports', 0)}",
            f"- 字符串熵: {summary.get('string_entropy', 0.0):.2f}",
            f"- URL 字符串数量: {summary.get('url_strings', 0)}",
            f"- 注册表字符串数量: {summary.get('registry_strings', 0)}",
            f"- 字符串密度: {summary.get('strings_per_kb', 0.0):.2f} 条/KB",
            f"- 节区数量: {summary.get('section_count', 0)}",
            f"- 入口节区: {entry_section or '未知'}",
        ])

        if header_info:
            lines.extend([
                "",
                "## PE 头部信息",
                "",
            ])
            header_lines = [f"- 机器类型: {header_info.get('machine', '未知') or '未知'}"]
            timestamp = int(header_info.get("timestamp") or 0)
            if timestamp > 0:
                build_time = datetime.utcfromtimestamp(timestamp)
                header_lines.append(
                    f"- 编译时间: {build_time.strftime('%Y-%m-%d %H:%M:%S')} (UTC)"
                )
            else:
                header_lines.append("- 编译时间: 未知/异常 (时间戳为 0)")
            header_lines.extend(
                [
                    f"- 子系统: {header_info.get('subsystem', '未知') or '未知'}",
                    f"- 代码区大小: {header_info.get('sizeof_code', 0)}",
                    f"- 头部大小: {header_info.get('sizeof_headers', 0)}",
                ]
            )
            dll_chars = header_info.get("dll_characteristics", [])
            if dll_chars:
                header_lines.append(
                    "- DLL 特征: " + ", ".join(str(item) for item in dll_chars[:12])
                )
            characteristics = header_info.get("characteristics", [])
            if characteristics:
                header_lines.append(
                    "- COFF 标志: " + ", ".join(str(item) for item in characteristics[:12])
                )
            lines.extend(header_lines)

        if suspicious_hits:
            lines.extend([
                "",
                "## 高风险 API",
                "",
            ])
            for hit in suspicious_hits[:10]:
                lines.append(f"- `{hit['api']}`: {hit['hint']}")

        if high_entropy_sections:
            lines.extend([
                "",
                "## 高熵节区",
                "",
            ])
            for sec in high_entropy_sections[:10]:
                lines.append(
                    f"- `{sec['name']}` — 大小 {sec['size']} 字节，熵 {sec['entropy']:.2f}"
                )

        if packer_sections:
            lines.extend([
                "",
                "## 可能的加壳迹象",
                "",
            ])
            unique_packers = []
            for name in packer_sections:
                if name not in unique_packers:
                    unique_packers.append(name)
            for name in unique_packers:
                lines.append(f"- {name}")

        if printable_strings:
            lines.extend([
                "",
                "## 字符串统计",
                "",
                f"- 可打印字符串数量: {printable_strings}",
                f"- 平均字符串长度: {avg_string_length:.2f}",
                f"- 包含 'MZ' 头的字符串数: {mz_count}",
            ])

        string_sections = {
            "url_samples": "URL 样本",
            "ip_samples": "IP 地址样本",
            "path_samples": "可疑文件路径样本",
            "regkey_samples": "注册表键样本",
            "suspicious_strings": "可疑命令行 / 脚本片段",
            "longest_strings": "最长字符串样本",
            "top_characters": "高频字符分布",
        }

        for key, title in string_sections.items():
            entries = string_samples.get(key)
            if not entries:
                continue

            if key == "top_characters":
                lines.extend([
                    "",
                    "### 高频字符分布",
                    "",
                    "| 字符 | 计数 |",
                    "| --- | ---: |",
                ])
                for entry in entries[:10]:
                    lines.append(f"| `{entry.get('char')}` | {entry.get('count', 0)} |")
                continue

            lines.extend([
                "",
                f"### {title}",
                "",
            ])
            for item in entries[:10]:
                lines.append(f"- {item}")

        if section_overview:
            lines.extend([
                "",
                "## 节区分布概览",
                "",
                "| 节区 | 大小 (字节) | 虚拟大小 | 熵 | 关键特征 |",
                "| --- | ---: | ---: | ---: | --- |",
            ])
            for sec in section_overview:
                characteristics = ", ".join(sec.get("characteristics", [])[:4])
                lines.append(
                    f"| `{sec.get('name')}` | {sec.get('size')} | {sec.get('virtual_size')} | "
                    f"{sec.get('entropy', 0.0):.2f} | {characteristics or '无'} |"
                )

        if dll_usage:
            lines.extend([
                "",
                "## 导入 DLL 统计",
                "",
                "| DLL | 导入函数数量 |",
                "| --- | ---: |",
            ])
            for entry in dll_usage[:15]:
                lines.append(f"| {entry.get('dll', '未知')} | {entry.get('count', 0)} |")

        if active_data_dirs:
            lines.extend([
                "",
                "## 数据目录概览",
                "",
                "| 数据目录 | 大小 | RVA |",
                "| --- | ---: | ---: |",
            ])
            for entry in active_data_dirs[:15]:
                lines.append(
                    f"| {entry.get('name', '未知')} | {entry.get('size', 0)} | {entry.get('virtual_address', 0)} |"
                )

        if exports:
            lines.extend([
                "",
                "## 导出函数",
                "",
            ])
            for item in exports[:30]:
                lines.append(f"- {item}")

        features = result.get("features", {})
        if isinstance(features, dict):
            sha256 = features.get("sha256")
            md5 = features.get("md5")
            if sha256 or md5:
                lines.extend([
                    "",
                    "## 哈希信息",
                    "",
                ])
                if sha256:
                    lines.append(f"- SHA-256: `{sha256}`")
                if md5:
                    lines.append(f"- MD5: `{md5}`")

        lines.append("")
        return "\n".join(lines)
