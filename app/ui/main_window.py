
# app/ui/main_window.py

from datetime import datetime
from pathlib import Path

from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import QFileDialog
from .progress_dialog import Worker
from .report_view import ReportManager
from .dynamic_analysis_dialog import DynamicAnalysisDialog
from scripts.GET_B import BenignResourceDialog
from core.utils.logger import set_log
from scripts.FILE_NAME import GET_TIME
from scripts.D import predict_file_with_features, DETECTION_MODES
from scripts.ROOT_PATH import ROOT


class MachineLearningPEUI(QtWidgets.QDialog):
    """基于机器学习的恶意PE文件检测系统主窗口"""

    def __init__(self):
        super().__init__()
        self._settings = QtCore.QSettings()
        self.workers = {}
        self.report_manager = ReportManager()
        self._benign_dialog = None
        self._dynamic_dialog = None
        self._mode_keys = list(DETECTION_MODES.keys())
        self.setupUi()

    def setupUi(self):
        """设置用户界面"""
        self.setObjectName("Dialog")
        self.resize(1920, 980)

        # --- 输入与选择 ---
        self._setup_input_output_section()

        # --- 主输出区 ---
        self._setup_main_output_section()

        # --- 顶部标题 ---
        self._setup_title_section()

        # --- 右侧进度条区域 ---
        self._setup_progress_section()

        # --- 右侧功能按钮 ---
        self._setup_function_buttons()

        # --- 底部区域 ---
        self._setup_bottom_section()

        # --- 中间标签 ---
        self._setup_middle_labels()

        # --- 绑定事件 ---
        self._bind_events()

    def _setup_input_output_section(self):
        """设置输入输出区域"""
        # 输入输出文本框
        self.inputLineEdit = QtWidgets.QLineEdit(self)
        self.inputLineEdit.setGeometry(QtCore.QRect(20, 160, 851 + 300, 31 + 9))
        self.inputLineEdit.setObjectName("inputLineEdit")

        self.outputLineEdit = QtWidgets.QLineEdit(self)
        self.outputLineEdit.setGeometry(QtCore.QRect(20, 200 + 9, 851 + 300, 31 + 9))
        self.outputLineEdit.setObjectName("outputLineEdit")

        # 选择按钮
        self.selectInputButton = QtWidgets.QPushButton("选择文件(夹)", self)
        self.selectInputButton.setGeometry(QtCore.QRect(890 + 300, 160, 121, 31 + 9))
        self.selectInputButton.setObjectName("selectInputButton")

        self.selectOutputButton = QtWidgets.QPushButton("选择文件(夹)", self)
        self.selectOutputButton.setGeometry(QtCore.QRect(890 + 300, 200 + 9, 121, 31 + 9))
        self.selectOutputButton.setObjectName("selectOutputButton")

        # 复选框
        self.useInputCheckBox = QtWidgets.QCheckBox("使用输入", self)
        self.useInputCheckBox.setGeometry(QtCore.QRect(1030 + 285, 165, 91, 31))
        self.useInputCheckBox.setObjectName("useInputCheckBox")

        self.useOutputCheckBox = QtWidgets.QCheckBox("使用输出", self)
        self.useOutputCheckBox.setGeometry(QtCore.QRect(1030 + 285, 215, 91, 31))
        self.useOutputCheckBox.setObjectName("useOutputCheckBox")

    def _setup_main_output_section(self):
        """设置主输出区域"""
        self.resultTextBrowser = QtWidgets.QTextBrowser(self)
        self.resultTextBrowser.setGeometry(QtCore.QRect(20, 290, 1370, 551))
        self.resultTextBrowser.setObjectName("resultTextBrowser")

    def _setup_title_section(self):
        """设置标题区域"""
        self.titleTextBrowser = QtWidgets.QTextBrowser(self)
        self.titleTextBrowser.setGeometry(QtCore.QRect(20, 20, 1880, 111))
        self.titleTextBrowser.setHtml(
            "<p align='center'><span style=' font-size:48pt; font-weight:600; color:#0000ff;'>"
            "基于机器学习的恶意PE文件检测系统</span></p>"
        )

    def _setup_progress_section(self):
        """设置进度条区域"""
        # 标签
        self.lbl_file_info = QtWidgets.QLabel("文件信息", self)
        self.lbl_file_info.setGeometry(1250 + 550 - 400, 160, 131, 41)

        self.lbl_data_cleaning = QtWidgets.QLabel("数据清洗", self)
        self.lbl_data_cleaning.setGeometry(1250 + 550 - 400, 210, 131, 41)

        self.lbl_extract_feature = QtWidgets.QLabel("提取特征", self)
        self.lbl_extract_feature.setGeometry(1250 + 550 - 400, 260, 131, 41)

        self.lbl_feature_transform = QtWidgets.QLabel("特征转换", self)
        self.lbl_feature_transform.setGeometry(1250 + 550 - 400, 310, 131, 41)

        self.lbl_train_model = QtWidgets.QLabel("训练模型", self)
        self.lbl_train_model.setGeometry(1250 + 550 - 400, 360, 131, 41)

        self.lbl_test_model = QtWidgets.QLabel("测试模型", self)
        self.lbl_test_model.setGeometry(1250 + 550 - 400, 410, 131, 41)

        self.lbl_model_predict = QtWidgets.QLabel("模型预测", self)
        self.lbl_model_predict.setGeometry(1250 + 550 - 400, 460, 131, 41)

        self.lbl_get_benign = QtWidgets.QLabel("获取良性", self)
        self.lbl_get_benign.setGeometry(1250 + 550 - 400, 510, 131, 41)

        self.lbl_sandbox = QtWidgets.QLabel("沙箱检测", self)
        self.lbl_sandbox.setGeometry(1250 + 550 - 400, 560, 131, 41)

        self.lbl_install_deps = QtWidgets.QLabel("安装依赖", self)
        self.lbl_install_deps.setGeometry(1250 + 550 - 400, 610, 131, 41)

        # 进度条
        self.progress_file_info = QtWidgets.QProgressBar(self)
        self.progress_file_info.setGeometry(1250 + 200 + 20 - 4, 160 + 2, 300, 40 - 4)
        self.progress_file_info.setValue(0)

        self.progress_data_cleaning = QtWidgets.QProgressBar(self)
        self.progress_data_cleaning.setGeometry(1250 + 200 + 20 - 4, 210 + 2, 300, 40 - 4)
        self.progress_data_cleaning.setValue(0)

        self.progress_extract_feature = QtWidgets.QProgressBar(self)
        self.progress_extract_feature.setGeometry(1250 + 200 + 20 - 4, 260 + 2, 300, 40 - 4)
        self.progress_extract_feature.setValue(0)

        self.progress_feature_transform = QtWidgets.QProgressBar(self)
        self.progress_feature_transform.setGeometry(1250 + 200 + 20 - 4, 310 + 2, 300, 40 - 4)
        self.progress_feature_transform.setValue(0)

        self.progress_train_model = QtWidgets.QProgressBar(self)
        self.progress_train_model.setGeometry(1250 + 200 + 20 - 4, 360 + 2, 300, 40 - 4)
        self.progress_train_model.setValue(0)

        self.progress_test_model = QtWidgets.QProgressBar(self)
        self.progress_test_model.setGeometry(1250 + 200 + 20 - 4, 410 + 2, 300, 40 - 4)
        self.progress_test_model.setValue(0)

        self.progress_model_predict = QtWidgets.QProgressBar(self)
        self.progress_model_predict.setGeometry(1250 + 200 + 20 - 4, 460 + 2, 300, 40 - 4)
        self.progress_model_predict.setValue(0)

        self.progress_get_benign = QtWidgets.QProgressBar(self)
        self.progress_get_benign.setGeometry(1250 + 200 + 20 - 4, 510 + 2, 300, 40 - 4)
        self.progress_get_benign.setValue(0)

        self.progress_sandbox = QtWidgets.QProgressBar(self)
        self.progress_sandbox.setGeometry(1250 + 200 + 20 - 4, 560 + 2, 300, 40 - 4)
        self.progress_sandbox.setValue(0)

        self.progress_install_deps = QtWidgets.QProgressBar(self)
        self.progress_install_deps.setGeometry(1250 + 200 + 20 - 4, 610 + 2, 300, 40 - 4)
        self.progress_install_deps.setValue(0)

        # 进度条映射
        self.progressBars = {
            "文件信息": self.progress_file_info,
            "数据清洗": self.progress_data_cleaning,
            "提取特征": self.progress_extract_feature,
            "特征转换": self.progress_feature_transform,
            "训练模型": self.progress_train_model,
            "测试模型": self.progress_test_model,
            "模型预测": self.progress_model_predict,
            "获取良性": self.progress_get_benign,
            "沙箱检测": self.progress_sandbox,
            "安装依赖": self.progress_install_deps,
        }

    def _setup_function_buttons(self):
        """设置功能按钮"""
        # 右侧功能按钮
        self.btn_file_info = QtWidgets.QPushButton("文件信息", self)
        self.btn_file_info.setGeometry(1250 + 520, 160, 131, 41)

        self.btn_data_cleaning = QtWidgets.QPushButton("数据清洗", self)
        self.btn_data_cleaning.setGeometry(1250 + 520, 210, 131, 41)

        self.btn_extract_feature = QtWidgets.QPushButton("提取特征", self)
        self.btn_extract_feature.setGeometry(1250 + 520, 260, 131, 41)

        self.btn_feature_transform = QtWidgets.QPushButton("特征转换", self)
        self.btn_feature_transform.setGeometry(1250 + 520, 310, 131, 41)

        self.btn_model_train = QtWidgets.QPushButton("模型训练", self)
        self.btn_model_train.setGeometry(1250 + 520, 360, 131, 41)

        self.btn_model_test = QtWidgets.QPushButton("测试模型", self)
        self.btn_model_test.setGeometry(1250 + 520, 410, 131, 41)

        self.btn_model_predict = QtWidgets.QPushButton("模型预测", self)
        self.btn_model_predict.setGeometry(1250 + 520, 460, 131, 41)

        self.btn_get_benign = QtWidgets.QPushButton("获取良性", self)
        self.btn_get_benign.setGeometry(1250 + 520, 510, 131, 41)

        self.btn_sandbox = QtWidgets.QPushButton("沙箱检测", self)
        self.btn_sandbox.setGeometry(1250 + 520, 560, 131, 41)

        self.btn_install_deps = QtWidgets.QPushButton("安装依赖", self)
        self.btn_install_deps.setGeometry(1250 + 520, 610, 131, 41)

        # 按钮任务映射
        self.button_task_map = {
            self.btn_file_info: "文件信息",
            self.btn_data_cleaning: "数据清洗",
            self.btn_extract_feature: "提取特征",
            self.btn_feature_transform: "特征转换",
            self.btn_model_train: "训练模型",
            self.btn_model_test: "测试模型",
            self.btn_model_predict: "模型预测",
            self.btn_get_benign: "获取良性",
            self.btn_sandbox: "沙箱检测",
            self.btn_install_deps: "安装依赖",
        }

    def _setup_bottom_section(self):
        """设置底部区域"""
        # 中下部按钮
        self.btn_download_report = QtWidgets.QPushButton("下载报告", self)
        self.btn_download_report.setGeometry(890 + 510, 665, 160, 41)

        self.btn_view_logs = QtWidgets.QPushButton("查看日志", self)
        self.btn_view_logs.setGeometry(1060 + 510, 665, 160, 41)

        self.btn_clear_text = QtWidgets.QPushButton("清空文本展示区", self)
        self.btn_clear_text.setGeometry(1230 + 510, 665, 161, 41)

        # 底部信息
        self.infoTextBrowser = QtWidgets.QTextBrowser(self)
        self.infoTextBrowser.setGeometry(20, 850, 1370, 120)
        self.infoTextBrowser.setHtml(
            """
    <div style="text-align:center;
                font-family:'SF Pro Display','Segoe UI','Helvetica Neue',Arial,sans-serif;
                color:#1c1c1e;">
      <a href="https://github.com/a637814143/Machine-Learning-for-Malicious-PE-File-Detection"
         style="display:inline-block;            /* 让整块都可点 */
                text-decoration:none;            /* 去下划线 */
                color:inherit;                   /* 继承文字颜色 */
                padding:8px 12px;                /* 扩大可点击区域 */
                border-radius:10px;">            <!-- 可按需保留圆角 -->
        <p style="margin:0; line-height:1.5;">
          a637814143 @2025<br/>
          a637814143<br/>
          Github Address Click
        </p>
      </a>
    </div>
    """
        )
        self.infoTextBrowser.setOpenExternalLinks(True)

        # 线程数与检测模式配置
        base_x = 1245 + 500 - 100 - 200 - 22
        base_y = 810 - 50

        model_y = base_y - 50
        self.modelPathLabel = QtWidgets.QLabel("模型文件", self)
        self.modelPathLabel.setGeometry(base_x, model_y, 80, 40)

        self.modelPathLineEdit = QtWidgets.QLineEdit(self)
        self.modelPathLineEdit.setGeometry(base_x + 80, model_y, 280, 40)
        self.modelPathLineEdit.setPlaceholderText("可选：选择 LightGBM 模型文件")
        default_model_path = self._resolve_default_model_path()
        if default_model_path:
            self.modelPathLineEdit.setText(default_model_path)

        self.modelBrowseButton = QtWidgets.QPushButton("选择", self)
        self.modelBrowseButton.setGeometry(base_x + 370, model_y, 80, 40)

        self.threadCountLabel = QtWidgets.QLabel("线程数", self)
        self.threadCountLabel.setGeometry(base_x, base_y, 60, 40)

        self.threadCountSpinBox = QtWidgets.QSpinBox(self)
        self.threadCountSpinBox.setGeometry(base_x + 60, base_y, 80, 40)
        self.threadCountSpinBox.setMinimum(1)
        self.threadCountSpinBox.setMaximum(100)
        self.threadCountSpinBox.setValue(8)  # 默认8个线程
        self.threadCountSpinBox.setToolTip("设置特征提取使用的线程数（1-100）")

        self.modeLabel = QtWidgets.QLabel("检测模式", self)
        self.modeLabel.setGeometry(base_x + 160, base_y, 80, 40)

        self.modeComboBox = QtWidgets.QComboBox(self)
        self.modeComboBox.setGeometry(base_x + 240, base_y, 220, 40)
        self._init_detection_mode_selector()

        validation_y = base_y + 50
        self.validationLabel = QtWidgets.QLabel("验证集", self)
        self.validationLabel.setGeometry(base_x, validation_y, 60, 40)

        self.validationLineEdit = QtWidgets.QLineEdit(self)
        self.validationLineEdit.setGeometry(base_x + 60, validation_y, 300, 40)
        self.validationLineEdit.setPlaceholderText("可选：选择验证集向量文件(.npz/.npy)")

        self.validationBrowseButton = QtWidgets.QPushButton("选择", self)
        self.validationBrowseButton.setGeometry(base_x + 370, validation_y, 80, 40)

    def _setup_middle_labels(self):
        """设置中间标签"""
        self.middleLabel_result = QtWidgets.QLabel("运行结果区", self)
        self.middleLabel_result.setGeometry(800, 260, 111, 21)

        self.middleLabel_progress = QtWidgets.QLabel("进度展示区", self)
        self.middleLabel_progress.setGeometry(1570, 140, 111, 21)


    def _init_detection_mode_selector(self):
        self.modeComboBox.clear()
        for key in self._mode_keys:
            mode = DETECTION_MODES.get(key)
            if not mode:
                continue
            display = f"{mode.label} · 阈值 {mode.threshold:.4f}"
            index = self.modeComboBox.count()
            self.modeComboBox.addItem(display, key)
            self.modeComboBox.setItemData(index, mode.description, QtCore.Qt.ToolTipRole)
        if self.modeComboBox.count():
            self.modeComboBox.setCurrentIndex(0)

    def _current_detection_mode(self):
        key = self.modeComboBox.currentData()
        if key not in DETECTION_MODES:
            key = self._mode_keys[0]
            try:
                index = self._mode_keys.index(key)
                self.modeComboBox.setCurrentIndex(index)
            except ValueError:
                pass
        return key, DETECTION_MODES.get(key, next(iter(DETECTION_MODES.values())))

    def _bind_events(self):
        """绑定事件"""
        # 文件选择按钮
        self.selectInputButton.clicked.connect(self.select_input_file)
        self.selectOutputButton.clicked.connect(self.select_output_file)
        self.validationBrowseButton.clicked.connect(self.select_validation_vectors)
        self.modelBrowseButton.clicked.connect(self.select_model_file)

        # 功能按钮
        for btn, name in self.button_task_map.items():
            btn.clicked.connect(lambda checked, tn=name: self.start_task(tn))

        # 其他按钮
        self.btn_download_report.clicked.connect(self.download_report)
        self.btn_view_logs.clicked.connect(self.view_logs)
        self.btn_clear_text.clicked.connect(self.clear_result_text)

        # 记住模型文件路径
        self.modelPathLineEdit.editingFinished.connect(self._handle_model_path_edited)

    def _resolve_default_model_path(self) -> str:
        saved_path = self._settings.value("modelPath", type=str)
        if saved_path:
            try:
                saved = Path(saved_path)
            except OSError:
                saved = None
            else:
                if saved and saved.exists():
                    return str(saved)

        fallback = ROOT / "model.txt"
        if fallback.exists():
            return str(fallback)
        return ""

    def _handle_model_path_edited(self):
        path = self.modelPathLineEdit.text().strip()
        self._remember_model_path(path)

    def _remember_model_path(self, path: str):
        if path:
            self._settings.setValue("modelPath", path)
        else:
            self._settings.remove("modelPath")

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

    def select_validation_vectors(self):
        """选择验证向量文件"""
        set_log(GET_TIME("[DEBUG] select_validation_vectors called"))
        path, _ = QFileDialog.getOpenFileName(
            self,
            "选择验证集向量文件",
            filter="NumPy 文件 (*.npz *.npy);;所有文件 (*)",
        )
        if path:
            self.validationLineEdit.setText(path)

    def select_model_file(self):
        """选择模型文件"""
        set_log(GET_TIME("[DEBUG] select_model_file called"))
        path, _ = QFileDialog.getOpenFileName(
            self,
            "选择 LightGBM 模型文件",
            filter="LightGBM 模型 (*.txt *.model *.gbm);;所有文件 (*)",
        )
        if path:
            self.modelPathLineEdit.setText(path)
            self._remember_model_path(path)

    def _get_params(self):
        """获取参数"""
        params = []
        if self.useInputCheckBox.isChecked():
            params.append(self.inputLineEdit.text())
        if self.useOutputCheckBox.isChecked():
            params.append(self.outputLineEdit.text())

        # 添加线程数参数
        thread_count = self.threadCountSpinBox.value()
        params.append(str(thread_count))

        return tuple(params)

    def start_task(self, task_name: str):
        """启动任务"""
        if task_name == "获取良性":
            self.open_benign_resources()
            return

        if task_name == "沙箱检测":
            self.open_dynamic_analysis()
            return

        params = list(self._get_params())

        if task_name == "模型预测":
            mode_key, mode = self._current_detection_mode()
            params.append(f"MODE::{mode_key}")
            params.append(f"THRESH::{mode.threshold:.6f}")
            model_path = self.modelPathLineEdit.text().strip()
            if model_path:
                params.append(f"MODEL::{model_path}")

        if task_name == "训练模型":
            validation_path = self.validationLineEdit.text().strip()
            if validation_path:
                params.append(validation_path)


        # 检查必要参数
        if task_name == "文件信息" and not self.useInputCheckBox.isChecked():
            self._append_result_text("请选择输入文件")
            return

        if task_name in ["提取特征", "特征转换", "训练模型"] and not (
                self.useInputCheckBox.isChecked() and self.useOutputCheckBox.isChecked()
        ):
            self._append_result_text("请选择输入和输出路径")
            return

        # 重置对应任务的进度条
        if task_name in self.progressBars:
            self.progressBars[task_name].setValue(0)

        worker = Worker(task_name, tuple(params))
        self.workers[task_name] = worker

        if task_name in self.progressBars:
            worker.progress_signal.connect(self.progressBars[task_name].setValue)

        # 如果是文件信息任务，区分HTML和普通文本
        worker.text_signal.connect(self._append_result_text_or_html)

        # 显示启动信息
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

    def open_dynamic_analysis(self):
        """打开动态检测窗口并触发动态分析。"""
        if self._dynamic_dialog is None:
            self._dynamic_dialog = DynamicAnalysisDialog(self)
            self._dynamic_dialog.analysisCompleted.connect(
                self._handle_dynamic_analysis_completed
            )
            self._dynamic_dialog.analysisFailed.connect(self._append_result_text)

        # 每次打开前更新文件路径
        self._dynamic_dialog.set_file_path(self.inputLineEdit.text())
        self._dynamic_dialog.show()
        self._dynamic_dialog.raise_()
        self._dynamic_dialog.activateWindow()

    def _handle_dynamic_analysis_completed(self, html: str) -> None:
        """动态检测完成后刷新主界面展示。"""
        if "沙箱检测" in self.progressBars:
            self.progressBars["沙箱检测"].setValue(100)

        # 在结果区中展示格式化后的检测摘要
        if html.strip():
            self.resultTextBrowser.setHtml(html)

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

        model_override = self.modelPathLineEdit.text().strip() or None
        try:
            mode_key, mode = self._current_detection_mode()
            result = predict_file_with_features(
                str(target),
                model_path=model_override,
                threshold=mode.threshold,
                mode_key=mode_key,
            )
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

        detection_mode = result.get("detection_mode") or {}
        mode_label = detection_mode.get("label") or "默认模式"
        mode_threshold = float(detection_mode.get("threshold", threshold or 0.0))
        summary_line += f"，检测模式 {mode_label} (阈值 {mode_threshold:.4f})"

        self._append_result_text(summary_line)

        interpretation = result.get("score_interpretation")
        if interpretation:
            self._append_result_text(f"检测结论: {interpretation}")

        markdown_content = self._build_markdown_report(Path(result.get("file_path", target)), result)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"{target.stem}_report_{timestamp}.md"
        report_path = self.report_manager.create_markdown_report(markdown_content, report_name=report_name)

        if report_path:
            self._append_result_text(f"报告已生成: {report_path}")
        else:
            self._append_result_text("报告生成失败，请检查日志。")

    def view_logs(self):
        """查看日志"""
        log_lines = self.report_manager.view_logs(max_lines=300)
        if not log_lines:
            self._append_result_text("未找到可显示的日志内容。")
            return

        log_text = "".join(log_lines).strip()
        if not log_text:
            self._append_result_text("日志文件为空。")
            return

        log_dialog = QtWidgets.QDialog(self)
        log_dialog.setWindowTitle("查看日志")
        log_dialog.resize(900, 600)

        layout = QtWidgets.QVBoxLayout(log_dialog)
        text_edit = QtWidgets.QPlainTextEdit(log_dialog)
        text_edit.setReadOnly(True)
        text_edit.setPlainText(log_text)
        layout.addWidget(text_edit)

        close_button = QtWidgets.QPushButton("关闭", log_dialog)
        close_button.clicked.connect(log_dialog.close)
        layout.addWidget(close_button)

        self._append_result_text(f"显示日志共 {len(log_lines)} 行。")
        log_dialog.exec_()

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
        detection_mode = result.get("detection_mode") or {}
        mode_label = detection_mode.get("label", "默认模式")
        mode_desc = detection_mode.get("description", "")
        score_interpretation = result.get("score_interpretation")

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
        ]

        if mode_label:
            extra = f"，{mode_desc}" if mode_desc else ""
            lines.append(f"- 检测模式: {mode_label} (阈值 {threshold:.4f}{extra})")

        if score_interpretation:
            lines.append(f"- 检测结论: {score_interpretation}")

        lines.extend([
            "",
            "## 模型信心与风险评估",
            "",
            f"- 综合风险等级: **{risk_level}**",
            f"- 综合风险得分: **{risk_score:.1f} / 10**",
        ])

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
                lines.append(f"- 节区名包含 `{name}`，疑似常见壳标识。")

        benign_hits = summary.get("benign_api_hits", [])
        if benign_hits:
            lines.extend([
                "",
                "## 常见系统 API",
                "",
            ])
            for api in benign_hits[:10]:
                lines.append(f"- `{api}`")

        if strings:
            lines.extend([
                "",
                "## 字符串统计",
                "",
                f"- 可打印字符串数量: {printable_strings}",
                f"- 平均字符串长度: {avg_string_length:.2f}",
                f"- MZ 标记次数: {mz_count}",
            ])

        if isinstance(string_samples, dict):
            url_samples = string_samples.get("urls", [])
            ip_samples = string_samples.get("ips", [])
            path_samples = string_samples.get("paths", [])
            reg_samples = string_samples.get("registry", [])
            suspicious_strings = string_samples.get("suspicious", [])
            longest_strings = string_samples.get("longest", [])
            top_chars = string_samples.get("top_chars", [])

            if url_samples:
                lines.extend([
                    "",
                    "### URL 样本",
                    "",
                ])
                for item in url_samples[:10]:
                    lines.append(f"- {item}")

            if ip_samples:
                lines.extend([
                    "",
                    "### IP 地址样本",
                    "",
                ])
                for item in ip_samples[:10]:
                    lines.append(f"- {item}")

            if path_samples:
                lines.extend([
                    "",
                    "### 可疑文件路径样本",
                    "",
                ])
                for item in path_samples[:10]:
                    lines.append(f"- {item}")

            if reg_samples:
                lines.extend([
                    "",
                    "### 注册表键样本",
                    "",
                ])
                for item in reg_samples[:10]:
                    lines.append(f"- {item}")

            if suspicious_strings:
                lines.extend([
                    "",
                    "### 可疑命令行 / 脚本片段",
                    "",
                ])
                for item in suspicious_strings[:10]:
                    lines.append(f"- {item}")

            if longest_strings:
                lines.extend([
                    "",
                    "### 最长字符串样本",
                    "",
                ])
                for item in longest_strings[:10]:
                    lines.append(f"- {item}")

            if top_chars:
                lines.extend([
                    "",
                    "### 高频字符分布",
                    "",
                    "| 字符 | 计数 |",
                    "| --- | ---: |",
                ])
                for entry in top_chars[:10]:
                    lines.append(f"| `{entry.get('char')}` | {entry.get('count', 0)} |")

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
