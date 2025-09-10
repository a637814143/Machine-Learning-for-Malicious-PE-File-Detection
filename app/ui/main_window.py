# app/ui/main_window.py
from pathlib import Path

from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import QFileDialog
from .progress_dialog import Worker
from .report_view import ReportManager
from core.utils.logger import set_log
from scripts.FILE_NAME import GET_TIME


class MachineLearningPEUI(QtWidgets.QDialog):
    """基于机器学习的恶意PE文件检测系统主窗口"""

    def __init__(self):
        super().__init__()
        self.workers = {}
        self.report_manager = ReportManager()
        self.setupUi()

    def setupUi(self):
        """设置用户界面"""
        self.setObjectName("Dialog")
        self.resize(1400, 860)

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
        self.inputLineEdit.setGeometry(QtCore.QRect(20, 160, 851, 31))
        self.inputLineEdit.setObjectName("inputLineEdit")

        self.outputLineEdit = QtWidgets.QLineEdit(self)
        self.outputLineEdit.setGeometry(QtCore.QRect(20, 200, 851, 31))
        self.outputLineEdit.setObjectName("outputLineEdit")

        # 选择按钮
        self.selectInputButton = QtWidgets.QPushButton("选择文件(夹)", self)
        self.selectInputButton.setGeometry(QtCore.QRect(890, 160, 121, 31))
        self.selectInputButton.setObjectName("selectInputButton")

        self.selectOutputButton = QtWidgets.QPushButton("选择文件(夹)", self)
        self.selectOutputButton.setGeometry(QtCore.QRect(890, 200, 121, 31))
        self.selectOutputButton.setObjectName("selectOutputButton")

        # 复选框
        self.useInputCheckBox = QtWidgets.QCheckBox("使用输入", self)
        self.useInputCheckBox.setGeometry(QtCore.QRect(1030, 160, 91, 31))
        self.useInputCheckBox.setObjectName("useInputCheckBox")

        self.useOutputCheckBox = QtWidgets.QCheckBox("使用输出", self)
        self.useOutputCheckBox.setGeometry(QtCore.QRect(1030, 200, 91, 31))
        self.useOutputCheckBox.setObjectName("useOutputCheckBox")

    def _setup_main_output_section(self):
        """设置主输出区域"""
        self.resultTextBrowser = QtWidgets.QTextBrowser(self)
        self.resultTextBrowser.setGeometry(QtCore.QRect(20, 290, 851, 551))
        self.resultTextBrowser.setObjectName("resultTextBrowser")

    def _setup_title_section(self):
        """设置标题区域"""
        self.titleTextBrowser = QtWidgets.QTextBrowser(self)
        self.titleTextBrowser.setGeometry(QtCore.QRect(20, 20, 1361, 111))
        self.titleTextBrowser.setHtml(
            "<p align='center'><span style=' font-size:48pt; font-weight:600; color:#0000ff;'>"
            "基于机器学习的恶意PE文件检测系统</span></p>"
        )

    def _setup_progress_section(self):
        """设置进度条区域"""
        # 标签
        self.lbl_file_info = QtWidgets.QLabel("文件信息", self)
        self.lbl_file_info.setGeometry(890, 300, 85, 25)

        self.lbl_data_cleaning = QtWidgets.QLabel("数据清洗", self)
        self.lbl_data_cleaning.setGeometry(890, 340, 85, 25)

        self.lbl_extract_feature = QtWidgets.QLabel("提取特征", self)
        self.lbl_extract_feature.setGeometry(890, 380, 85, 25)

        self.lbl_feature_transform = QtWidgets.QLabel("特征转换", self)
        self.lbl_feature_transform.setGeometry(890, 420, 85, 25)

        self.lbl_train_model = QtWidgets.QLabel("训练模型", self)
        self.lbl_train_model.setGeometry(890, 460, 85, 25)

        self.lbl_test_model = QtWidgets.QLabel("测试模型", self)
        self.lbl_test_model.setGeometry(890, 500, 85, 25)

        self.lbl_static_detect = QtWidgets.QLabel("静态检测", self)
        self.lbl_static_detect.setGeometry(890, 540, 85, 25)

        self.lbl_get_benign = QtWidgets.QLabel("获取良性", self)
        self.lbl_get_benign.setGeometry(890, 580, 85, 25)

        self.lbl_sandbox = QtWidgets.QLabel("沙箱检测", self)
        self.lbl_sandbox.setGeometry(890, 620, 85, 25)

        self.lbl_install_deps = QtWidgets.QLabel("安装依赖", self)
        self.lbl_install_deps.setGeometry(890, 660, 85, 25)

        # 进度条
        self.progress_file_info = QtWidgets.QProgressBar(self)
        self.progress_file_info.setGeometry(985, 300, 245, 25)
        self.progress_file_info.setValue(0)

        self.progress_data_cleaning = QtWidgets.QProgressBar(self)
        self.progress_data_cleaning.setGeometry(985, 340, 245, 25)
        self.progress_data_cleaning.setValue(0)

        self.progress_extract_feature = QtWidgets.QProgressBar(self)
        self.progress_extract_feature.setGeometry(985, 380, 245, 25)
        self.progress_extract_feature.setValue(0)

        self.progress_feature_transform = QtWidgets.QProgressBar(self)
        self.progress_feature_transform.setGeometry(985, 420, 245, 25)
        self.progress_feature_transform.setValue(0)

        self.progress_train_model = QtWidgets.QProgressBar(self)
        self.progress_train_model.setGeometry(985, 460, 245, 25)
        self.progress_train_model.setValue(0)

        self.progress_test_model = QtWidgets.QProgressBar(self)
        self.progress_test_model.setGeometry(985, 500, 245, 25)
        self.progress_test_model.setValue(0)

        self.progress_static_detect = QtWidgets.QProgressBar(self)
        self.progress_static_detect.setGeometry(985, 540, 245, 25)
        self.progress_static_detect.setValue(0)

        self.progress_get_benign = QtWidgets.QProgressBar(self)
        self.progress_get_benign.setGeometry(985, 580, 245, 25)
        self.progress_get_benign.setValue(0)

        self.progress_sandbox = QtWidgets.QProgressBar(self)
        self.progress_sandbox.setGeometry(985, 620, 245, 25)
        self.progress_sandbox.setValue(0)

        self.progress_install_deps = QtWidgets.QProgressBar(self)
        self.progress_install_deps.setGeometry(985, 660, 245, 25)
        self.progress_install_deps.setValue(0)

        # 进度条映射
        self.progressBars = {
            "文件信息": self.progress_file_info,
            "数据清洗": self.progress_data_cleaning,
            "提取特征": self.progress_extract_feature,
            "特征转换": self.progress_feature_transform,
            "训练模型": self.progress_train_model,
            "测试模型": self.progress_test_model,
            "静态检测": self.progress_static_detect,
            "获取良性": self.progress_get_benign,
            "沙箱检测": self.progress_sandbox,
            "安装依赖": self.progress_install_deps,
        }

    def _setup_function_buttons(self):
        """设置功能按钮"""
        # 右侧功能按钮
        self.btn_file_info = QtWidgets.QPushButton("文件信息", self)
        self.btn_file_info.setGeometry(1250, 160, 131, 41)

        self.btn_data_cleaning = QtWidgets.QPushButton("数据清洗", self)
        self.btn_data_cleaning.setGeometry(1250, 210, 131, 41)

        self.btn_extract_feature = QtWidgets.QPushButton("提取特征", self)
        self.btn_extract_feature.setGeometry(1250, 260, 131, 41)

        self.btn_feature_transform = QtWidgets.QPushButton("特征转换", self)
        self.btn_feature_transform.setGeometry(1250, 310, 131, 41)

        self.btn_model_train = QtWidgets.QPushButton("模型训练", self)
        self.btn_model_train.setGeometry(1250, 360, 131, 41)

        self.btn_model_test = QtWidgets.QPushButton("测试模型", self)
        self.btn_model_test.setGeometry(1250, 410, 131, 41)

        self.btn_static_detect = QtWidgets.QPushButton("静态检测", self)
        self.btn_static_detect.setGeometry(1250, 460, 131, 41)

        self.btn_get_benign = QtWidgets.QPushButton("获取良性", self)
        self.btn_get_benign.setGeometry(1250, 510, 131, 41)

        self.btn_sandbox = QtWidgets.QPushButton("沙箱检测", self)
        self.btn_sandbox.setGeometry(1250, 560, 131, 41)

        self.btn_install_deps = QtWidgets.QPushButton("安装依赖", self)
        self.btn_install_deps.setGeometry(1250, 610, 131, 41)

        # 按钮任务映射
        self.button_task_map = {
            self.btn_file_info: "文件信息",
            self.btn_data_cleaning: "数据清洗",
            self.btn_extract_feature: "提取特征",
            self.btn_feature_transform: "特征转换",
            self.btn_model_train: "训练模型",
            self.btn_model_test: "测试模型",
            self.btn_static_detect: "静态检测",
            self.btn_get_benign: "获取良性",
            self.btn_sandbox: "沙箱检测",
            self.btn_install_deps: "安装依赖",
        }

    def _setup_bottom_section(self):
        """设置底部区域"""
        # 中下部按钮
        self.btn_download_report = QtWidgets.QPushButton("下载报告", self)
        self.btn_download_report.setGeometry(890, 695, 160, 35)

        self.btn_view_logs = QtWidgets.QPushButton("查看日志", self)
        self.btn_view_logs.setGeometry(1060, 695, 160, 35)

        self.btn_clear_text = QtWidgets.QPushButton("清空文本展示区", self)
        self.btn_clear_text.setGeometry(1230, 695, 161, 35)

        # 底部信息
        self.infoTextBrowser = QtWidgets.QTextBrowser(self)
        self.infoTextBrowser.setGeometry(890, 740, 341, 101)
        self.infoTextBrowser.setHtml(
            "<p>大理大学 @2025<br/>数学与计算机学院 22级 信息安全班 蒋添麒<br/>"
            "Github Address:<br/>https://github.com/a637814143/Machine-Learning-for-Mailcious-PE-File-Detection</p>"
        )

        # 下拉框
        self.modelComboBox = QtWidgets.QComboBox(self)
        self.modelComboBox.setGeometry(1250, 740, 131, 21)
        self.modelComboBox.addItems(["随机森林", "SNN", "深度树"])

    def _setup_middle_labels(self):
        """设置中间标签"""
        self.middleLabel_result = QtWidgets.QLabel("运行结果区", self)
        self.middleLabel_result.setGeometry(400, 250, 111, 21)

        self.middleLabel_progress = QtWidgets.QLabel("进度展示区", self)
        self.middleLabel_progress.setGeometry(1010, 250, 111, 21)

    def _bind_events(self):
        """绑定事件"""
        # 文件选择按钮
        self.selectInputButton.clicked.connect(self.select_input_file)
        self.selectOutputButton.clicked.connect(self.select_output_file)

        # 功能按钮
        for btn, name in self.button_task_map.items():
            btn.clicked.connect(lambda checked, tn=name: self.start_task(tn))

        # 其他按钮
        self.btn_download_report.clicked.connect(self.download_report)
        self.btn_view_logs.clicked.connect(self.view_logs)
        self.btn_clear_text.clicked.connect(self.clear_result_text)

    # --- 文件选择槽 ---
    def select_input_file(self):
        """选择输入文件"""
        print("[DEBUG] select_input_file called")
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
        return tuple(params)

    def start_task(self, task_name: str):
        """启动任务"""
        params = self._get_params()
        if not params and task_name == "文件信息":
            self._append_result_text("请选择输入文件")
            return

        worker = Worker(task_name, params)
        self.workers[task_name] = worker

        if task_name in self.progressBars:
            worker.progress_signal.connect(self.progressBars[task_name].setValue)

        # 如果是文件信息任务，区分HTML和普通文本
        worker.text_signal.connect(self._append_result_text_or_html)

        #self._append_result_text(f"任务启动: {task_name} 参数: {params}")
        worker.start()

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
        self._append_result_text("下载报告：占位（未实现）")

    def view_logs(self):
        """查看日志"""
        self._append_result_text("查看日志：占位（未实现）")

    def clear_result_text(self):
        """清空文件信息展示区"""
        self.resultTextBrowser.clear()