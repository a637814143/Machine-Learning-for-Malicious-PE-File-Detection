# app/main.py
"""
基于机器学习的恶意PE文件检测系统
主程序入口
"""

import sys
from PyQt5 import QtWidgets

from core.utils.logger import set_log
from scripts.FILE_NAME import GET_TIME
from scripts.ROOT_PATH import ROOT
from ui.main_window import MachineLearningPEUI


def main():
    """主函数"""
    try:
        app = QtWidgets.QApplication(sys.argv)

        app.setApplicationName("恶意PE文件检测系统")
        app.setApplicationVersion("1.0.0")
        app.setOrganizationName("大理大学")

        qss_path = ROOT / "app" / "styles" / "modern_aqua.qss"
        if qss_path.exists():
            set_log(GET_TIME(f"[INFO] 使用样式表 {qss_path}"))
            with qss_path.open("r", encoding="utf-8") as handle:
                app.setStyleSheet(handle.read())
        else:
            set_log(GET_TIME(f"[WARN] 样式表 {qss_path} 缺失，使用默认外观"))

        main_window = MachineLearningPEUI()
        main_window.show()

        sys.exit(app.exec_())

    except Exception as exc:  # pragma: no cover - UI 启动保护
        print(f"程序启动失败: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
