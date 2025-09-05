# app/main.py
"""
基于机器学习的恶意PE文件检测系统
主程序入口
"""

import sys
from PyQt5 import QtWidgets
from ui.main_window import MachineLearningPEUI
from scripts.ROOT_PATH import ROOT
from random import randint

def main():
    """主函数"""
    try:
        # 创建Qt应用
        app = QtWidgets.QApplication(sys.argv)
        
        # 设置应用信息
        app.setApplicationName("恶意PE文件检测系统")
        app.setApplicationVersion("1.0.0")
        app.setOrganizationName("大理大学")

        # 随机皮肤
        qss = [str(i + 1) + '.qss' for i in range(10)]
        qss_path = ROOT / "app" / "styles" / qss[randint(2022110, 8900253) % 10]
        print(f"[DEBUG] selected {qss_path}")
        qss_file = open(qss_path, 'r').read()
        app.setStyleSheet(qss_file)
        
        # 创建主窗口
        main_window = MachineLearningPEUI()
        main_window.show()
        
        # 运行应用
        sys.exit(app.exec_())
        
    except Exception as e:
        print(f"程序启动失败: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
