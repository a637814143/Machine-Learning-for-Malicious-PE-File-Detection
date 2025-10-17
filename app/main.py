# app/main.py
"""
基于机器学习的恶意PE文件检测系统
主程序入口
"""

import sys
from importlib import util as _importlib_util
from pathlib import Path

# ``python app/main.py`` executes this file as a script which means Python only
# places the ``app`` directory (not its parent) on ``sys.path``.  When that
# happens, attempting to import ``app`` as a package fails.  To make the entry
# point robust we manually bootstrap the package using the file system location
# and register it in ``sys.modules`` before any other imports execute.
_PACKAGE_NAME = "app"
_PACKAGE_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _PACKAGE_DIR.parent

if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

if _PACKAGE_NAME not in sys.modules:
    _spec = _importlib_util.spec_from_file_location(
        _PACKAGE_NAME,
        _PACKAGE_DIR / "__init__.py",
        submodule_search_locations=[str(_PACKAGE_DIR)],
    )
    if _spec and _spec.loader:
        _module = _importlib_util.module_from_spec(_spec)
        sys.modules[_PACKAGE_NAME] = _module
        _spec.loader.exec_module(_module)

from PyQt5 import QtWidgets
from app.ui.main_window import MachineLearningPEUI
from scripts.ROOT_PATH import ROOT
from random import randint
from core.utils.logger import set_log
from scripts.FILE_NAME import GET_TIME


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
        qss_path = ROOT / "app" / "styles" / qss[3 if randint(2022110, 8900253) % 10 < 5 else 9]
        set_log(GET_TIME(f"[INFO] selected {qss_path}"))
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
