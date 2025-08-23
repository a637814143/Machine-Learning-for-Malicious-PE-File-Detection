# app/ui/progress_dialog.py
from PyQt5 import QtCore
from pathlib import Path
import time


class Worker(QtCore.QThread):
    """后台工作线程，用于执行耗时任务"""

    progress_signal = QtCore.pyqtSignal(int)  # 进度信号
    text_signal = QtCore.pyqtSignal(str)  # 文本或HTML信号

    def __init__(self, task_name: str, args):
        super().__init__()
        self.task_name = task_name
        self.args = args
        self._stopped = False

    def run(self):
        """执行任务"""
        if self.task_name == "文件信息" and self.args:
            self._run_file_info(Path(self.args[0]))
        else:
            # 模拟其他任务
            for i in range(1, 101):
                if self._stopped:
                    break
                time.sleep(0.02)
                self.progress_signal.emit(i)
                if i % 10 == 0:
                    self.text_signal.emit(f"{self.task_name} 进行中: {i}% 参数: {self.args}")
            if not self._stopped:
                self.text_signal.emit(f"{self.task_name} 完成，参数: {self.args}")

    def _run_file_info(self, file_path: Path):
        """文件信息任务，解析节区和导入函数并更新进度"""
        try:
            import pefile
            pe = pefile.PE(str(file_path))
        except Exception as e:
            self.text_signal.emit(f"解析PE失败: {e}")
            return

        # 节区进度
        total_sections = len(pe.sections)
        for idx, section in enumerate(pe.sections, 1):
            if self._stopped:
                return
            percent = int((idx / total_sections) * 50)  # 节区占前50%
            self.progress_signal.emit(percent)
            self.text_signal.emit(f"解析节区 {idx}/{total_sections}: {section.Name.decode(errors='ignore')}")

        # 导入表进度
        imports = getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
        total_funcs = sum(len(imp.imports) for imp in imports) or 1
        counted = 0
        for imp in imports:
            for func in imp.imports:
                if self._stopped:
                    return
                counted += 1
                percent = 50 + int((counted / total_funcs) * 50)  # 导入函数占后50%
                self.progress_signal.emit(percent)
                self.text_signal.emit(
                    f"解析导入函数 {counted}/{total_funcs}: {func.name.decode(errors='ignore') if func.name else 'None'}")

        # 完成后生成 HTML
        from app.ui import FileInfo
        html = FileInfo(file_path)
        self.text_signal.emit(html)

    def stop(self):
        """停止任务"""
        self._stopped = True
