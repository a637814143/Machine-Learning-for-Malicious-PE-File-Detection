# app/ui/progress_dialog.py
"""Thread worker that executes registered tasks asynchronously."""

from PyQt5 import QtCore
from app.tasks import TASKS


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
        task = TASKS.get(self.task_name)
        if not task:
            self.text_signal.emit(f"{self.task_name} 未实现")
            return

        def progress(value: int):
            if not self._stopped:
                self.progress_signal.emit(value)

        def text(msg: str):
            if not self._stopped:
                self.text_signal.emit(msg)

        task(self.args, progress, text)

    def stop(self):
        """停止任务"""
        self._stopped = True
