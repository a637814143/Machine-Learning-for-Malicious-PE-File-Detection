# app/ui/progress_dialog.py
from PyQt5 import QtCore
import time

class Worker(QtCore.QThread):
    """后台工作线程，用于执行耗时任务"""
    
    progress_signal = QtCore.pyqtSignal(int)  # 进度信号
    text_signal = QtCore.pyqtSignal(str)      # 文本信号

    def __init__(self, task_name: str, args):
        """
        初始化工作线程
        :param task_name: 任务名称
        :param args: 任务参数
        """
        super().__init__()
        self.task_name = task_name
        self.args = args
        self._stopped = False

    def run(self):
        """执行任务"""
        for i in range(1, 101):
            if self._stopped:
                break
            time.sleep(0.02)
            self.progress_signal.emit(i)
            if i % 10 == 0:
                self.text_signal.emit(f"{self.task_name} 进行中: {i}% 参数: {self.args}")
        
        if not self._stopped:
            self.text_signal.emit(f"{self.task_name} 完成，参数: {self.args}")

    def stop(self):
        """停止任务"""
        self._stopped = True
