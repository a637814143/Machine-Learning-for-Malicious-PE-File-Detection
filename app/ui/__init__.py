# app/ui/__init__.py
"""
UI模块包
包含所有用户界面相关的类和函数
"""

from .main_window import MachineLearningPEUI
from .progress_dialog import Worker
from .report_view import ReportManager
from .resources import (
    get_icon_path, 
    get_style_sheet, 
    get_ui_string, 
    get_color, 
    get_font
)
from core.utils.visualization import get_pe_info_html as FileInfo
from core.utils.logger import set_log

__all__ = [
    'MachineLearningPEUI',
    'Worker', 
    'ReportManager',
    'get_icon_path',
    'get_style_sheet',
    'get_ui_string',
    'get_color',
    'get_font',
    'FileInfo',
    'set_log'
]

__version__ = "2.1.0"
__author__ = "a637814143"
__organization__ = "single"
