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

__all__ = [
    'MachineLearningPEUI',
    'Worker', 
    'ReportManager',
    'get_icon_path',
    'get_style_sheet',
    'get_ui_string',
    'get_color',
    'get_font'
]

__version__ = "1.0.0"
__author__ = "蒋添麒"
__organization__ = "大理大学数学与计算机学院"
