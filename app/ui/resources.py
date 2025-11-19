# app/ui/resources.py
"""
UI资源管理模块
包含图标、样式、字符串等资源的定义和管理
"""

# 图标资源路径
ICON_PATHS = {
    "app_icon": "icons/app_icon.png",
    "file_icon": "icons/file_icon.png",
    "folder_icon": "icons/folder_icon.png",
    "report_icon": "icons/report_icon.png",
    "log_icon": "icons/log_icon.png",
    "settings_icon": "icons/settings_icon.png"
}

# 样式表资源
STYLE_SHEETS = {
    "default": "styles/default.qss",
    "dark": "styles/dark.qss",
    "light": "styles/light.qss"
}

# 字符串资源
UI_STRINGS = {
    "app_title": "基于机器学习的恶意PE文件检测系统",
    "file_info": "文件信息",
    "data_cleaning": "数据清洗",
    "extract_feature": "提取特征",
    "feature_transform": "特征转换",
    "train_model": "训练模型",
    "test_model": "测试模型",
    "model_predict": "模型预测",
    "get_benign": "获取良性",
    "sandbox": "沙箱检测",
    "install_deps": "安装依赖",
    "download_report": "下载报告",
    "view_logs": "查看日志",
    "select_model": "选择模型请下拉选项"
}

# 颜色资源
COLORS = {
    "primary": "#0000ff",
    "secondary": "#666666",
    "success": "#28a745",
    "warning": "#ffc107",
    "danger": "#dc3545",
    "info": "#17a2b8",
    "light": "#f8f9fa",
    "dark": "#343a40"
}

# 字体资源
FONTS = {
    "title": "Arial, 48pt, bold",
    "heading": "Arial, 16pt, bold",
    "body": "Arial, 12pt, normal",
    "caption": "Arial, 10pt, normal"
}


def get_icon_path(icon_name: str) -> str:
    """
    获取图标路径
    :param icon_name: 图标名称
    :return: 图标路径
    """
    return ICON_PATHS.get(icon_name, "")


def get_style_sheet(style_name: str = "default") -> str:
    """
    获取样式表路径
    :param style_name: 样式名称
    :return: 样式表路径
    """
    return STYLE_SHEETS.get(style_name, STYLE_SHEETS["default"])


def get_ui_string(key: str) -> str:
    """
    获取UI字符串
    :param key: 字符串键
    :return: 字符串值
    """
    return UI_STRINGS.get(key, key)


def get_color(color_name: str) -> str:
    """
    获取颜色值
    :param color_name: 颜色名称
    :return: 颜色值
    """
    return COLORS.get(color_name, "#000000")


def get_font(font_name: str) -> str:
    """
    获取字体设置
    :param font_name: 字体名称
    :return: 字体设置
    """
    return FONTS.get(font_name, FONTS["body"])
