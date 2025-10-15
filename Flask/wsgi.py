"""WSGI entry point for running the Flask service under a process manager."""
from __future__ import annotations

from Flask import create_app

# BaoTa 面板的 WSGI 模式默认会在该模块中查找名为 ``application`` 的对象。
# 我们同时暴露 ``app`` 变量以兼容常见的 WSGI 部署脚本。
application = create_app()
app = application
