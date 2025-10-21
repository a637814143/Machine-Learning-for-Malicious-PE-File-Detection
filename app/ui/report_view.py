# app/ui/report_view.py
import os
import time
from pathlib import Path
from typing import Optional, List, Dict, Union

from core.utils.logger import LOG_DIR, list_logs, read_log, set_log
from scripts.ROOT_PATH import ROOT


class ReportManager:
    """报告和日志管理器"""

    def __init__(
            self,
            reports_dir: Optional[Union[str, os.PathLike]] = None,
            logs_dir: Optional[Union[str, os.PathLike]] = None,
    ):
        """
        初始化报告管理器
        :param reports_dir: 报告目录
        :param logs_dir: 日志目录
        """
        self.reports_dir = Path(reports_dir) if reports_dir else ROOT / "docs"
        self.logs_dir = Path(logs_dir) if logs_dir else LOG_DIR

        # 确保目录存在
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)

    def download_report(self, report_name: str = None) -> Optional[str]:
        """
        下载报告
        :param report_name: 报告名称，如果为None则使用最新报告
        :return: 报告文件路径或None
        """
        try:
            if report_name is None:
                # 获取最新的报告文件
                report_files = (
                        list(self.reports_dir.glob("*.pdf"))
                        + list(self.reports_dir.glob("*.html"))
                        + list(self.reports_dir.glob("*.md"))
                )
                if not report_files:
                    return None

                # 按修改时间排序，获取最新的
                latest_report = max(report_files, key=lambda x: x.stat().st_mtime)
                report_name = latest_report.name

            report_path = self.reports_dir / report_name
            if report_path.exists():
                return str(report_path)
            else:
                return None

        except Exception as e:
            print(f"下载报告失败: {e}")
            return None

    def view_logs(self, log_name: str = None, max_lines: int = 100) -> Optional[List[str]]:
        """
        查看日志
        :param log_name: 日志文件名，如果为None则使用最新日志
        :param max_lines: 最大显示行数
        :return: 日志内容列表或None
        """
        try:
            if max_lines is not None and max_lines <= 0:
                max_lines = None

            if log_name is None:
                # 获取最新的日志文件
                available = list_logs(self.logs_dir)
                if not available:
                    return None
                log_path = available[0]
            else:
                candidate = Path(log_name)
                log_path = candidate if candidate.is_absolute() else self.logs_dir / candidate

            if not log_path.exists():
                return None

            lines = read_log(log_path, max_lines=max_lines)
            return lines

        except Exception as e:
            print(f"查看日志失败: {e}")
            return None

    def get_available_reports(self) -> List[Dict[str, str]]:
        """
        获取可用的报告列表
        :return: 报告信息列表
        """
        try:
            reports = []
            for report_file in self.reports_dir.glob("*"):
                if report_file.is_file():
                    stat = report_file.stat()
                    reports.append({
                        "name": report_file.name,
                        "size": f"{stat.st_size / 1024:.1f} KB",
                        "modified": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_mtime)),
                        "path": str(report_file)
                    })

            # 按修改时间排序
            reports.sort(key=lambda x: x["modified"], reverse=True)
            return reports

        except Exception as e:
            print(f"获取报告列表失败: {e}")
            return []

    def get_available_logs(self) -> List[Dict[str, str]]:
        """
        获取可用的日志列表
        :return: 日志信息列表
        """
        try:
            logs: List[Dict[str, Union[str, float]]] = []
            for log_file in list_logs(self.logs_dir):
                stat = log_file.stat()
                logs.append({
                    "name": log_file.name,
                    "size": f"{stat.st_size / 1024:.1f} KB",
                    "modified": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_mtime)),
                    "path": str(log_file),
                    "_modified_ts": stat.st_mtime,
                })

            logs.sort(key=lambda x: x.get("_modified_ts", 0), reverse=True)
            for entry in logs:
                entry.pop("_modified_ts", None)
            return logs

        except Exception as e:
            print(f"获取日志列表失败: {e}")
            return []

    def create_report(self, content: str, report_name: str = None) -> Optional[str]:
        """
        创建报告
        :param content: 报告内容
        :param report_name: 报告名称，如果为None则自动生成
        :return: 报告文件路径或None
        """
        try:
            if report_name is None:
                from datetime import datetime
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                report_name = f"report_{timestamp}.html"

            report_path = self.reports_dir / report_name

            # 创建HTML格式的报告
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>恶意PE文件检测报告</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; text-align: center; }}
        .content {{ margin: 20px 0; }}
        .footer {{ text-align: center; color: #666; margin-top: 40px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>恶意PE文件检测报告</h1>
        <p>生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    <div class="content">
        {content}
    </div>
    <div class="footer">
        <p>大理大学 @2025 - 数学与计算机学院</p>
    </div>
</body>
</html>
            """

            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)

            return str(report_path)

        except Exception as e:
            print(f"创建报告失败: {e}")
            return None

    def create_markdown_report(self, content: str, report_name: str = None) -> Optional[str]:
        """创建 Markdown 报告文件。"""
        try:
            from datetime import datetime

            if report_name is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                report_name = f"report_{timestamp}.md"

            report_path = self.reports_dir / report_name
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(content)

            return str(report_path)
        except Exception as e:
            print(f"创建Markdown报告失败: {e}")
            return None

    def log_message(self, message: str, log_name: str = "app.log") -> bool:
        """
        记录日志消息
        :param message: 日志消息
        :param log_name: 日志文件名
        :return: 是否成功
        """
        try:
            from datetime import datetime

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] {message}"

            return set_log(log_entry, log_name=log_name, log_dir=self.logs_dir)

        except Exception as e:
            print(f"记录日志失败: {e}")
            return False
