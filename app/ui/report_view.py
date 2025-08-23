# app/ui/report_view.py
import os
from pathlib import Path
from typing import Optional, List, Dict

class ReportManager:
    """报告和日志管理器"""
    
    def __init__(self, reports_dir: str = "reports", logs_dir: str = "logs"):
        """
        初始化报告管理器
        :param reports_dir: 报告目录
        :param logs_dir: 日志目录
        """
        self.reports_dir = Path(reports_dir)
        self.logs_dir = Path(logs_dir)
        
        # 确保目录存在
        self.reports_dir.mkdir(exist_ok=True)
        self.logs_dir.mkdir(exist_ok=True)
    
    def download_report(self, report_name: str = None) -> Optional[str]:
        """
        下载报告
        :param report_name: 报告名称，如果为None则使用最新报告
        :return: 报告文件路径或None
        """
        try:
            if report_name is None:
                # 获取最新的报告文件
                report_files = list(self.reports_dir.glob("*.pdf")) + list(self.reports_dir.glob("*.html"))
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
            if log_name is None:
                # 获取最新的日志文件
                log_files = list(self.logs_dir.glob("*.log")) + list(self.logs_dir.glob("*.txt"))
                if not log_files:
                    return None
                
                # 按修改时间排序，获取最新的
                latest_log = max(log_files, key=lambda x: x.stat().st_mtime)
                log_name = latest_log.name
            
            log_path = self.logs_dir / log_name
            if log_path.exists():
                with open(log_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    # 返回最后max_lines行
                    return lines[-max_lines:] if len(lines) > max_lines else lines
            else:
                return None
                
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
            logs = []
            for log_file in self.logs_dir.glob("*"):
                if log_file.is_file():
                    stat = log_file.stat()
                    logs.append({
                        "name": log_file.name,
                        "size": f"{stat.st_size / 1024:.1f} KB",
                        "modified": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_mtime)),
                        "path": str(log_file)
                    })
            
            # 按修改时间排序
            logs.sort(key=lambda x: x["modified"], reverse=True)
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
    
    def log_message(self, message: str, log_name: str = "app.log") -> bool:
        """
        记录日志消息
        :param message: 日志消息
        :param log_name: 日志文件名
        :return: 是否成功
        """
        try:
            log_path = self.logs_dir / log_name
            
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] {message}\n"
            
            with open(log_path, 'a', encoding='utf-8') as f:
                f.write(log_entry)
            
            return True
            
        except Exception as e:
            print(f"记录日志失败: {e}")
            return False

# 导入time模块用于时间处理
import time
