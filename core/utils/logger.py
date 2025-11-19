# core/utils/logger.py

from pathlib import Path
from scripts.ROOT_PATH import ROOT


LOG_PATH = ROOT / "docs" / "log.txt"


def set_log(log_info: str) -> bool:
    """
    写入日志
    :param file_path: 日志存储位置，类型为pathlib.Path
    :param log_info: 日志写入的内容，类型为字符串
    :return: 返回值为布尔类型
    """
    with open(LOG_PATH, 'a+') as file:
        file.write(log_info + '\n')

    return True


