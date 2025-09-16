# core/utils/logger.py

from pathlib import Path
from scripts.ROOT_PATH import ROOT
from scripts.FILE_NAME import GET_TIME

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


def LOG(info: str, level: int = 0) -> None:
    """
    省几个字符，懒得加GET_TIME()
    :param level: 日志等级这一块
    :param info: 日志信息这一块
    :return: 啥也不返回这一块
    """
    level_list = ['INFO', 'WARING', 'ERROR']
    info = level_list[level] + info
    with open(LOG_PATH, 'a+') as file:
        file.write(GET_TIME(info) + '\n')
