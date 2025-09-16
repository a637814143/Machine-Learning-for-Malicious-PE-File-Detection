# scripts/FILE_NAME.py

import inspect
from datetime import datetime
from pathlib import Path


def NAME_RULE() -> str:
    """
    获取调用者的名字，以便生成正确的日志和训练产物
    :return:
    """
    stack = inspect.stack()
    name = Path(stack[1].filename).stem
    time = datetime.now().strftime("%Y.%m.%d_%H.%M.%S")
    final_name = name + '~' + time

    return final_name


def GET_TIME(ori_str: str) -> str:
    """
    获取当前时间，生成带有时间戳的日志
    :return: 时间xxxx/xx/xx_xx:xx:xx
    """
    time = datetime.now().strftime("%Y/%m/%d %H:%M:%S")

    return time + ' ' + ori_str