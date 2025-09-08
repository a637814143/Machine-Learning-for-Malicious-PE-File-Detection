from pathlib import Path


def ROOT_PATH(num: int = 1) -> Path:
    """
    获取项目根目录
    :param num:
    :return: pathlib.Path
    """
    ROOT = Path(__file__).resolve().parents[num]
    return ROOT


ROOT = ROOT_PATH()
