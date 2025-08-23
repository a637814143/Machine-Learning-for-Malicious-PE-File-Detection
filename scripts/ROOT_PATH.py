from pathlib import Path


def ROOT_PATH(num: int = 1) -> Path:
    ROOT = Path(__file__).resolve().parents[num]
    return ROOT


ROOT = ROOT_PATH()
