import os
from ROOT_PATH import ROOT


def INSTALL() -> None:
    path = ROOT / "requirements.txt"
    cmd = f'pip install -r {path}'
    os.system(cmd)


