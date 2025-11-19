# core/data_processing/dataset_loader.py
from scripts.ROOT_PATH import ROOT
from pathlib import Path
import shutil
from pefile import PE
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm
from core.utils.logger import set_log
from scripts.FILE_NAME import GET_TIME


RAW_PATH = [ROOT / "data" / "raw" / "benign",
            ROOT / "data" / "raw" / "malware"]

INVALID_PATH = ROOT / "data" / "quarantine" / "invalid"
INVALID_PATH.mkdir(parents=True, exist_ok=True)


def quick_check(path: Path) -> bool:
    """快速检查是否可能是 PE 文件"""
    try:
        with open(path, "rb") as f:
            mz = f.read(2)
            if mz != b"MZ":
                return False
            f.seek(0x3C)
            pe_offset = int.from_bytes(f.read(4), "little")
            f.seek(pe_offset)
            return f.read(4) == b"PE\0\0"
    except Exception:
        return False


def analyze_file(path: Path):
    """分析文件，返回 (path, type) 或 None"""
    if not quick_check(path):
        return None

    try:
        pe = PE(str(path), fast_load=True)
        characteristics = pe.FILE_HEADER.Characteristics
        if characteristics & 0x2000:
            ftype = "DLL"
        elif characteristics & 0x1000:
            ftype = "SYS"
        else:
            ftype = "EXE"
        return path, ftype
    except Exception:
        return None


def validate_dataset():
    all_files = [f for raw_dir in RAW_PATH for f in raw_dir.rglob("*") if f.is_file()]
    valid_files = []
    invalid_files = []

    with ProcessPoolExecutor() as executor:
        futures = {executor.submit(analyze_file, f): f for f in all_files}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Validating"):
            result = future.result()
            if result:
                valid_files.append(result)
            else:
                invalid_files.append(futures[future])

    # 批量移动无效文件
    for file in invalid_files:
        dest = INVALID_PATH / file.name
        try:
            shutil.move(str(file), dest)
        except Exception as e:
            set_log(GET_TIME(f"[ERROR] {file}: {e}"))

    return valid_files

