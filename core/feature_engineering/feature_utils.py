"""Utility helpers for feature extraction and transformation."""

from __future__ import annotations
import hashlib
from typing import Iterable, Dict, List
from pathlib import Path
import re
import mmap
import numpy as np
from .pe_parser import parse_pe

# 可打印字符ASCII值
PRINTABLE_MIN = 0x20
PRINTABLE_MAX = 0x7E
PRINTABLE_RANGE = PRINTABLE_MAX - PRINTABLE_MIN + 1

# 正则表达式匹配
RE_PRINTABLE = re.compile(rb'[\x20-\x7e]{4,}')
RE_URL = re.compile(
    rb'(?:'
    rb'(?:https?|ftp)://[^\s/$.?#].[^\s]*'
    rb'|'
    rb'www\.[^\s/]+[^\s]*'
    rb'|'
    rb'[A-Za-z0-9.-]+\.(?:com|net|org|edu|gov|mil|info|io|biz|cn|ru|uk|de|jp|fr|au|br|it|nl|es)[^\s]*'
    rb')',
    flags=re.IGNORECASE
)
RE_WIN_PATH = re.compile(
    rb'(?:'
    rb'[A-Za-z]:\\(?:[^\\\r\n<>:"/|?*]+\\)*[^\\\r\n<>:"/|?*]*'
    rb'|'
    rb'\\\\[^\s\\/:*?"<>|]+\\[^\s\\/:*?"<>|]+'
    rb')'
)
RE_REG = re.compile(
    rb'(?:HKEY_(?:CLASSES_ROOT|CURRENT_USER|LOCAL_MACHINE|USERS|CURRENT_CONFIG)\\[^\r\n\"\'\t]+)',
    flags=re.IGNORECASE
)
RE_MZ = re.compile(rb'MZ')


def Hash_md5(file_path: str, size: int = 4 * 1024 * 1024) -> str:
    """
    分块取md5
    :param file_path:
    :param size:
    :return:
    """
    md5 = hashlib.md5()
    with open(file_path, 'rb') as file:
        while chunk := file.read(size):
            md5.update(chunk)

    return md5.hexdigest()


def Hash_sha256(file_path: str, size: int = 4 * 1024 * 1024) -> str:
    """
    分块取sha-256
    :param file_path:
    :param size:
    :return:
    """
    sha = hashlib.sha256()
    with open(file_path, 'rb') as file:
        while chunk := file.read(size):
            sha.update(chunk)

    return sha.hexdigest()


def Appeared() -> str:
    return ""


def Label(file_path: str) -> int:
    """
    打标签
    :param file_path:
    :return:
    """
    label = 1 if 'malware' in file_path else 0

    return label


def Avclass(file_path: str) -> str:
    """
    恶意类型，我不知道怎么实现
    :param file_path:
    :return:
    """
    return "unknown" if 'malware' in file_path else ""


def ByteHistogram(pe_path: str, is_normalize: bool = False) -> np.ndarray:
    """
    字节直方图
    :param pe_path: pe文件路径
    :param is_normalize: 是否归一化，默认不归一化
    :return: 返回值numpy数组
    """
    with open(pe_path, 'rb') as f:
        data = f.read()

    arr = np.frombuffer(data, dtype=np.uint8)
    histogram = np.bincount(arr, minlength=256).astype(np.float32)

    if is_normalize and arr.size > 0:
        histogram /= arr.size

    return histogram


def ByteEntropyHistogram(pe_path: str, window_size: int = 2048) -> np.ndarray:
    """
    提取Byte-Entropy Histogtam特征
    :param pe_path: PE文件路径
    :param window_size: 滑动窗口大小（默认2048B）
    :return:
    """
    shape = (16, 16)
    histogram = np.zeros(shape, dtype=np.float32)
    with open(pe_path, 'rb') as file:
        data = file.read()

    length = len(data)
    if length < window_size:
        return histogram.flatten()

    data = np.frombuffer(data, dtype=np.uint8)

    step = window_size // 2
    for i in range(0, length - window_size + 1, step):
        window = data[i:i + window_size]
        if not window.size:
            continue
        # 获取平均字节值
        argv_byte = sum(window) / len(window)
        byte_bin = min(int(argv_byte / 16), 15)
        # 计算信息熵
        counts = np.bincount(window, minlength=256)
        probs = counts[counts > 0] / float(len(window))
        entropy = -np.sum(probs * np.log2(probs))
        entropy_bin = min(int(entropy * 2), 15)

        histogram[byte_bin, entropy_bin] += 1

    return histogram.flatten()


def Strings(file_path) -> Dict:
    """
    字符串信息
    :param file_path:
    :return:
    """

    def _entropy_from_counts(counts: np.ndarray) -> float:
        """Shannon 熵（基于可打印字符分布）。"""
        total = counts.sum()
        if total == 0:
            return 0.0
        p = counts[counts > 0] / total
        return float(-(p * np.log2(p)).sum())

    # 统计容器
    printable_counts = np.zeros(PRINTABLE_RANGE, dtype=np.int64)
    numstrings = 0
    total_len = 0
    urls = paths = registry = mz = 0

    p = Path(file_path)
    with open(p, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        data = mm[:]
        mz = len(RE_MZ.findall(data))
        for m in RE_PRINTABLE.finditer(data):
            s = m.group(0)
            L = len(s)
            numstrings += 1
            total_len += L

            arr = np.frombuffer(s, dtype=np.uint8)
            mask = (arr >= PRINTABLE_MIN) & (arr <= PRINTABLE_MAX)
            if mask.any():
                vals = arr[mask] - PRINTABLE_MIN
                printable_counts += np.bincount(vals, minlength=PRINTABLE_RANGE)

        urls = len(RE_URL.findall(data))
        paths = len(RE_WIN_PATH.findall(data))
        registry = len(RE_REG.findall(data))

        mm.close()

    printables = int(printable_counts.sum())
    avlength = float(total_len / numstrings) if numstrings else 0.0
    entropy = _entropy_from_counts(printable_counts)

    return {
        "numstrings": int(numstrings),
        "avlength": float(avlength),
        "printabledist": printable_counts.tolist(),
        "printables": int(printables),
        "entropy": float(entropy),
        "paths": int(paths),
        "urls": int(urls),
        "registry": int(registry),
        "MZ": int(mz),
    }


def General(path: str) -> Dict:
    """
    使用 LIEF(0.16.6) + 你提供的 parse_pe 提取 EMBER 风格 general 字段。
    返回:
      {
        "size": int, "vsize": int,
        "has_debug": int, "exports": int, "imports": int,
        "has_relocations": int, "has_resources": int,
        "has_signature": int, "has_tls": int, "symbols": int
      }
    """
    p = Path(path)
    size = p.stat().st_size if p.exists() else 0

    out = {
        "size": int(size),
        "vsize": 0,
        "has_debug": 0,
        "exports": 0,
        "imports": 0,
        "has_relocations": 0,
        "has_resources": 0,
        "has_signature": 0,
        "has_tls": 0,
        "symbols": 0,
    }

    bin = parse_pe(path)
    if bin is None:
        return out  # 非PE/解析失败，按 EMBER 风格返回默认值

    # vsize (SizeOfImage)
    try:
        out["vsize"] = int(getattr(bin.optional_header, "sizeof_image", 0))
    except Exception:
        pass

    # has_debug
    try:
        dbg_list = getattr(bin, "debug", None)  # List[lief.PE.Debug]
        out["has_debug"] = int(bool(dbg_list))  # 非空即 1
    except Exception:
        pass

    # exports: 导出函数数量
    try:
        if getattr(bin, "has_exports", False):
            exp = bin.get_export()  # lief.PE.Export
            entries = getattr(exp, "entries", []) if exp is not None else []
            out["exports"] = int(len(entries))
    except Exception:
        pass

    # imports: 导入函数总数（所有 DLL 的 entries 合计）
    try:
        total = 0
        for lib in getattr(bin, "imports", []):   # List[lief.PE.Import]
            total += len(getattr(lib, "entries", []))
        out["imports"] = int(total)
    except Exception:
        pass

    # has_relocations
    try:
        relocs = getattr(bin, "relocations", None)
        out["has_relocations"] = int(bool(relocs))
    except Exception:
        pass

    # has_resources
    try:
        out["has_resources"] = int(
            getattr(bin, "has_resources", False) or getattr(bin, "resources", None) is not None
        )
    except Exception:
        pass

    # has_signature (Authenticode)
    try:
        sigs = getattr(bin, "signatures", None)  # List[lief.PE.Signature]
        out["has_signature"] = int(bool(sigs))
    except Exception:
        pass

    # has_tls
    try:
        out["has_tls"] = int(getattr(bin, "has_tls", False) or getattr(bin, "tls", None) is not None)
    except Exception:
        pass

    # symbols: COFF 符号表条目数
    try:
        out["symbols"] = int(getattr(bin.header, "numberof_symbols", 0))
    except Exception:
        pass

    return out


def stable_hash(value: str, n_buckets: int) -> int:
    """Compute a stable hash for ``value`` within ``n_buckets``.

    Python's builtin ``hash`` is salted per-process which would result in
    inconsistent feature indices between runs.  For feature hashing we rely on
    a deterministic hash derived from SHA-256.

    Parameters
    ----------
    value:
        Input string to hash.
    n_buckets:
        Size of the hashing space.

    Returns
    -------
    int
        Integer in the range ``[0, n_buckets)``.
    """

    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "little") % n_buckets


def shannon_entropy(data: Iterable[int]) -> float:
    """Compute Shannon entropy of an iterable of byte values."""
    if not data:
        return 0.0
    counts = np.bincount(list(data), minlength=256)
    probs = counts[counts > 0] / float(len(data))
    return float(-np.sum(probs * np.log2(probs)))
