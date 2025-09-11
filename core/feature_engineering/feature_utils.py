"""Utility helpers for feature extraction and transformation."""

from __future__ import annotations

import hashlib
import math
from typing import Iterable

import numpy as np


def ByteHistogram(pe_path: str, is_normalize: bool = False) -> np.ndarray:
    """
    统计每个字节值出现次数，对于是否归一化可以调整参数，默认不归一化
    :param pe_path: PE文件路径
    :param is_normalize: 是否归一化
    :return: numpy.ndarray长度256
    """
    histogram = np.zeros(256, dtype=np.float32)
    with open(pe_path, 'rb') as file:
        data = file.read()

    for byte in data:
        histogram[byte] += 1

    if is_normalize and len(data):
        histogram /= len(data)

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