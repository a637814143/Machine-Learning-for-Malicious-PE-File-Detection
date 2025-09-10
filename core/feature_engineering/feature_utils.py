"""Utility helpers for feature extraction.

This module contains low level helpers used by the feature engineering
pipeline.  Functions here avoid any dependence on external datasets such as
EMBER so that all features are computed directly from the provided PE file.
"""

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


def stable_hash(value: str, modulo: int) -> int:
    """Return a stable hash of ``value`` in the range ``[0, modulo)``.

    Python's built-in ``hash`` is salted per process which makes it
    non-deterministic between runs.  Feature hashing therefore relies on a
    cryptographic hash (MD5) so that the same value is always mapped to the
    same index.

    Parameters
    ----------
    value:
        Input string to be hashed.
    modulo:
        Size of the target hash space.
    """

    digest = hashlib.md5(value.encode("utf-8", errors="ignore")).digest()
    return int.from_bytes(digest, byteorder="little") % modulo


def chunked_iterable(it: Iterable, size: int) -> Iterable[list]:
    """Yield lists of length ``size`` from ``it`` until exhausted."""

    chunk: list = []
    for item in it:
        chunk.append(item)
        if len(chunk) == size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk

