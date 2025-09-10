"""High level feature extraction and vectorisation for PE files.

This module exposes two main entry points used by the UI tasks:

``extract_features_from_dir``
    Walk a directory of PE files and extract raw (non-vectorised) features to a
    JSON-lines file.

``vectorize_features``
    Convert the JSON-lines feature representation into fixed length numeric
    vectors using feature hashing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Callable

import numpy as np

try:  # ``pefile`` may not be installed during tests
    import pefile
except Exception:  # pragma: no cover
    pefile = None

from .feature_utils import ByteEntropyHistogram, ByteHistogram, chunked_iterable, stable_hash
from .semantic_features import get_string_features
from .static_features import (
    get_data_directories,
    get_exports,
    get_general_features,
    get_imports,
    get_section_features,
)


FEATURE_DIM = 2858  # total dimension of the vectorised feature space


def extract_pe_features(pe_path: Path) -> Dict[str, Any]:
    """Extract non-vectorised features from a single PE file."""

    if pefile is None:
        raise RuntimeError("pefile library not available")

    with open(pe_path, "rb") as f:
        data = f.read()

    pe = pefile.PE(data=data)
    general = get_general_features(pe, len(data))
    directories = get_data_directories(pe)
    sections = get_section_features(pe)
    imports = get_imports(pe)
    exports = get_exports(pe)
    strings = get_string_features(pe_path)
    byte_hist = ByteHistogram(str(pe_path), is_normalize=True).tolist()
    byte_entropy_hist = ByteEntropyHistogram(str(pe_path)).tolist()

    return {
        "metadata": {"name": pe_path.name},
        "general": general,
        "datadirectories": directories,
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "strings": strings,
        "byte_hist": byte_hist,
        "byte_entropy_hist": byte_entropy_hist,
    }


def extract_features_from_dir(
    input_dir: str,
    save_path: str,
    progress_callback: Callable[[int], None] | None = None,
    text_callback: Callable[[str], None] | None = None,
) -> None:
    """Extract features for all PE files in ``input_dir`` and save to JSON lines."""

    progress_callback = progress_callback or (lambda v: None)
    text_callback = text_callback or (lambda s: None)

    paths = [p for p in Path(input_dir).glob("**/*") if p.is_file()]
    total = len(paths) or 1

    with open(save_path, "w", encoding="utf-8") as out:
        for idx, path in enumerate(paths, 1):
            try:
                feats = extract_pe_features(path)
                out.write(json.dumps(feats) + "\n")
                text_callback(f"提取 {path.name} 成功")
            except Exception as exc:  # pragma: no cover - runtime errors
                text_callback(f"提取 {path.name} 失败: {exc}")
            progress_callback(int(idx / total * 100))


def _vectorize_single(feats: Dict[str, Any]) -> np.ndarray:
    """Convert a single feature dictionary to a numeric vector."""

    vec = np.zeros(FEATURE_DIM, dtype=np.float32)
    offset = 0

    # 1. general features (10)
    general_order = [
        "size",
        "vsize",
        "entry",
        "code_size",
        "init_data_size",
        "uninit_data_size",
        "image_base",
        "section_align",
        "file_align",
        "num_sections",
    ]
    general_values = [feats["general"].get(k, 0) for k in general_order]
    vec[offset : offset + len(general_values)] = general_values
    offset += len(general_values)

    # 2. data directories (32)
    dd = feats.get("datadirectories", [])
    vec[offset : offset + 32] = dd[:32]
    offset += 32

    # 3. byte histogram (256)
    bh = feats.get("byte_hist", [])
    vec[offset : offset + 256] = bh[:256]
    offset += 256

    # 4. byte entropy histogram (256)
    beh = feats.get("byte_entropy_hist", [])
    vec[offset : offset + 256] = beh[:256]
    offset += 256

    # 5. section features hashed (512 -> 256 for size + 256 for entropy)
    for section in feats.get("sections", []):
        name = section.get("name", "")
        h = stable_hash(name, 256)
        vec[offset + h] += section.get("size", 0)
        vec[offset + 256 + h] += section.get("entropy", 0.0)
    offset += 512

    # 6. imported libraries hashed (256)
    for lib in feats.get("imports", {}).get("libraries", []):
        vec[offset + stable_hash(lib, 256)] += 1.0
    offset += 256

    # 7. imported functions hashed (1024)
    for func in feats.get("imports", {}).get("functions", []):
        vec[offset + stable_hash(func, 1024)] += 1.0
    offset += 1024

    # 8. exported functions hashed (256)
    for func in feats.get("exports", []):
        vec[offset + stable_hash(func, 256)] += 1.0
    offset += 256

    # 9. strings hashed (256)
    for s in feats.get("strings", []):
        vec[offset + stable_hash(s, 256)] += 1.0
    # offset += 256  # final value not used further

    return vec


def vectorize_features(
    feature_path: str,
    save_path: str,
    progress_callback: Callable[[int], None] | None = None,
    text_callback: Callable[[str], None] | None = None,
) -> None:
    """Vectorise features stored in ``feature_path`` and save as ``.npy``."""

    progress_callback = progress_callback or (lambda v: None)
    text_callback = text_callback or (lambda s: None)

    with open(feature_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    total = len(lines) or 1
    vectors: List[np.ndarray] = []
    for idx, line in enumerate(lines, 1):
        feats = json.loads(line)
        vectors.append(_vectorize_single(feats))
        progress_callback(int(idx / total * 100))

    array = np.vstack(vectors)
    np.save(save_path, array)
    text_callback(f"保存向量到 {save_path}")

