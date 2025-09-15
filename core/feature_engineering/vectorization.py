"""Feature vectorisation utilities.

This module converts the raw feature dictionaries produced by
``static_features.extract_features`` into fixed-length numpy arrays using a
feature hashing scheme.  The resulting vectors have dimensionality greater
than the 2381 dimensions used in the original EMBER dataset to satisfy the
project requirements.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

import numpy as np

from .feature_utils import stable_hash


# Feature layout configuration -----------------------------------------------
BYTE_HIST_SIZE = 256
BYTE_ENTROPY_HIST_SIZE = 256
GENERAL_FEATURES = [
    "file_size",
    "virtual_size",
    "entrypoint",
    "num_sections",
    "num_imports",
    "num_exports",
    "num_resources",
    "has_signature",
    "has_debug",
    "overall_entropy",
]
HEADER_FEATURES = [
    "machine",
    "numberof_sections",
    "time_date_stamps",
    "pointerto_symbol_table",
    "numberof_symbols",
    "sizeof_optional_header",
    "characteristics",
]
OPTIONAL_HEADER_FEATURES = [
    "magic",
    "major_linker_version",
    "minor_linker_version",
    "size_of_code",
    "size_of_initialized_data",
    "size_of_uninitialized_data",
    "addressof_entrypoint",
    "base_of_code",
    "imagebase",
    "section_alignment",
    "file_alignment",
    "major_os_version",
    "minor_os_version",
    "major_image_version",
    "minor_image_version",
    "major_subsystem_version",
    "minor_subsystem_version",
    "win32_version_value",
    "sizeof_image",
    "sizeof_headers",
    "checksum",
    "subsystem",
    "dll_characteristics",
    "sizeof_stack_reserve",
    "sizeof_stack_commit",
    "sizeof_heap_reserve",
    "sizeof_heap_commit",
    "loader_flags",
    "numberof_rva_and_size",
]

DATA_DIRECTORY_SIZE = 32  # 16 directories * (rva, size)

# For up to 10 sections we store 5 numeric attributes per section
SECTION_COUNT = 10
SECTION_ATTRS = ["size", "virtual_size", "entropy", "characteristics", "pointerto_raw_data"]
SECTION_STATS_SIZE = SECTION_COUNT * len(SECTION_ATTRS)

SECTION_NAME_HASH_SIZE = 200
IMPORT_LIB_HASH_SIZE = 256
IMPORT_FUNC_HASH_SIZE = 1536
EXPORT_HASH_SIZE = 128
RESOURCE_HASH_SIZE = 256

VECTOR_SIZE = (
    BYTE_HIST_SIZE
    + BYTE_ENTROPY_HIST_SIZE
    + len(GENERAL_FEATURES)
    + len(HEADER_FEATURES)
    + len(OPTIONAL_HEADER_FEATURES)
    + DATA_DIRECTORY_SIZE
    + SECTION_STATS_SIZE
    + SECTION_NAME_HASH_SIZE
    + IMPORT_LIB_HASH_SIZE
    + IMPORT_FUNC_HASH_SIZE
    + EXPORT_HASH_SIZE
    + RESOURCE_HASH_SIZE
)


def _vectorize_entry(features: Dict[str, object]) -> np.ndarray:
    vec = np.zeros(VECTOR_SIZE, dtype=np.float32)
    offset = 0

    # Byte histograms --------------------------------------------------
    vec[offset : offset + BYTE_HIST_SIZE] = np.array(features.get("byte_hist", []), dtype=np.float32)[
        :BYTE_HIST_SIZE
    ]
    offset += BYTE_HIST_SIZE
    vec[offset : offset + BYTE_ENTROPY_HIST_SIZE] = np.array(
        features.get("byte_entropy_hist", []), dtype=np.float32
    )[:BYTE_ENTROPY_HIST_SIZE]
    offset += BYTE_ENTROPY_HIST_SIZE

    # General ----------------------------------------------------------
    general = features.get("general", {})
    for i, name in enumerate(GENERAL_FEATURES):
        vec[offset + i] = float(general.get(name, 0))
    offset += len(GENERAL_FEATURES)

    # Header -----------------------------------------------------------
    header = features.get("header", {})
    for i, name in enumerate(HEADER_FEATURES):
        vec[offset + i] = float(header.get(name, 0))
    offset += len(HEADER_FEATURES)

    # Optional header --------------------------------------------------
    opt = features.get("optional_header", {})
    for i, name in enumerate(OPTIONAL_HEADER_FEATURES):
        vec[offset + i] = float(opt.get(name, 0))
    offset += len(OPTIONAL_HEADER_FEATURES)

    # Data directories -------------------------------------------------
    data_dirs = features.get("data_directories", [])
    for i in range(16):
        if i < len(data_dirs):
            entry = data_dirs[i]
            vec[offset + i * 2] = float(entry.get("rva", 0))
            vec[offset + i * 2 + 1] = float(entry.get("size", 0))
    offset += DATA_DIRECTORY_SIZE

    # Section statistics -----------------------------------------------
    sections = features.get("sections", [])
    for i in range(SECTION_COUNT):
        if i < len(sections):
            sec = sections[i]
            base = offset + i * len(SECTION_ATTRS)
            for j, attr in enumerate(SECTION_ATTRS):
                vec[base + j] = float(sec.get(attr, 0))
    offset += SECTION_STATS_SIZE

    # Section name hashing ---------------------------------------------
    for sec in sections:
        idx = stable_hash(sec.get("name", ""), SECTION_NAME_HASH_SIZE)
        vec[offset + idx] += 1.0
    offset += SECTION_NAME_HASH_SIZE

    # Import libraries hashing ----------------------------------------
    imports = features.get("imports", {})
    for lib in imports.get("libraries", []):
        idx = stable_hash(lib, IMPORT_LIB_HASH_SIZE)
        vec[offset + idx] += 1.0
    offset += IMPORT_LIB_HASH_SIZE

    # Import functions hashing ----------------------------------------
    for func in imports.get("functions", []):
        idx = stable_hash(func, IMPORT_FUNC_HASH_SIZE)
        vec[offset + idx] += 1.0
    offset += IMPORT_FUNC_HASH_SIZE

    # Exported functions hashing --------------------------------------
    for func in features.get("exports", {}).get("functions", []):
        idx = stable_hash(func, EXPORT_HASH_SIZE)
        vec[offset + idx] += 1.0
    offset += EXPORT_HASH_SIZE

    # Resources hashing ------------------------------------------------
    for res in features.get("resources", []):
        idx = stable_hash(res, RESOURCE_HASH_SIZE)
        vec[offset + idx] += 1.0

    return vec


def vectorize_feature_file(
    json_path: str,
    save_path: str,
    progress_callback=None,
    text_callback=None,
    max_workers: int = None,
) -> None:
    """Vectorise features stored in ``json_path`` and save to ``save_path``.

    ``json_path`` should contain one JSON object per line with a ``features``
    field as produced by :func:`static_features.extract_from_directory`.
    ``save_path`` will be written in NumPy ``.npy`` format containing an
    array of shape ``(num_files, VECTOR_SIZE)``.
    """
    print(save_path)
    file_path = Path(json_path)
    lines = file_path.read_text(encoding="utf-8").splitlines()

    total = len(lines)
    if progress_callback is None:
        progress_callback = lambda x: None
    if text_callback is None:
        text_callback = lambda x: None

    # 确定线程数
    if max_workers is None:
        import os
        cpu_count = os.cpu_count() or 4
        max_workers = min(total, cpu_count, 8)
    
    text_callback(f"开始向量化 {total} 个特征，使用 {max_workers} 个线程")
    
    def process_line(line_data):
        """处理单行数据的向量化"""
        idx, line = line_data
        record = json.loads(line)
        features = record.get("features", {})
        
        try:
            vec = _vectorize_entry(features)
            return idx, vec, record.get('path', f'line_{idx}'), True, None
        except Exception as e:
            return idx, None, record.get('path', f'line_{idx}'), False, str(e)
    
    # 准备数据
    line_data = [(i, line) for i, line in enumerate(lines)]
    
    # 使用线程池并行处理
    vectors = [None] * total  # 预分配数组以保持顺序
    successful = 0
    failed = 0
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务
        future_to_idx = {
            executor.submit(process_line, data): data[0] 
            for data in line_data
        }
        
        # 收集结果
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                result_idx, vec, path, success, error = future.result()
                
                if success:
                    vectors[result_idx] = vec
                    successful += 1
                    text_callback(f"已转换 {path}")
                else:
                    vectors[result_idx] = np.zeros(VECTOR_SIZE, dtype=np.float32)
                    failed += 1
                    text_callback(f"转换失败 {path}: {error}")
                
                # 更新进度
                progress_callback(int((successful + failed) / total * 100))
                
            except Exception as e:
                vectors[idx] = np.zeros(VECTOR_SIZE, dtype=np.float32)
                failed += 1
                text_callback(f"处理异常 line_{idx}: {str(e)}")
                progress_callback(int((successful + failed) / total * 100))

    # 移除None值并转换为numpy数组
    vectors = [v for v in vectors if v is not None]
    array = np.vstack(vectors) if vectors else np.empty((0, VECTOR_SIZE), dtype=np.float32)
    np.save(save_path, array)
    
    text_callback(f"向量化完成: 成功 {successful} 个，失败 {failed} 个")