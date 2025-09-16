"""Feature vectorisation utilities.

This module converts the raw feature dictionaries produced by
``static_features.extract_features`` into fixed-length numpy arrays using a
feature hashing scheme.  The resulting vectors have dimensionality greater
than the 2381 dimensions used in the original EMBER dataset to satisfy the
project requirements.
"""

from __future__ import annotations

import json
from typing import Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from pathlib import Path

import numpy as np

from scripts.FILE_NAME import NAME_RULE

from .feature_utils import stable_hash


class ThreadSafeVectorWriter:
    """线程安全的向量实时写入器"""
    
    def __init__(self, save_path: str, vector_size: int, text_callback=None):
        self.save_path = save_path
        self.vector_size = vector_size
        self.text_callback = text_callback or (lambda x: None)
        self.lock = threading.Lock()
        self.vectors = []
        self.written_count = 0
        
    def add_vector(self, vector: np.ndarray, index: int, path: str = ""):
        """添加向量到缓存"""
        with self.lock:
            self.vectors.append((index, vector, path))
            self.written_count += 1
            if path:
                self.text_callback(f"已缓存向量 {self.written_count}: {Path(path).name}")
    
    def write_to_file(self):
        """将所有向量写入文件"""
        with self.lock:
            if not self.vectors:
                self.text_callback("没有向量需要写入")
                return
            
            # 按索引排序
            self.vectors.sort(key=lambda x: x[0])
            
            # 提取向量并组合成数组
            vectors_only = [vec for _, vec, _ in self.vectors]
            array = np.vstack(vectors_only) if vectors_only else np.empty((0, self.vector_size), dtype=np.float32)
            
            # 写入文件
            np.save(self.save_path, array)
            self.text_callback(f"向量化完成，共写入 {len(vectors_only)} 个向量到 {self.save_path}")
    
    def get_written_count(self):
        """获取已写入的数量"""
        with self.lock:
            return self.written_count


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


def _prepare_output_path(target: Path) -> Path:
    """Return the final file path for saving vectorised features."""

    if target.suffix.lower() == ".npy":
        target.parent.mkdir(parents=True, exist_ok=True)
        return target

    if target.exists() and target.is_file():
        resolved = target.with_suffix(".npy")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        return resolved

    target.mkdir(parents=True, exist_ok=True)
    return target / f"{NAME_RULE()}.npy"


def vectorize_feature_file(
    json_path: str,
    save_path: str,
    progress_callback=None,
    text_callback=None,
    max_workers: int = None,
    realtime_write: bool = True,
) -> Path:
    """Vectorise features stored in ``json_path`` and save to ``save_path``.

    ``json_path`` should contain one JSON object per line with a ``features``
    field as produced by :func:`static_features.extract_from_directory`.
    ``save_path`` may point to a directory or to a target ``.npy`` file.  The
    returned :class:`pathlib.Path` specifies the actual file written to disk.
    """

    file_path = Path(json_path)
    if not file_path.exists():
        raise FileNotFoundError(f"特征文件不存在: {json_path}")

    output_path = _prepare_output_path(Path(save_path))

    if progress_callback is None:
        progress_callback = lambda x: None
    if text_callback is None:
        text_callback = lambda x: None

    text_callback(f"读取特征文件: {file_path}")
    text_callback(f"向量结果将保存至: {output_path}")

    lines = file_path.read_text(encoding="utf-8").splitlines()
    total = len(lines)

    if total == 0:
        text_callback("特征文件为空，已生成空向量数组")
        np.save(output_path, np.empty((0, VECTOR_SIZE), dtype=np.float32))
        progress_callback(100)
        return output_path

    # 确定线程数
    if max_workers is None:
        import os

        cpu_count = os.cpu_count() or 4
        max_workers = min(total, cpu_count, 12)

    write_mode = "实时写入" if realtime_write else "批量写入"
    text_callback(f"开始向量化 {total} 个特征，使用 {max_workers} 个线程，{write_mode}模式")
    
    def process_line(line_data, vector_writer=None):
        """处理单行数据的向量化"""
        idx, line = line_data
        record = json.loads(line)
        features = record.get("features", {})
        path = record.get('path', f'line_{idx}')
        
        try:
            vec = _vectorize_entry(features)
            
            # 实时写入向量
            if vector_writer:
                vector_writer.add_vector(vec, idx, path)
            
            return idx, vec, path, True, None
        except Exception as e:
            # 失败时也写入零向量
            if vector_writer:
                zero_vec = np.zeros(VECTOR_SIZE, dtype=np.float32)
                vector_writer.add_vector(zero_vec, idx, path)
            
            return idx, None, path, False, str(e)
    
    # 创建实时向量写入器
    vector_writer = None
    if realtime_write:
        vector_writer = ThreadSafeVectorWriter(str(output_path), VECTOR_SIZE, text_callback)
    
    # 准备数据
    line_data = [(i, line) for i, line in enumerate(lines)]
    
    # 使用线程池并行处理
    vectors = [None] * total if not realtime_write else None  # 批量模式才需要预分配
    successful = 0
    failed = 0
    
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有任务
            future_to_idx = {
                executor.submit(process_line, data, vector_writer): data[0] 
                for data in line_data
            }
            
            # 收集结果
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    result_idx, vec, path, success, error = future.result()
                    
                    if success:
                        if not realtime_write:
                            vectors[result_idx] = vec
                        successful += 1
                        text_callback(f"已转换 {path}")
                    else:
                        if not realtime_write:
                            vectors[result_idx] = np.zeros(VECTOR_SIZE, dtype=np.float32)
                        failed += 1
                        text_callback(f"转换失败 {path}: {error}")
                    
                    # 更新进度
                    progress_callback(int((successful + failed) / total * 100))
                    
                except Exception as e:
                    if not realtime_write:
                        vectors[idx] = np.zeros(VECTOR_SIZE, dtype=np.float32)
                    failed += 1
                    text_callback(f"处理异常 line_{idx}: {str(e)}")
                    progress_callback(int((successful + failed) / total * 100))

        # 如果不是实时写入模式，需要批量写入
        if not realtime_write:
            text_callback("开始批量写入向量...")
            # 移除None值并转换为numpy数组
            vectors = [v for v in vectors if v is not None]
            array = np.vstack(vectors) if vectors else np.empty((0, VECTOR_SIZE), dtype=np.float32)
            np.save(output_path, array)
        else:
            # 实时写入模式，将所有向量写入文件
            vector_writer.write_to_file()

        text_callback(f"向量化完成: 成功 {successful} 个，失败 {failed} 个")
        progress_callback(100)
        return output_path

    except Exception as e:
        text_callback(f"向量化过程异常: {str(e)}")
        raise
