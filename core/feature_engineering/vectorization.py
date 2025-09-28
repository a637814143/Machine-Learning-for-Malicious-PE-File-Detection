"""Feature vectorisation utilities.

This module mirrors the behaviour of the original EMBER feature pipeline and
converts the raw feature dictionaries produced by
``static_features.extract_features`` into 2381-dimensional NumPy arrays.  The
implementation follows ``ember.features.PEFeatureExtractor.process_raw_features``
so that downstream models obtain feature vectors identical to those generated
by EMBER.
"""

from __future__ import annotations

import json
from typing import Dict, Iterable, List, Sequence, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from pathlib import Path

import numpy as np
from scripts.FILE_NAME import NAME_RULE

from sklearn.feature_extraction import FeatureHasher


class ThreadSafeVectorWriter:
    """线程安全的向量实时写入器"""

    def __init__(self, save_path: str, vector_size: int, text_callback=None):
        self.save_path = save_path
        self.vector_size = vector_size
        self.text_callback = text_callback or (lambda x: None)
        self.lock = threading.Lock()
        self.vectors = []
        self.written_count = 0

    def add_vector(
        self,
        vector: np.ndarray,
        index: int,
        label: int,
        path: str = "",
    ):
        """添加向量到缓存"""
        with self.lock:
            self.vectors.append((index, vector, label, path))
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

            # 提取向量、标签
            vectors_only = [vec for _, vec, _, _ in self.vectors]
            labels_only = [label for _, _, label, _ in self.vectors]

            features_array = (
                np.vstack(vectors_only)
                if vectors_only
                else np.empty((0, self.vector_size), dtype=np.float32)
            )
            labels_array = (
                np.asarray(labels_only, dtype=np.int64)
                if labels_only
                else np.empty((0,), dtype=np.int64)
            )

            # 写入文件，保持特征和标签对应
            np.save(self.save_path, {"x": features_array, "y": labels_array})
            self.text_callback(
                f"向量化完成，共写入 {len(vectors_only)} 个向量到 {self.save_path}"
            )

    def get_written_count(self):
        """获取已写入的数量"""
        with self.lock:
            return self.written_count


# Feature layout configuration -----------------------------------------------
BYTE_HIST_SIZE = 256
BYTE_ENTROPY_HIST_SIZE = 256

STRING_LEADING_FIELDS = ["numstrings", "avlength", "printables"]
PRINTABLE_DIST_SIZE = 96  # printable ASCII characters (0x20 - 0x7f)
STRING_TRAILING_FIELDS = ["entropy", "paths", "urls", "registry", "MZ"]

FEATURE_BLOCK_KEYS = {
    "histogram",
    "byteentropy",
    "strings",
    "general",
    "header",
    "section",
    "imports",
    "exports",
    "datadirectories",
}

GENERAL_FEATURES = [
    "size",
    "vsize",
    "has_debug",
    "exports",
    "imports",
    "has_relocations",
    "has_resources",
    "has_signature",
    "has_tls",
    "symbols",
]

HEADER_TIMESTAMP_SIZE = 1
HEADER_MACHINE_HASH_SIZE = 10
HEADER_CHARACTERISTICS_HASH_SIZE = 10
OPTIONAL_SUBSYSTEM_HASH_SIZE = 10
OPTIONAL_DLL_CHARACTERISTICS_HASH_SIZE = 10
OPTIONAL_MAGIC_HASH_SIZE = 10

OPTIONAL_NUMERIC_FEATURES = [
    "major_image_version",
    "minor_image_version",
    "major_linker_version",
    "minor_linker_version",
    "major_operating_system_version",
    "minor_operating_system_version",
    "major_subsystem_version",
    "minor_subsystem_version",
    "sizeof_code",
    "sizeof_headers",
    "sizeof_heap_commit",
]

DATA_DIRECTORY_COUNT = 15
DATA_DIRECTORY_SIZE = DATA_DIRECTORY_COUNT * 2

SECTION_GENERAL_SIZE = 5
SECTION_HASH_SIZE = 50
SECTION_VECTOR_SIZE = SECTION_GENERAL_SIZE + SECTION_HASH_SIZE * 5

IMPORT_LIB_HASH_SIZE = 256
IMPORT_FUNC_HASH_SIZE = 1024
EXPORT_HASH_SIZE = 128

VECTOR_SIZE = (
    BYTE_HIST_SIZE
    + BYTE_ENTROPY_HIST_SIZE
    + len(STRING_LEADING_FIELDS)
    + PRINTABLE_DIST_SIZE
    + len(STRING_TRAILING_FIELDS)
    + len(GENERAL_FEATURES)
    + HEADER_TIMESTAMP_SIZE
    + HEADER_MACHINE_HASH_SIZE
    + HEADER_CHARACTERISTICS_HASH_SIZE
    + OPTIONAL_SUBSYSTEM_HASH_SIZE
    + OPTIONAL_DLL_CHARACTERISTICS_HASH_SIZE
    + OPTIONAL_MAGIC_HASH_SIZE
    + len(OPTIONAL_NUMERIC_FEATURES)
    + DATA_DIRECTORY_SIZE
    + SECTION_VECTOR_SIZE
    + IMPORT_LIB_HASH_SIZE
    + IMPORT_FUNC_HASH_SIZE
    + EXPORT_HASH_SIZE
)


_MACHINE_HASHER = FeatureHasher(HEADER_MACHINE_HASH_SIZE, input_type="string")
_CHARACTERISTICS_HASHER = FeatureHasher(HEADER_CHARACTERISTICS_HASH_SIZE, input_type="string")
_SUBSYSTEM_HASHER = FeatureHasher(OPTIONAL_SUBSYSTEM_HASH_SIZE, input_type="string")
_DLL_CHARACTERISTICS_HASHER = FeatureHasher(OPTIONAL_DLL_CHARACTERISTICS_HASH_SIZE, input_type="string")
_MAGIC_HASHER = FeatureHasher(OPTIONAL_MAGIC_HASH_SIZE, input_type="string")

_SECTION_SIZE_HASHER = FeatureHasher(SECTION_HASH_SIZE, input_type="pair")
_SECTION_ENTROPY_HASHER = FeatureHasher(SECTION_HASH_SIZE, input_type="pair")
_SECTION_VSIZE_HASHER = FeatureHasher(SECTION_HASH_SIZE, input_type="pair")
_SECTION_ENTRY_HASHER = FeatureHasher(SECTION_HASH_SIZE, input_type="string")
_SECTION_CHARACTERISTICS_HASHER = FeatureHasher(SECTION_HASH_SIZE, input_type="string")

_IMPORT_LIBRARY_HASHER = FeatureHasher(IMPORT_LIB_HASH_SIZE, input_type="string")
_IMPORT_FUNCTION_HASHER = FeatureHasher(IMPORT_FUNC_HASH_SIZE, input_type="string")
_EXPORT_HASHER = FeatureHasher(EXPORT_HASH_SIZE, input_type="string")


def _normalise_histogram(values: Sequence[float] | np.ndarray | None, size: int) -> np.ndarray:
    array = np.zeros(size, dtype=np.float32)
    if values is None:
        return array

    data = np.asarray(values, dtype=np.float32)
    if data.size == 0:
        return array

    data = data[:size]
    total = data.sum()
    if total > 0:
        data = data / total
    array[: data.size] = data
    return array


def _hash_single_string(hasher: FeatureHasher, value: str) -> np.ndarray:
    tokens: Iterable[str]
    if value:
        tokens = [value]
    else:
        tokens = []
    return hasher.transform([list(tokens)]).toarray()[0].astype(np.float32)


def _hash_string_iterable(hasher: FeatureHasher, values: Iterable[str] | None) -> np.ndarray:
    tokens = list(values) if values is not None else []
    return hasher.transform([tokens]).toarray()[0].astype(np.float32)


def _hash_pairs(hasher: FeatureHasher, pairs: Iterable[Tuple[str, float]] | None) -> np.ndarray:
    clean_pairs: List[Tuple[str, float]] = []
    if pairs is not None:
        for name, value in pairs:
            clean_pairs.append((str(name), float(value)))
    return hasher.transform([clean_pairs]).toarray()[0].astype(np.float32)


def _vectorize_entry(features: Dict[str, object]) -> np.ndarray:
    vec = np.zeros(VECTOR_SIZE, dtype=np.float32)
    offset = 0

    # Byte histograms --------------------------------------------------
    vec[offset : offset + BYTE_HIST_SIZE] = _normalise_histogram(features.get("histogram", []), BYTE_HIST_SIZE)
    offset += BYTE_HIST_SIZE

    vec[offset : offset + BYTE_ENTROPY_HIST_SIZE] = _normalise_histogram(
        features.get("byteentropy", []), BYTE_ENTROPY_HIST_SIZE
    )
    offset += BYTE_ENTROPY_HIST_SIZE

    # Strings ----------------------------------------------------------
    strings = features.get("strings", {}) or {}
    for name in STRING_LEADING_FIELDS:
        vec[offset] = float(strings.get(name, 0))
        offset += 1

    printable = np.zeros(PRINTABLE_DIST_SIZE, dtype=np.float32)
    raw_printable = np.asarray(strings.get("printabledist", []), dtype=np.float32)
    if raw_printable.size:
        length = min(PRINTABLE_DIST_SIZE, raw_printable.size)
        printable[:length] = raw_printable[:length]
    divisor = float(strings.get("printables", 0))
    if divisor > 0:
        printable /= divisor
    else:
        printable[:] = 0.0
    vec[offset : offset + PRINTABLE_DIST_SIZE] = printable
    offset += PRINTABLE_DIST_SIZE

    for name in STRING_TRAILING_FIELDS:
        vec[offset] = float(strings.get(name, 0))
        offset += 1

    # General ----------------------------------------------------------
    general = features.get("general", {}) or {}
    for name in GENERAL_FEATURES:
        vec[offset] = float(general.get(name, 0))
        offset += 1

    # Header -----------------------------------------------------------
    header = features.get("header", {}) or {}
    coff = header.get("coff", {}) or {}
    optional = header.get("optional", {}) or {}

    vec[offset] = float(coff.get("timestamp", 0))
    offset += HEADER_TIMESTAMP_SIZE

    vec[offset : offset + HEADER_MACHINE_HASH_SIZE] = _hash_single_string(
        _MACHINE_HASHER, str(coff.get("machine", "") or "")
    )
    offset += HEADER_MACHINE_HASH_SIZE

    vec[offset : offset + HEADER_CHARACTERISTICS_HASH_SIZE] = _hash_string_iterable(
        _CHARACTERISTICS_HASHER, coff.get("characteristics", []) or []
    )
    offset += HEADER_CHARACTERISTICS_HASH_SIZE

    vec[offset : offset + OPTIONAL_SUBSYSTEM_HASH_SIZE] = _hash_single_string(
        _SUBSYSTEM_HASHER, str(optional.get("subsystem", "") or "")
    )
    offset += OPTIONAL_SUBSYSTEM_HASH_SIZE

    vec[offset : offset + OPTIONAL_DLL_CHARACTERISTICS_HASH_SIZE] = _hash_string_iterable(
        _DLL_CHARACTERISTICS_HASHER, optional.get("dll_characteristics", []) or []
    )
    offset += OPTIONAL_DLL_CHARACTERISTICS_HASH_SIZE

    vec[offset : offset + OPTIONAL_MAGIC_HASH_SIZE] = _hash_single_string(
        _MAGIC_HASHER, str(optional.get("magic", "") or "")
    )
    offset += OPTIONAL_MAGIC_HASH_SIZE

    for name in OPTIONAL_NUMERIC_FEATURES:
        vec[offset] = float(optional.get(name, 0))
        offset += 1

    # Data directories -------------------------------------------------
    data_dirs = features.get("datadirectories", []) or []
    for i in range(DATA_DIRECTORY_COUNT):
        if i < len(data_dirs):
            entry = data_dirs[i] or {}
            vec[offset + i * 2] = float(entry.get("size", 0))
            vec[offset + i * 2 + 1] = float(entry.get("virtual_address", entry.get("rva", 0)))
    offset += DATA_DIRECTORY_SIZE

    # Section statistics -----------------------------------------------
    section_info = features.get("section", {}) or {}
    sections = section_info.get("sections", []) or []

    general_stats = [
        len(sections),
        sum(1 for s in sections if float(s.get("size", 0)) == 0),
        sum(1 for s in sections if not s.get("name")),
        sum(
            1
            for s in sections
            if "MEM_READ" in (s.get("props") or []) and "MEM_EXECUTE" in (s.get("props") or [])
        ),
        sum(1 for s in sections if "MEM_WRITE" in (s.get("props") or [])),
    ]
    vec[offset : offset + SECTION_GENERAL_SIZE] = np.asarray(general_stats, dtype=np.float32)
    offset += SECTION_GENERAL_SIZE

    section_sizes = [(s.get("name", ""), s.get("size", 0)) for s in sections]
    vec[offset : offset + SECTION_HASH_SIZE] = _hash_pairs(_SECTION_SIZE_HASHER, section_sizes)
    offset += SECTION_HASH_SIZE

    section_entropy = [(s.get("name", ""), s.get("entropy", 0)) for s in sections]
    vec[offset : offset + SECTION_HASH_SIZE] = _hash_pairs(_SECTION_ENTROPY_HASHER, section_entropy)
    offset += SECTION_HASH_SIZE

    section_vsize = [(s.get("name", ""), s.get("vsize", s.get("virtual_size", 0))) for s in sections]
    vec[offset : offset + SECTION_HASH_SIZE] = _hash_pairs(_SECTION_VSIZE_HASHER, section_vsize)
    offset += SECTION_HASH_SIZE

    vec[offset : offset + SECTION_HASH_SIZE] = _hash_single_string(
        _SECTION_ENTRY_HASHER, str(section_info.get("entry", "") or "")
    )
    offset += SECTION_HASH_SIZE

    entry_name = section_info.get("entry", "")
    entry_characteristics: List[str] = []
    for s in sections:
        if s.get("name") == entry_name:
            entry_characteristics.extend(s.get("props", []) or [])
    vec[offset : offset + SECTION_HASH_SIZE] = _hash_string_iterable(
        _SECTION_CHARACTERISTICS_HASHER, entry_characteristics
    )
    offset += SECTION_HASH_SIZE

    # Imports ----------------------------------------------------------
    imports = features.get("imports", {}) or {}
    if isinstance(imports, dict):
        libraries = list({str(lib).lower() for lib in imports.keys()})
    else:
        libraries = []
    vec[offset : offset + IMPORT_LIB_HASH_SIZE] = _hash_string_iterable(_IMPORT_LIBRARY_HASHER, libraries)
    offset += IMPORT_LIB_HASH_SIZE

    import_functions: List[str] = []
    if isinstance(imports, dict):
        for lib, entries in imports.items():
            lib_lower = str(lib).lower()
            if isinstance(entries, (list, tuple)):
                import_functions.extend(f"{lib_lower}:{entry}" for entry in entries)
            elif entries:
                import_functions.append(f"{lib_lower}:{entries}")
    vec[offset : offset + IMPORT_FUNC_HASH_SIZE] = _hash_string_iterable(
        _IMPORT_FUNCTION_HASHER, import_functions
    )
    offset += IMPORT_FUNC_HASH_SIZE

    # Exports ----------------------------------------------------------
    exports = features.get("exports", [])
    if isinstance(exports, dict):
        export_entries = exports.get("functions", []) or []
    else:
        export_entries = exports or []
    vec[offset : offset + EXPORT_HASH_SIZE] = _hash_string_iterable(_EXPORT_HASHER, export_entries)
    offset += EXPORT_HASH_SIZE

    return vec


def vectorize_feature_file(
    json_path: str,
    save_path: str,
    progress_callback=None,
    text_callback=None,
    max_workers: int = None,
    realtime_write: bool = True,
) -> None:
    """Vectorise features stored in ``json_path`` and save to ``save_path``.

    ``json_path`` should contain one JSON object per line. Each line can either
    include a ``features`` field (as produced by
    :func:`static_features.extract_from_directory`) or place the EMBER-style
    feature blocks directly at the top level (official EMBER JSONL export).
    ``save_path`` will be written in NumPy ``.npy`` format containing an
    array of shape ``(num_files, VECTOR_SIZE)``.
    """
    save_path += '/' + NAME_RULE(only_time=True)
    print(save_path)
    file_path = Path(json_path)

    if not file_path.exists():
        raise FileNotFoundError(f"特征文件不存在: {json_path}")

    # 为了兼容大型官方 EMBER 数据集，按流式方式读取文件，并单独统计行数
    with file_path.open("r", encoding="utf-8") as fh:
        total = sum(1 for _ in fh)

    if total == 0:
        text_callback("输入文件为空，未生成任何向量")
        return
    if progress_callback is None:
        progress_callback = lambda x: None
    if text_callback is None:
        text_callback = lambda x: None

    # 确定线程数
    if max_workers is None:
        import os
        cpu_count = os.cpu_count() or 12
        max_workers = min(total, cpu_count, 100)  # 提高默认线程数上限

    write_mode = "实时写入" if realtime_write else "批量写入"
    text_callback(f"开始向量化 {total} 个特征，使用 {max_workers} 个线程，{write_mode}模式")

    def process_line(line_data, vector_writer=None):
        """处理单行数据的向量化"""
        idx, line = line_data

        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            label = 0
            path = f"line_{idx}"
            if vector_writer:
                zero_vec = np.zeros(VECTOR_SIZE, dtype=np.float32)
                vector_writer.add_vector(zero_vec, idx, label, path)
            return idx, None, label, path, False, str(exc)

        features = record.get("features")
        if not features:
            # 兼容 EMBER 官方 JSONL：特征字段位于顶层
            fallback = {
                key: value
                for key, value in record.items()
                if key in FEATURE_BLOCK_KEYS
            }
            if fallback:
                features = fallback
            else:
                features = {}

        raw_label = record.get("label")
        if raw_label is None and isinstance(features, dict):
            raw_label = features.get("label")
        try:
            label = int(raw_label) if raw_label is not None else 0
        except (TypeError, ValueError):
            label = 0

        path = (
            record.get("path")
            or record.get("sha256")
            or record.get("md5")
            or f"line_{idx}"
        )

        try:
            vec = _vectorize_entry(features)

            # 实时写入向量
            if vector_writer:
                vector_writer.add_vector(vec, idx, label, path)

            return idx, vec, label, path, True, None
        except Exception as e:
            # 失败时也写入零向量
            if vector_writer:
                zero_vec = np.zeros(VECTOR_SIZE, dtype=np.float32)
                vector_writer.add_vector(zero_vec, idx, label, path)

            return idx, None, label, path, False, str(e)

    # 创建实时向量写入器
    vector_writer = None
    if realtime_write:
        vector_writer = ThreadSafeVectorWriter(save_path, VECTOR_SIZE, text_callback)

    # 准备数据
    def iter_lines():
        with file_path.open("r", encoding="utf-8") as fh:
            for idx, raw_line in enumerate(fh):
                yield idx, raw_line.rstrip("\n")

    # 使用线程池并行处理
    vectors = [None] * total if not realtime_write else None  # 批量模式才需要预分配
    labels = [None] * total if not realtime_write else None
    successful = 0
    failed = 0

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有任务
            future_to_idx = {}
            for data in iter_lines():
                future = executor.submit(process_line, data, vector_writer)
                future_to_idx[future] = data[0]
            
            # 收集结果
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    result_idx, vec, label, path, success, error = future.result()

                    if success:
                        if not realtime_write:
                            vectors[result_idx] = vec
                            labels[result_idx] = label
                        successful += 1
                        text_callback(f"已转换 {path}")
                    else:
                        if not realtime_write:
                            vectors[result_idx] = np.zeros(
                                VECTOR_SIZE, dtype=np.float32
                            )
                            labels[result_idx] = label
                        failed += 1
                        text_callback(f"转换失败 {path}: {error}")
                    
                    # 更新进度
                    progress_callback(int((successful + failed) / total * 100))
                    
                except Exception as e:
                    if not realtime_write:
                        vectors[idx] = np.zeros(VECTOR_SIZE, dtype=np.float32)
                        labels[idx] = 0
                    failed += 1
                    text_callback(f"处理异常 line_{idx}: {str(e)}")
                    progress_callback(int((successful + failed) / total * 100))

        # 如果不是实时写入模式，需要批量写入
        if not realtime_write:
            text_callback("开始批量写入向量...")
            # 移除None值并转换为numpy数组
            combined = [
                (vec, label)
                for vec, label in zip(vectors, labels)
                if vec is not None and label is not None
            ]
            if combined:
                array = np.vstack([vec for vec, _ in combined])
                label_array = np.asarray([label for _, label in combined], dtype=np.int64)
            else:
                array = np.empty((0, VECTOR_SIZE), dtype=np.float32)
                label_array = np.empty((0,), dtype=np.int64)
            np.save(save_path, {"x": array, "y": label_array})
        else:
            # 实时写入模式，将所有向量写入文件
            vector_writer.write_to_file()
        
        text_callback(f"向量化完成: 成功 {successful} 个，失败 {failed} 个")
        
    except Exception as e:
        text_callback(f"向量化过程异常: {str(e)}")
        raise
