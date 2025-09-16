# core/feature_engineering/static_features.py

from __future__ import annotations

import json
import hashlib
import math
import re
from typing import Dict, List, Union, Optional
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

import numpy as np

from scripts.FILE_NAME import NAME_RULE
from .feature_utils import shannon_entropy
from .pe_parser import parse_pe
from core.utils.logger import LOG


class ThreadSafeProgressTracker:
    """线程安全的进度跟踪器"""

    def __init__(self, total_files: int, progress_callback=None, text_callback=None):
        self.total_files = total_files
        self.progress_callback = progress_callback or (lambda x: None)
        self.text_callback = text_callback or (lambda x: None)
        self.completed_files = 0
        self.lock = threading.Lock()

    def update_progress(self, file_progress: float, file_name: str = ""):
        """更新整体进度"""
        with self.lock:
            # 计算整体进度：已完成文件数 + 当前文件进度
            overall_progress = (self.completed_files + file_progress / 100) / self.total_files * 100
            self.progress_callback(int(overall_progress))
            if file_name:
                self.text_callback(f"处理中 {file_name} ({file_progress:.1f}%)")

    def complete_file(self, file_name: str):
        """标记文件完成"""
        with self.lock:
            self.completed_files += 1
            overall_progress = self.completed_files / self.total_files * 100
            self.progress_callback(int(overall_progress))
            self.text_callback(f"已完成 {file_name} ({self.completed_files}/{self.total_files})")


class ThreadSafeFileWriter:
    """线程安全的实时文件写入器"""

    def __init__(self, file_path: Path, text_callback=None):
        self.file_path = file_path
        self.text_callback = text_callback or (lambda x: None)
        self.lock = threading.Lock()
        self.written_count = 0

        # 打开文件进行追加写入
        self.file_handle = open(file_path, 'w', encoding='utf-8', buffering=1)  # 行缓冲

    def write_result(self, result: Dict, file_index: int = None):
        """写入单个结果"""
        with self.lock:
            try:
                if result["success"]:
                    data = {
                        # "path": result["path"],
                        "features": result["features"],
                        # "label": result.get("label")
                    }
                else:
                    data = {
                        # "path": result["path"],
                        "features": {},
                        # "label": result.get("label")
                    }

                self.file_handle.write(json.dumps(data) + "\n")
                self.file_handle.flush()  # 强制刷新缓冲区
                self.written_count += 1

                if file_index is not None:
                    self.text_callback(f"已写入第 {file_index} 个文件: {Path(result['path']).name}")

            except Exception as e:
                self.text_callback(f"写入失败: {str(e)}")
                LOG(f"{Path(result['path']).name}写入失败: {str(e)}")

    def close(self):
        """关闭文件"""
        with self.lock:
            if hasattr(self, 'file_handle') and self.file_handle:
                self.file_handle.close()
                self.text_callback(f"文件写入完成，共写入 {self.written_count} 条记录")
                LOG(f"文件写入完成，共写入 {self.written_count} 条记录")

    def __del__(self):
        """析构函数确保文件被关闭"""
        self.close()


def _byte_histogram(data: bytes) -> List[int]:
    if not data:
        return [0] * 256
    byte_array = np.frombuffer(data, dtype=np.uint8)
    hist = np.bincount(byte_array, minlength=256)
    return hist.astype(int).tolist()


def _byte_entropy_histogram(data: bytes, window_size: int = 2048) -> List[int]:
    if not data:
        return [0] * 256

    histogram = np.zeros((16, 16), dtype=np.float32)
    length = len(data)
    if length < window_size:
        return histogram.flatten().astype(int).tolist()

    byte_array = np.frombuffer(data, dtype=np.uint8)
    step = max(window_size // 2, 1)
    for start in range(0, length - window_size + 1, step):
        window = byte_array[start:start + window_size]
        if not window.size:
            continue

        avg_byte = float(np.mean(window))
        byte_bin = min(int(avg_byte / 16), 15)

        counts = np.bincount(window, minlength=256)
        non_zero = counts[counts > 0]
        probs = non_zero / float(window.size)
        entropy = float(-np.sum(probs * np.log2(probs))) if non_zero.size else 0.0
        entropy_bin = min(int(entropy * 2), 15)

        histogram[byte_bin, entropy_bin] += 1.0

    return histogram.flatten().astype(int).tolist()


def _compute_hashes(data: bytes) -> Dict[str, str]:
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    return {"sha256": sha256, "md5": md5}


def _extract_strings(data: bytes, min_length: int = 5) -> List[str]:
    strings: List[str] = []
    current: List[str] = []
    for byte in data:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append("".join(current))
            current = []
    if len(current) >= min_length:
        strings.append("".join(current))
    return strings


def _strings_features(data: bytes) -> Dict[str, object]:
    ascii_strings = _extract_strings(data)
    num_strings = len(ascii_strings)
    total_length = sum(len(s) for s in ascii_strings)
    average_length = (total_length / num_strings) if num_strings else 0.0

    printable_dist = [0] * 96
    for s in ascii_strings:
        for ch in s:
            idx = ord(ch) - 32
            if 0 <= idx < 96:
                printable_dist[idx] += 1

    total_printables = sum(printable_dist)
    entropy = 0.0
    if total_printables:
        probabilities = [count / total_printables for count in printable_dist if count]
        entropy = -sum(p * math.log2(p) for p in probabilities)

    path_pattern = re.compile(r"([A-Za-z]:\\|\\\\|/).+")
    url_pattern = re.compile(r"https?://", re.IGNORECASE)
    registry_pattern = re.compile(r"HKEY_|HKLM|HKCU|HKCR|HKU", re.IGNORECASE)

    paths = sum(1 for s in ascii_strings if path_pattern.search(s))
    urls = sum(1 for s in ascii_strings if url_pattern.search(s))
    registry = sum(1 for s in ascii_strings if registry_pattern.search(s))
    mz_count = data.count(b"MZ")

    return {
        "numstrings": num_strings,
        "avlength": float(average_length),
        "printabledist": printable_dist,
        "printables": total_printables,
        "entropy": float(entropy),
        "paths": paths,
        "urls": urls,
        "registry": registry,
        "MZ": mz_count,
    }


def _general_features(pe_path: Path, binary, data: bytes) -> Dict[str, object]:
    sections_count = len(binary.sections)
    imports_count = sum(len(lib.entries) for lib in binary.imports)
    exports_count = len(binary.exported_functions) if binary.has_exports else 0
    resources_count = len(getattr(binary.resources, "childs", [])) if binary.has_resources else 0

    oh = binary.optional_header
    entrypoint = int(getattr(oh, "addressof_entrypoint", 0)) if oh is not None else 0

    return {
        "size": pe_path.stat().st_size,
        "vsize": int(getattr(binary, "virtual_size", 0)),
        "has_debug": int(getattr(binary, "has_debug", False)),
        "exports": exports_count,
        "imports": imports_count,
        "has_relocations": int(getattr(binary, "has_relocations", False)),
        "has_resources": int(getattr(binary, "has_resources", False)),
        "has_signature": int(getattr(binary, "has_signatures", False)),
        "has_tls": int(getattr(binary, "has_tls", False)),
        "symbols": int(len(getattr(binary, "symbols", []))),
        "num_sections": sections_count,
        "entrypoint": entrypoint,
        "overall_entropy": shannon_entropy(data),
        "num_resources": resources_count,
    }


def _header_features(binary) -> Dict[str, object]:
    header_info: Dict[str, object] = {"coff": {}, "optional": {}}

    coff = binary.header
    if coff is not None:
        machine = getattr(coff.machine, "name", str(coff.machine))
        characteristics = [
            getattr(flag, "name", str(flag)) for flag in getattr(coff, "characteristics_lists", [])
        ]
        header_info["coff"] = {
            "timestamp": int(getattr(coff, "time_date_stamps", 0)),
            "machine": machine,
            "characteristics": characteristics,
        }

    oh = binary.optional_header
    if oh is not None:
        dll_characteristics = [
            getattr(flag, "name", str(flag)) for flag in getattr(oh, "dll_characteristics_lists", [])
        ]
        header_info["optional"] = {
            "subsystem": getattr(getattr(oh, "subsystem", None), "name", str(getattr(oh, "subsystem", ""))),
            "dll_characteristics": dll_characteristics,
            "magic": getattr(getattr(oh, "magic", None), "name", str(getattr(oh, "magic", ""))),
            "major_image_version": int(getattr(oh, "major_image_version", 0)),
            "minor_image_version": int(getattr(oh, "minor_image_version", 0)),
            "major_linker_version": int(getattr(oh, "major_linker_version", 0)),
            "minor_linker_version": int(getattr(oh, "minor_linker_version", 0)),
            "major_operating_system_version": int(getattr(oh, "major_operating_system_version", 0)),
            "minor_operating_system_version": int(getattr(oh, "minor_operating_system_version", 0)),
            "major_subsystem_version": int(getattr(oh, "major_subsystem_version", 0)),
            "minor_subsystem_version": int(getattr(oh, "minor_subsystem_version", 0)),
            "sizeof_code": int(getattr(oh, "sizeof_code", 0)),
            "sizeof_headers": int(getattr(oh, "sizeof_headers", 0)),
            "sizeof_heap_commit": int(getattr(oh, "sizeof_heap_commit", 0)),
            "sizeof_image": int(getattr(oh, "sizeof_image", 0)),
            "checksum": int(getattr(oh, "checksum", 0)),
            "addressof_entrypoint": int(getattr(oh, "addressof_entrypoint", 0)),
        }

    return header_info


def _section_features(binary) -> Dict[str, object]:
    sections: List[Dict[str, object]] = []
    for sec in binary.sections:
        props = [getattr(flag, "name", str(flag)) for flag in getattr(sec, "characteristics_lists", [])]
        sections.append(
            {
                "name": sec.name,
                "size": int(getattr(sec, "size", 0)),
                "vsize": int(getattr(sec, "virtual_size", 0)),
                "entropy": float(getattr(sec, "entropy", 0.0)),
                "props": props,
            }
        )

    entry_section = ""
    try:
        section_obj = None
        if hasattr(binary, "section_from_rva"):
            section_obj = binary.section_from_rva(getattr(binary, "entrypoint", 0))
        if section_obj is not None:
            entry_section = getattr(section_obj, "name", "")
    except Exception:
        entry_section = ""

    return {"entry": entry_section, "sections": sections}


def _imports_features(binary) -> Dict[str, List[str]]:
    imports: Dict[str, List[str]] = {}
    for lib in binary.imports:
        functions = []
        for entry in lib.entries:
            if getattr(entry, "is_ordinal", False):
                continue
            if entry.name:
                functions.append(entry.name)
        imports[lib.name] = functions
    return imports


def _exports_features(binary) -> List[str]:
    if not getattr(binary, "has_exports", False):
        return []
    return [func.name for func in getattr(binary, "exported_functions", []) if func.name]


def _datadirectories_features(binary) -> List[Dict[str, object]]:
    directories: List[Dict[str, object]] = []

    oh = getattr(binary, "optional_header", None)
    data_dirs = []
    if oh is not None and hasattr(oh, "data_directories"):
        data_dirs = oh.data_directories
    elif hasattr(binary, "data_directories"):
        data_dirs = binary.data_directories

    for dd in data_dirs:
        name = getattr(getattr(dd, "type", None), "name", str(getattr(dd, "type", "")))
        directories.append(
            {
                "name": name,
                "size": int(getattr(dd, "size", 0)),
                "virtual_address": int(getattr(dd, "rva", 0)),
            }
        )

    return directories


def extract_features(pe_path: Union[str, Path], progress_callback=None, label: Optional[int] = None) -> Dict[
    str, object]:
    pe_path = Path(pe_path)
    binary = parse_pe(str(pe_path))
    if binary is None:
        return {}

    if progress_callback is None:
        progress_callback = lambda x: None

    raw_data = pe_path.read_bytes()
    hashes = _compute_hashes(raw_data)

    features: Dict[str, object] = {
        **hashes,
        "label": int(label) if label is not None else (1 if "malware" in str(pe_path).lower() else 0),
        "avclass": None,
    }

    total_steps = 8
    current_step = 0

    features["histogram"] = _byte_histogram(raw_data)
    current_step += 1
    progress_callback(int(current_step / total_steps * 100))

    features["byteentropy"] = _byte_entropy_histogram(raw_data)
    current_step += 1
    progress_callback(int(current_step / total_steps * 100))

    features["strings"] = _strings_features(raw_data)
    current_step += 1
    progress_callback(int(current_step / total_steps * 100))

    features["general"] = _general_features(pe_path, binary, raw_data)
    current_step += 1
    progress_callback(int(current_step / total_steps * 100))

    features["header"] = _header_features(binary)
    current_step += 1
    progress_callback(int(current_step / total_steps * 100))

    features["section"] = _section_features(binary)
    current_step += 1
    progress_callback(int(current_step / total_steps * 100))

    features["imports"] = _imports_features(binary)
    features["exports"] = _exports_features(binary)
    current_step += 1
    progress_callback(int(current_step / total_steps * 100))

    features["datadirectories"] = _datadirectories_features(binary)
    current_step += 1
    progress_callback(int(current_step / total_steps * 100))

    return features


def _process_single_file(file_path: Path, progress_tracker: ThreadSafeProgressTracker,
                         file_writer: ThreadSafeFileWriter = None, file_index: int = None) -> Dict:
    """处理单个文件的特征提取（用于多线程）"""
    print(file_path)
    try:
        # 创建文件级的进度回调
        def file_progress_callback(progress: int):
            progress_tracker.update_progress(progress, file_path.name)

        # 预估标签
        inferred_label = 1 if 'malware' in str(file_path).lower() else 0

        # 提取特征
        features = extract_features(file_path, progress_callback=file_progress_callback, label=inferred_label)

        result = {
            # "path": str(file_path),
            "features": features,
            # "label": features.get("label", inferred_label),
            "success": True
        }

        print(result)
        # 实时写入结果
        if file_writer:
            file_writer.write_result(result, file_index)

        # 标记文件完成
        progress_tracker.complete_file(file_path.name)

        return result
    except Exception as e:
        progress_tracker.text_callback(f"处理失败 {file_path.name}: {str(e)}")
        result = {
            # "path": str(file_path),
            "features": {},
            "success": False,
            "error": str(e)
        }

        # 实时写入失败结果
        if file_writer:
            file_writer.write_result(result, file_index)

        print(result)
        return result


def extract_from_directory(
        folder: Union[str, Path],
        save_path: Union[str, Path],
        progress_callback=None,
        text_callback=None,
        max_workers: int = None,
        realtime_write: bool = True,
) -> Path:
    folder_path = Path(folder)
    if folder_path.is_file():
        folder_path = folder_path.parent
    output_dir = Path(save_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    files = [
        p
        for p in folder_path.rglob("*")
        if p.is_file() and p.suffix.lower() in {".exe", ".dll", ".sys"}
    ]

    total = len(files)
    if progress_callback is None:
        progress_callback = lambda x: None
    if text_callback is None:
        text_callback = lambda x: None

    save_file = output_dir / f"{NAME_RULE()}.jsonl"
    print(f"save: {save_file}")
    LOG(f"save: {save_file}", level=1)

    if total == 0:
        save_file.touch()
        progress_callback(100)
        return save_file

    # 确定线程数
    if max_workers is None:
        # 智能选择线程数：基于CPU核心数和文件数量
        import os
        cpu_count = os.cpu_count() or 4
        LOG(f"cpu core nums {os.cpu_count()}", level=0)
        # 使用CPU核心数，但不超过文件数量和100个线程（提高默认值）
        max_workers = min(total, cpu_count, 100)

    write_mode = "实时写入" if realtime_write else "批量写入"
    text_callback(f"开始处理 {total} 个文件，使用 {max_workers} 个线程，{write_mode}模式")

    # 创建线程安全的进度跟踪器
    progress_tracker = ThreadSafeProgressTracker(total, progress_callback, text_callback)

    # 创建实时文件写入器
    file_writer = None
    if realtime_write:
        file_writer = ThreadSafeFileWriter(save_file, text_callback)

    try:
        # 使用线程池并行处理文件
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 为每个文件分配索引
            file_to_index = {str(f): i for i, f in enumerate(files, 1)}

            # 提交所有任务
            future_to_file = {
                executor.submit(
                    _process_single_file,
                    file_path,
                    progress_tracker,
                    file_writer,
                    file_to_index[str(file_path)]
                ): file_path
                for file_path in files
            }

            # 收集结果（用于统计）
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    text_callback(f"文件 {file_path} 处理异常: {str(e)}")
                    result = {
                        # "path": str(file_path),
                        "features": {},
                        "success": False,
                        "error": str(e)
                    }
                    results.append(result)

                    # 实时写入异常结果
                    if file_writer:
                        file_writer.write_result(result, file_to_index[str(file_path)])

        # 如果不是实时写入模式，需要批量写入
        if not realtime_write:
            text_callback("开始批量写入结果...")
            with open(save_file, "w", encoding="utf-8") as f:
                # 按原始顺序排序结果（保持文件顺序）
                file_path_to_result = {result["path"]: result for result in results}
                sorted_results = [file_path_to_result[str(f)] for f in files]

                for result in sorted_results:
                    if result["success"]:
                        f.write(json.dumps({
                            # "path": result["path"],
                            "features": result["features"],
                            # "label": result.get("label")
                        }) + "\n")
                    else:
                        # 即使失败也记录，但特征为空
                        f.write(json.dumps({
                            # "path": result["path"],
                            "features": {},
                            # "label": result.get("label")
                        }) + "\n")

        # 统计成功和失败的文件数
        successful = sum(1 for r in results if r["success"])
        failed = len(results) - successful

        text_callback(f"特征提取完成: 成功 {successful} 个，失败 {failed} 个")
        progress_callback(100)

    finally:
        # 确保文件写入器被正确关闭
        if file_writer:
            file_writer.close()

    return save_file
