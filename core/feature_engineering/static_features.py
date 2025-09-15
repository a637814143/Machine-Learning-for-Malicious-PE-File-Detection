# core/feature_engineering/static_features.py

from __future__ import annotations

import json
from typing import Dict, List, Union
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from queue import Queue
import time

from scripts.FILE_NAME import NAME_RULE
from .feature_utils import ByteEntropyHistogram, ByteHistogram, shannon_entropy
from .pe_parser import parse_pe


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
                        "path": result["path"],
                        "features": result["features"]
                    }
                else:
                    data = {
                        "path": result["path"],
                        "features": {}
                    }
                
                self.file_handle.write(json.dumps(data) + "\n")
                self.file_handle.flush()  # 强制刷新缓冲区
                self.written_count += 1
                
                if file_index is not None:
                    self.text_callback(f"已写入第 {file_index} 个文件: {Path(result['path']).name}")
                
            except Exception as e:
                self.text_callback(f"写入失败: {str(e)}")
    
    def close(self):
        """关闭文件"""
        with self.lock:
            if hasattr(self, 'file_handle') and self.file_handle:
                self.file_handle.close()
                self.text_callback(f"文件写入完成，共写入 {self.written_count} 条记录")
    
    def __del__(self):
        """析构函数确保文件被关闭"""
        self.close()


def _section_features(binary) -> List[Dict[str, object]]:
    sections = []
    for sec in binary.sections:
        sections.append(
            {
                "name": sec.name,
                "size": int(sec.size),
                "virtual_size": int(sec.virtual_size),
                "entropy": float(sec.entropy),
                "characteristics": int(sec.characteristics),
                "pointerto_raw_data": int(sec.pointerto_raw_data),
            }
        )
    return sections


def _imports_features(binary) -> Dict[str, List[str]]:
    libraries: List[str] = []
    functions: List[str] = []
    for lib in binary.imports:
        libraries.append(lib.name)
        for entry in lib.entries:
            if entry.name:
                functions.append(entry.name)
    return {"libraries": libraries, "functions": functions}


def _exports_features(binary) -> Dict[str, List[str]]:
    if not binary.has_exports:
        return {"functions": []}
    return {"functions": [func.name for func in binary.exported_functions]}


def _resources_features(binary) -> List[str]:
    resources: List[str] = []
    if not binary.has_resources:
        return resources

    def walk(node, path=""):
        try:
            current = f"{path}/{node.id}" if path else str(node.id)
            
            # Try different ways to determine if it's a leaf node
            is_leaf = False
            if hasattr(node, 'is_leaf'):
                is_leaf = node.is_leaf
            elif hasattr(node, 'is_directory'):
                is_leaf = not node.is_directory
            else:
                # If we can't determine, assume it's a leaf if it has no children
                children = getattr(node, 'childs', None) or getattr(node, 'children', [])
                is_leaf = not children or len(children) == 0
            
            if is_leaf:
                resources.append(current)
            else:
                children = getattr(node, 'childs', None) or getattr(node, 'children', [])
                if children:
                    for child in children:
                        walk(child, current)
        except Exception as e:

            pass

    try:
        walk(binary.resources)
    except Exception as e:
        pass
    
    return resources


def extract_features(pe_path: Union[str, Path], progress_callback=None) -> Dict[str, object]:
    pe_path = Path(pe_path)
    binary = parse_pe(str(pe_path))
    if binary is None:
        return {}

    features: Dict[str, object] = {}
    
    # 初始化进度回调
    if progress_callback is None:
        progress_callback = lambda x: None
    
    total_steps = 9  # 总共的处理步骤数
    current_step = 0

    # Byte histograms
    features["byte_hist"] = ByteHistogram(str(pe_path)).tolist()
    current_step += 1
    progress_callback(int(current_step / total_steps * 100))
    
    features["byte_entropy_hist"] = ByteEntropyHistogram(str(pe_path)).tolist()
    current_step += 1
    progress_callback(int(current_step / total_steps * 100))

    # General file statistics
    sections_count = len(binary.sections)
    imports_count = sum(len(lib.entries) for lib in binary.imports)
    exports_count = len(binary.exported_functions) if binary.has_exports else 0
    resources_count = len(binary.resources.childs) if binary.has_resources else 0

    oh = binary.optional_header

    features["general"] = {
        "file_size": pe_path.stat().st_size,
        "virtual_size": int(getattr(binary, "virtual_size", 0)),
        "entrypoint": int(oh.addressof_entrypoint) if oh is not None else 0,
        "num_sections": sections_count,
        "num_imports": imports_count,
        "num_exports": exports_count,
        "num_resources": resources_count,
        "has_signature": int(binary.has_signatures),
        "has_debug": int(binary.has_debug),
        "overall_entropy": shannon_entropy(pe_path.read_bytes()),
    }
    current_step += 1
    progress_callback(int(current_step / total_steps * 100))

    # Header
    h = binary.header
    features["header"] = {
        "machine": int(h.machine.value),
        "numberof_sections": int(h.numberof_sections),
        "time_date_stamps": int(h.time_date_stamps),
        "pointerto_symbol_table": int(h.pointerto_symbol_table),
        "numberof_symbols": int(h.numberof_symbols),
        "sizeof_optional_header": int(h.sizeof_optional_header),
        "characteristics": int(h.characteristics),
    }
    current_step += 1
    progress_callback(int(current_step / total_steps * 100))

    # Optional header
    if oh is not None:
        features["optional_header"] = {
            "magic": int(oh.magic.value),
            "major_linker_version": int(oh.major_linker_version),
            "minor_linker_version": int(oh.minor_linker_version),
            "size_of_code": int(oh.sizeof_code),
            "size_of_initialized_data": int(oh.sizeof_initialized_data),
            "size_of_uninitialized_data": int(oh.sizeof_uninitialized_data),
            "addressof_entrypoint": int(oh.addressof_entrypoint),
            "base_of_code": int(oh.baseof_code),
            "imagebase": int(oh.imagebase),
            "section_alignment": int(oh.section_alignment),
            "file_alignment": int(oh.file_alignment),
            "major_os_version": int(oh.major_operating_system_version),
            "minor_os_version": int(oh.minor_operating_system_version),
            "major_image_version": int(oh.major_image_version),
            "minor_image_version": int(oh.minor_image_version),
            "major_subsystem_version": int(oh.major_subsystem_version),
            "minor_subsystem_version": int(oh.minor_subsystem_version),
            "win32_version_value": int(oh.win32_version_value),
            "sizeof_image": int(oh.sizeof_image),
            "sizeof_headers": int(oh.sizeof_headers),
            "checksum": int(oh.checksum),
            "subsystem": int(oh.subsystem),
            "dll_characteristics": int(oh.dll_characteristics),
            "sizeof_stack_reserve": int(oh.sizeof_stack_reserve),
            "sizeof_stack_commit": int(oh.sizeof_stack_commit),
            "sizeof_heap_reserve": int(oh.sizeof_heap_reserve),
            "sizeof_heap_commit": int(oh.sizeof_heap_commit),
            "loader_flags": int(oh.loader_flags),
            "numberof_rva_and_size": int(oh.numberof_rva_and_size),
        }

        # Data directories
        directories: List[Dict[str, int]] = []
        # Check if data_directories attribute exists, otherwise try alternative access
        if hasattr(oh, 'data_directories'):
            data_dirs = oh.data_directories
        else:
            # Try to access data directories through the binary object
            data_dirs = getattr(binary, 'data_directories', [])
        
        for dd in data_dirs:
            directories.append({"rva": int(dd.rva), "size": int(dd.size)})
        features["data_directories"] = directories
    else:
        features["optional_header"] = {}
        features["data_directories"] = []
    current_step += 1
    progress_callback(int(current_step / total_steps * 100))
    
    # Sections
    features["sections"] = _section_features(binary)
    current_step += 1
    progress_callback(int(current_step / total_steps * 100))

    # Imports / Exports / Resources
    features["imports"] = _imports_features(binary)
    current_step += 1
    progress_callback(int(current_step / total_steps * 100))
    
    features["exports"] = _exports_features(binary)
    current_step += 1
    progress_callback(int(current_step / total_steps * 100))
    
    features["resources"] = _resources_features(binary)
    current_step += 1
    progress_callback(int(current_step / total_steps * 100))

    return features


def _process_single_file(file_path: Path, progress_tracker: ThreadSafeProgressTracker, 
                        file_writer: ThreadSafeFileWriter = None, file_index: int = None) -> Dict:
    """处理单个文件的特征提取（用于多线程）"""
    try:
        # 创建文件级的进度回调
        def file_progress_callback(progress: int):
            progress_tracker.update_progress(progress, file_path.name)
        
        # 提取特征
        features = extract_features(file_path, progress_callback=file_progress_callback)
        
        result = {
            "path": str(file_path),
            "features": features,
            "success": True
        }
        
        # 实时写入结果
        if file_writer:
            file_writer.write_result(result, file_index)
        
        # 标记文件完成
        progress_tracker.complete_file(file_path.name)
        
        return result
    except Exception as e:
        progress_tracker.text_callback(f"处理失败 {file_path.name}: {str(e)}")
        result = {
            "path": str(file_path),
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

    if total == 0:
        save_file.touch()
        progress_callback(100)
        return save_file

    # 确定线程数
    if max_workers is None:
        # 智能选择线程数：基于CPU核心数和文件数量
        import os
        cpu_count = os.cpu_count() or 4
        # 使用CPU核心数，但不超过文件数量和12个线程（提高默认值）
        max_workers = min(total, cpu_count, 12)
    
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
                        "path": str(file_path),
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
                            "path": result["path"],
                            "features": result["features"]
                        }) + "\n")
                    else:
                        # 即使失败也记录，但特征为空
                        f.write(json.dumps({
                            "path": result["path"],
                            "features": {}
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
