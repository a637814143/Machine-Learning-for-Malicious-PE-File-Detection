# core/feature_engineering/static_features.py

from __future__ import annotations

import json
from typing import Dict, Union
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from scripts.FILE_NAME import NAME_RULE
from .feature_utils import (
    Hash_sha256,
    Hash_md5,
    Appeared,
    Label,
    Avclass,
    ByteEntropyHistogram,
    ByteHistogram,
    General,
    Header,
    Sections,
    Strings,
)


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
                    data = result["features"]
                else:
                    data = {"features": {}}

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


def extract_features(pe_path: Union[str, Path], progress_callback=None) -> Dict[str, object]:
    """提取与 EMBER 数据集结构对齐的静态特征。"""

    pe_path = Path(pe_path)
    features: Dict[str, object] = {}

    if progress_callback is None:
        progress_callback = lambda x: None

    total_steps = 7
    current_step = 0

    # 元信息：哈希 / 标签 --------------------------------------------------
    try:
        features["sha256"] = Hash_sha256(str(pe_path))
        features["md5"] = Hash_md5(str(pe_path))
    except Exception:
        features["sha256"] = ""
        features["md5"] = ""

    try:
        features["appeared"] = Appeared()
    except Exception:
        features["appeared"] = ""

    try:
        features["label"] = Label(str(pe_path))
    except Exception:
        features["label"] = 0

    try:
        features["avclass"] = Avclass(str(pe_path))
    except Exception:
        features["avclass"] = ""

    current_step += 1
    progress_callback(int(current_step / total_steps * 100))

    # Byte histograms -----------------------------------------------------
    try:
        features["histogram"] = [int(v) for v in ByteHistogram(str(pe_path)).tolist()]
    except Exception:
        features["histogram"] = [0] * 256
    current_step += 1
    progress_callback(int(current_step / total_steps * 100))

    try:
        features["byteentropy"] = [int(v) for v in ByteEntropyHistogram(str(pe_path)).tolist()]
    except Exception:
        features["byteentropy"] = [0] * 256
    current_step += 1
    progress_callback(int(current_step / total_steps * 100))

    # Strings -------------------------------------------------------------
    try:
        features["strings"] = Strings(str(pe_path))
    except Exception:
        features["strings"] = {}
    current_step += 1
    progress_callback(int(current_step / total_steps * 100))

    # General statistics --------------------------------------------------
    try:
        features["general"] = General(str(pe_path))
    except Exception:
        features["general"] = {}
    current_step += 1
    progress_callback(int(current_step / total_steps * 100))

    # Header --------------------------------------------------------------
    header_data: Dict[str, Dict] = {}
    try:
        header_data = Header(str(pe_path))
    except Exception:
        header_data = {}

    if isinstance(header_data, dict):
        features["header"] = {
            "coff": header_data.get("coff", {}),
            "optional": header_data.get("optional", {}),
        }
    else:
        features["header"] = {"coff": {}, "optional": {}}
    current_step += 1
    progress_callback(int(current_step / total_steps * 100))

    # Sections / imports / exports / data directories --------------------
    try:
        section_data = Sections(str(pe_path))
    except Exception:
        section_data = {}

    if isinstance(section_data, dict):
        section_info = section_data.get("section", {})
        features["section"] = {
            "entry": section_info.get("entry", ""),
            "sections": section_info.get("sections", []),
        }
        features["imports"] = section_data.get("imports", {})
        features["exports"] = section_data.get("exports", [])
        features["datadirectories"] = section_data.get("datadirectories", [])
    else:
        features["section"] = {"entry": "", "sections": []}
        features["imports"] = {}
        features["exports"] = []
        features["datadirectories"] = []

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
        cpu_count = os.cpu_count() or 8
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
                        data = result["features"]
                    else:
                        data = {"features": {}}

                    f.write(json.dumps(data) + "\n")

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
