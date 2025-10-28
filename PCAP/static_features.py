"""PCAP feature extraction orchestrator mirroring the PE static pipeline."""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Union

from .feature_utils import extract_flow_features

__all__ = [
    "ThreadSafeProgressTracker",
    "ThreadSafeFileWriter",
    "extract_pcap_features",
    "extract_pcap_features_batch",
    "extract_pcap_features_to_file",
]


class ThreadSafeProgressTracker:
    """Thread-safe helper used to surface extraction progress."""

    def __init__(self, total_items: int, progress_callback=None, text_callback=None):
        self.total_items = max(total_items, 1)
        self.progress_callback = progress_callback or (lambda *_: None)
        self.text_callback = text_callback or (lambda *_: None)
        self.completed_items = 0
        self.lock = threading.Lock()

    def update_progress(self, file_progress: float, file_name: str = "") -> None:
        with self.lock:
            overall_progress = (self.completed_items + file_progress / 100.0) / self.total_items * 100.0
            self.progress_callback(int(overall_progress))
            if file_name:
                self.text_callback(f"Processing {file_name} ({file_progress:.1f}%)")

    def complete_item(self, file_name: str = "") -> None:
        with self.lock:
            self.completed_items += 1
            overall_progress = self.completed_items / self.total_items * 100.0
            self.progress_callback(int(overall_progress))
            if file_name:
                self.text_callback(f"Completed {file_name} ({self.completed_items}/{self.total_items})")


class ThreadSafeFileWriter:
    """Streaming writer for JSON lines output."""

    def __init__(self, file_path: Path, text_callback=None):
        self.file_path = file_path
        self.text_callback = text_callback or (lambda *_: None)
        self.lock = threading.Lock()
        self.file_handle = open(file_path, "w", encoding="utf-8", buffering=1)
        self.written = 0

    def write_result(self, result: Dict[str, object]) -> None:
        with self.lock:
            self.file_handle.write(json.dumps(result, ensure_ascii=False) + "\n")
            self.file_handle.flush()
            self.written += 1

    def close(self) -> None:
        with self.lock:
            if getattr(self, "file_handle", None):
                self.file_handle.close()
                self.file_handle = None
                self.text_callback(f"Finished writing {self.written} records to {self.file_path}")

    def __del__(self):
        self.close()


def extract_pcap_features(pcap_path: Union[str, Path], progress_callback=None) -> Dict[str, object]:
    """Extract CIC-style flow statistics for a single PCAP file."""

    pcap_path = Path(pcap_path)
    progress_callback = progress_callback or (lambda *_: None)

    try:
        flows = extract_flow_features(pcap_path)
        progress_callback(100)
        return {
            "success": True,
            "path": str(pcap_path),
            "flows": flows,
        }
    except Exception as exc:  # pragma: no cover - defensive by design
        progress_callback(100)
        return {
            "success": False,
            "path": str(pcap_path),
            "error": str(exc),
            "flows": [],
        }


def extract_pcap_features_batch(
    inputs: Iterable[Union[str, Path]],
    *,
    max_workers: Optional[int] = None,
    progress_callback=None,
    text_callback=None,
) -> List[Dict[str, object]]:
    """Parallel feature extraction over multiple PCAP files."""

    paths = [Path(item) for item in inputs]
    tracker = ThreadSafeProgressTracker(len(paths), progress_callback, text_callback)
    results: List[Dict[str, object]] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {}
        for path in paths:
            callback = lambda progress, name=path.name: tracker.update_progress(progress, name)
            future = executor.submit(extract_pcap_features, path, callback)
            future_map[future] = path
        for future in as_completed(future_map):
            path = future_map[future]
            try:
                result = future.result()
            except Exception as exc:  # pragma: no cover - defensive
                result = {"success": False, "path": str(path), "error": str(exc), "flows": []}
            results.append(result)
            tracker.complete_item(path.name)

    return results


def extract_pcap_features_to_file(
    inputs: Iterable[Union[str, Path]],
    output_file: Union[str, Path],
    *,
    max_workers: Optional[int] = None,
    progress_callback=None,
    text_callback=None,
) -> Path:
    """Extract features for multiple PCAP files and write them as JSON lines."""

    output_path = Path(output_file)
    writer = ThreadSafeFileWriter(output_path, text_callback)

    try:
        for result in extract_pcap_features_batch(
            inputs,
            max_workers=max_workers,
            progress_callback=progress_callback,
            text_callback=text_callback,
        ):
            writer.write_result(result)
    finally:
        writer.close()

    return output_path
