"""Minimal static feature extractor aligned with the training pipeline."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Dict, Optional, Union

from .feature_utils import (
    Appeared,
    Avclass,
    ByteEntropyHistogram,
    ByteHistogram,
    General,
    Hash_md5,
    Hash_sha256,
    Header,
    Label,
    Sections,
    Strings,
)

FeatureDict = Dict[str, object]


def extract_features(
    pe_path: Union[str, Path],
    progress_callback: Optional[Callable[[int], None]] = None,
) -> FeatureDict:
    path = Path(pe_path)
    if not path.is_file():
        raise FileNotFoundError(f"未找到文件: {pe_path}")

    if progress_callback is None:
        progress_callback = lambda _: None

    features: FeatureDict = {}
    total_steps = 7
    step = 0

    features["sha256"] = Hash_sha256(str(path))
    features["md5"] = Hash_md5(str(path))
    features["appeared"] = Appeared()
    features["label"] = Label(str(path))
    features["avclass"] = Avclass(str(path))
    step += 1
    progress_callback(int(step / total_steps * 100))

    features["histogram"] = [int(v) for v in ByteHistogram(str(path))]
    step += 1
    progress_callback(int(step / total_steps * 100))

    features["byteentropy"] = [int(v) for v in ByteEntropyHistogram(str(path))]
    step += 1
    progress_callback(int(step / total_steps * 100))

    features["strings"] = Strings(str(path))
    step += 1
    progress_callback(int(step / total_steps * 100))

    features["general"] = General(str(path))
    step += 1
    progress_callback(int(step / total_steps * 100))

    features["header"] = Header(str(path))
    step += 1
    progress_callback(int(step / total_steps * 100))

    section_data = Sections(str(path))
    features["section"] = section_data.get("section", {"entry": "", "sections": []})
    features["imports"] = section_data.get("imports", {})
    features["exports"] = section_data.get("exports", [])
    features["datadirectories"] = section_data.get("datadirectories", [])
    step += 1
    progress_callback(int(step / total_steps * 100))

    return features
