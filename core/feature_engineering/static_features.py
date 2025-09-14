# core/feature_engineering/static_features.py

from __future__ import annotations

import json
from typing import Dict, List, Union
from pathlib import Path

from scripts.FILE_NAME import NAME_RULE
from .feature_utils import ByteEntropyHistogram, ByteHistogram, shannon_entropy
from .pe_parser import parse_pe


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


def extract_features(pe_path: Union[str, Path]) -> Dict[str, object]:
    pe_path = Path(pe_path)
    binary = parse_pe(str(pe_path))
    if binary is None:
        return {}

    features: Dict[str, object] = {}

    # Byte histograms
    features["byte_hist"] = ByteHistogram(str(pe_path)).tolist()
    features["byte_entropy_hist"] = ByteEntropyHistogram(str(pe_path)).tolist()

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
    # Sections
    features["sections"] = _section_features(binary)

    # Imports / Exports / Resources
    features["imports"] = _imports_features(binary)
    features["exports"] = _exports_features(binary)
    features["resources"] = _resources_features(binary)

    return features


def extract_from_directory(
        folder: Union[str, Path],
        save_path: Union[str, Path],
        progress_callback=None,
        text_callback=None,
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

    with open(save_file, "w", encoding="utf-8") as f:
        for idx, file in enumerate(files, 1):
            feats = extract_features(file)
            f.write(json.dumps({"path": str(file), "features": feats}) + "\n")
            progress_callback(int(idx / total * 100))
            text_callback(f"已处理 {file.name}")

    return save_file
