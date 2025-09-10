"""Extraction of static structural features from PE files.

All functions here operate on a ``pefile.PE`` object and return Python data
structures (dicts or lists) without performing any vectorisation.  The goal is
to keep the extraction logic separate from the later feature hashing step so
that the raw information can be inspected and extended easily.
"""

from __future__ import annotations

from typing import Dict, List

try:  # ``pefile`` may not be installed during some tests
    import pefile
except Exception:  # pragma: no cover
    pefile = None


def get_general_features(pe: "pefile.PE", file_size: int) -> Dict[str, int]:
    """Basic file information and values from the optional header."""

    oh = pe.OPTIONAL_HEADER
    fh = pe.FILE_HEADER
    return {
        "size": file_size,
        "vsize": getattr(oh, "SizeOfImage", 0),
        "entry": getattr(oh, "AddressOfEntryPoint", 0),
        "code_size": getattr(oh, "SizeOfCode", 0),
        "init_data_size": getattr(oh, "SizeOfInitializedData", 0),
        "uninit_data_size": getattr(oh, "SizeOfUninitializedData", 0),
        "image_base": getattr(oh, "ImageBase", 0),
        "section_align": getattr(oh, "SectionAlignment", 0),
        "file_align": getattr(oh, "FileAlignment", 0),
        "num_sections": getattr(fh, "NumberOfSections", 0),
    }


def get_data_directories(pe: "pefile.PE") -> List[int]:
    """Return a flattened list of VirtualAddress/Size for 16 directories."""

    result: List[int] = []
    dirs = getattr(pe, "OPTIONAL_HEADER", None)
    for i in range(16):
        if dirs and len(dirs.DATA_DIRECTORY) > i:
            entry = dirs.DATA_DIRECTORY[i]
            result.append(getattr(entry, "VirtualAddress", 0))
            result.append(getattr(entry, "Size", 0))
        else:
            result.extend([0, 0])
    return result


def get_section_features(pe: "pefile.PE") -> List[Dict[str, float]]:
    """Return name, raw size and entropy for each section."""

    sections: List[Dict[str, float]] = []
    for section in getattr(pe, "sections", []) or []:
        name = section.Name.decode(errors="ignore").rstrip("\x00")
        entropy_fn = getattr(section, "get_entropy", lambda: 0.0)
        sections.append(
            {
                "name": name,
                "size": int(getattr(section, "SizeOfRawData", 0)),
                "entropy": float(entropy_fn()),
            }
        )
    return sections


def get_imports(pe: "pefile.PE") -> Dict[str, List[str]]:
    """Return imported libraries and functions."""

    libs: List[str] = []
    funcs: List[str] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        libs.append(entry.dll.decode(errors="ignore"))
        for imp in entry.imports:
            if imp.name:
                funcs.append(imp.name.decode(errors="ignore"))
    return {"libraries": libs, "functions": funcs}


def get_exports(pe: "pefile.PE") -> List[str]:
    """Return list of exported function names."""

    names: List[str] = []
    directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if directory and getattr(directory, "symbols", None):
        for sym in directory.symbols:
            if sym.name:
                names.append(sym.name.decode(errors="ignore"))
    return names

