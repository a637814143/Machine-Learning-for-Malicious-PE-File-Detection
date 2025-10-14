"""Vectorise raw feature dictionaries into LightGBM-ready arrays."""

from __future__ import annotations

from typing import Dict, Iterable, List, Sequence, Tuple

import numpy as np
from sklearn.feature_extraction import FeatureHasher

BYTE_HIST_SIZE = 256
BYTE_ENTROPY_HIST_SIZE = 256

STRING_LEADING_FIELDS = ["numstrings", "avlength", "printables"]
PRINTABLE_DIST_SIZE = 96
STRING_TRAILING_FIELDS = ["entropy", "paths", "urls", "registry", "MZ"]

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
    tokens: Iterable[str] = [value] if value else []
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

    vec[offset : offset + BYTE_HIST_SIZE] = _normalise_histogram(features.get("histogram", []), BYTE_HIST_SIZE)
    offset += BYTE_HIST_SIZE

    vec[offset : offset + BYTE_ENTROPY_HIST_SIZE] = _normalise_histogram(
        features.get("byteentropy", []), BYTE_ENTROPY_HIST_SIZE
    )
    offset += BYTE_ENTROPY_HIST_SIZE

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

    general = features.get("general", {}) or {}
    for name in GENERAL_FEATURES:
        vec[offset] = float(general.get(name, 0))
        offset += 1

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

    data_dirs = features.get("datadirectories", []) or []
    for i in range(DATA_DIRECTORY_COUNT):
        if i < len(data_dirs):
            entry = data_dirs[i] or {}
            vec[offset + i * 2] = float(entry.get("size", 0))
            vec[offset + i * 2 + 1] = float(entry.get("virtual_address", entry.get("rva", 0)))
    offset += DATA_DIRECTORY_SIZE

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
    for section in sections:
        if section.get("name") == entry_name:
            entry_characteristics.extend(section.get("props", []) or [])
    vec[offset : offset + SECTION_HASH_SIZE] = _hash_string_iterable(
        _SECTION_CHARACTERISTICS_HASHER, entry_characteristics
    )
    offset += SECTION_HASH_SIZE

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

    exports = features.get("exports", [])
    if isinstance(exports, dict):
        export_entries = exports.get("functions", []) or []
    else:
        export_entries = exports or []
    vec[offset : offset + EXPORT_HASH_SIZE] = _hash_string_iterable(_EXPORT_HASHER, export_entries)
    offset += EXPORT_HASH_SIZE

    return vec


def vectorize_features(features: Dict[str, object]) -> np.ndarray:
    return _vectorize_entry(features)
