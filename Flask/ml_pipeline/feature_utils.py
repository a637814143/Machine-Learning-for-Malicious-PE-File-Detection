"""Helpers for extracting EMBER-style static features."""

from __future__ import annotations

import hashlib
import heapq
import mmap
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List

import lief
import numpy as np

from .pe_parser import parse_pe

PRINTABLE_MIN = 0x20
PRINTABLE_MAX = 0x7E
PRINTABLE_RANGE = PRINTABLE_MAX - PRINTABLE_MIN + 1

RE_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
RE_URL = re.compile(
    rb"(?:"
    rb"(?:https?|ftp)://[^\s/$.?#].\S*"
    rb"|"
    rb"www\.[^\s/]+\S*"
    rb"|"
    rb"[A-Za-z0-9.-]+\.(?:com|net|org|edu|gov|mil|info|io|biz|cn|ru|uk|de|jp|fr|au|br|it|nl|es)\S*"
    rb")",
    flags=re.IGNORECASE,
)
RE_WIN_PATH = re.compile(
    rb"(?:"
    rb"[A-Za-z]:\\\\(?:[^\\\\\r\n<>:\"/|?*]+\\\\)*[^\\\\\r\n<>:\"/|?*]*"
    rb"|"
    rb"\\\\\\\\[^\s\\\\/:*?\"<>|]+\\\\[^\s\\\\/:*?\"<>|]+"
    rb")",
)
RE_REG = re.compile(
    rb"(?:HKEY_(?:CLASSES_ROOT|CURRENT_USER|LOCAL_MACHINE|USERS|CURRENT_CONFIG)\\[^\r\n\"\'\t]+)",
    flags=re.IGNORECASE,
)
RE_MZ = re.compile(rb"MZ")
RE_IP = re.compile(
    rb"(?:"
    rb"(?:25[0-5]|2[0-4][0-9]|[01]?\d?\d)\."
    rb"(?:25[0-5]|2[0-4][0-9]|[01]?\d?\d)\."
    rb"(?:25[0-5]|2[0-4][0-9]|[01]?\d?\d)\."
    rb"(?:25[0-5]|2[0-4][0-9]|[01]?\d?\d)"
    rb")",
)

SUSPICIOUS_STRING_KEYWORDS = [
    "powershell",
    "cmd.exe",
    "rundll32",
    "regsvr32",
    "sc ",
    "schtasks",
    "wmic",
    "mshta",
    "wscript",
    "cscript",
    "bitsadmin",
    "invoke-webrequest",
    "-enc",
    "-nop",
    "downloadstring",
    "shellcode",
    "mimikatz",
]

MAX_URL_SAMPLES = 12
MAX_PATH_SAMPLES = 12
MAX_REG_SAMPLES = 12
MAX_IP_SAMPLES = 12
MAX_SUSPICIOUS_SAMPLES = 12
MAX_LONGEST_STRINGS = 10

_DATA_DIR_NAMES = [
    "EXPORT_TABLE",
    "IMPORT_TABLE",
    "RESOURCE_TABLE",
    "EXCEPTION_TABLE",
    "CERTIFICATE_TABLE",
    "BASE_RELOCATION_TABLE",
    "DEBUG",
    "ARCHITECTURE",
    "GLOBAL_PTR",
    "TLS_TABLE",
    "LOAD_CONFIG_TABLE",
    "BOUND_IMPORT",
    "IAT",
    "DELAY_IMPORT_DESCRIPTOR",
    "CLR_RUNTIME_HEADER",
]


def Hash_md5(file_path: str, size: int = 4 * 1024 * 1024) -> str:
    digest = hashlib.md5()
    with open(file_path, "rb") as handle:
        while chunk := handle.read(size):
            digest.update(chunk)
    return digest.hexdigest()


def Hash_sha256(file_path: str, size: int = 4 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(file_path, "rb") as handle:
        while chunk := handle.read(size):
            digest.update(chunk)
    return digest.hexdigest()


def Appeared() -> str:
    return "2018-11"


def Label(file_path: str) -> int:
    return 1 if "malware" in file_path.lower() else 0


def Avclass(file_path: str) -> str:
    return "unknown" if "malware" in file_path.lower() else ""


def ByteHistogram(pe_path: str, is_normalize: bool = False) -> np.ndarray:
    with open(pe_path, "rb") as handle:
        data = handle.read()
    arr = np.frombuffer(data, dtype=np.uint8)
    histogram = np.bincount(arr, minlength=256).astype(np.float32)
    if is_normalize and arr.size > 0:
        histogram /= arr.size
    return histogram


def ByteEntropyHistogram(pe_path: str, window_size: int = 2048) -> np.ndarray:
    histogram = np.zeros((16, 16), dtype=np.float32)
    with open(pe_path, "rb") as handle:
        data = handle.read()
    length = len(data)
    if length < window_size:
        return histogram.flatten()
    arr = np.frombuffer(data, dtype=np.uint8)
    step = max(window_size // 2, 1)
    for start in range(0, length - window_size + 1, step):
        window = arr[start : start + window_size]
        if not window.size:
            continue
        avg_byte = float(window.mean(dtype=np.float64))
        byte_bin = min(int(avg_byte / 16), 15)
        counts = np.bincount(window, minlength=256)
        probs = counts[counts > 0] / float(len(window))
        entropy = -np.sum(probs * np.log2(probs))
        entropy_bin = min(int(entropy * 2), 15)
        histogram[byte_bin, entropy_bin] += 1
    return histogram.flatten()


def Strings(file_path: str) -> Dict[str, Any]:
    def _entropy_from_counts(counts: np.ndarray) -> float:
        total = counts.sum()
        if total == 0:
            return 0.0
        probs = counts[counts > 0] / total
        return float(-(probs * np.log2(probs)).sum())

    def _decode(sample: bytes) -> str:
        text = sample.decode("utf-8", "ignore").strip()
        if text:
            return text
        return sample.decode("latin-1", "ignore").strip()

    printable_counts = np.zeros(PRINTABLE_RANGE, dtype=np.int64)
    numstrings = 0
    total_len = 0
    urls = paths = registry = mz = 0

    sample_urls: List[str] = []
    sample_paths: List[str] = []
    sample_registry: List[str] = []
    sample_ips: List[str] = []
    suspicious_samples: List[str] = []
    longest_heap: List[tuple[int, str]] = []

    target = Path(file_path)
    file_size = target.stat().st_size if target.exists() else 0

    with open(target, "rb") as handle:
        mm = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
        data = mm[:]
        mz = len(RE_MZ.findall(data))

        for match in RE_PRINTABLE.finditer(data):
            segment = match.group(0)
            length = len(segment)
            numstrings += 1
            total_len += length

            arr = np.frombuffer(segment, dtype=np.uint8)
            mask = (arr >= PRINTABLE_MIN) & (arr <= PRINTABLE_MAX)
            if mask.any():
                values = arr[mask] - PRINTABLE_MIN
                printable_counts += np.bincount(values, minlength=PRINTABLE_RANGE)

            text = _decode(segment)
            if not text:
                continue
            lower = text.lower()
            if any(keyword in lower for keyword in SUSPICIOUS_STRING_KEYWORDS):
                if text not in suspicious_samples and len(suspicious_samples) < MAX_SUSPICIOUS_SAMPLES:
                    suspicious_samples.append(text)

            if len(longest_heap) < MAX_LONGEST_STRINGS:
                heapq.heappush(longest_heap, (length, text))
            elif length > longest_heap[0][0]:
                heapq.heapreplace(longest_heap, (length, text))

        seen: set[str] = set()
        for finder, store, limit in [
            (RE_URL.finditer, sample_urls, MAX_URL_SAMPLES),
            (RE_WIN_PATH.finditer, sample_paths, MAX_PATH_SAMPLES),
            (RE_REG.finditer, sample_registry, MAX_REG_SAMPLES),
            (RE_IP.finditer, sample_ips, MAX_IP_SAMPLES),
        ]:
            seen.clear()
            for match in finder(data):
                candidate = _decode(match.group(0))
                if not candidate or candidate in seen:
                    continue
                store.append(candidate)
                seen.add(candidate)
                if len(store) >= limit:
                    break

        urls = len(RE_URL.findall(data))
        paths = len(RE_WIN_PATH.findall(data))
        registry = len(RE_REG.findall(data))

        mm.close()

    printables = int(printable_counts.sum())
    avlength = float(total_len / numstrings) if numstrings else 0.0
    entropy = _entropy_from_counts(printable_counts)
    strings_per_kb = float(numstrings / (file_size / 1024.0)) if file_size else 0.0

    top_chars: List[Dict[str, Any]] = []
    if printable_counts.sum() > 0:
        top_indices = np.argsort(printable_counts)[::-1][:10]
        for idx in top_indices:
            count = int(printable_counts[idx])
            if count == 0:
                continue
            char = chr(idx + PRINTABLE_MIN)
            top_chars.append({"char": char, "count": count})

    longest_strings = [text for _, text in sorted(longest_heap, key=lambda item: item[0], reverse=True)]

    return {
        "numstrings": int(numstrings),
        "avlength": float(avlength),
        "printabledist": printable_counts.tolist(),
        "printables": int(printables),
        "entropy": float(entropy),
        "paths": int(paths),
        "urls": int(urls),
        "registry": int(registry),
        "MZ": int(mz),
        "strings_per_kb": strings_per_kb,
        "sample_urls": sample_urls,
        "sample_paths": sample_paths,
        "sample_registry": sample_registry,
        "sample_ips": sample_ips,
        "suspicious_strings": suspicious_samples,
        "longest_strings": longest_strings,
        "top_printable_chars": top_chars,
    }


def General(path: str) -> Dict[str, Any]:
    target = Path(path)
    size = target.stat().st_size if target.exists() else 0

    result: Dict[str, Any] = {
        "size": int(size),
        "vsize": 0,
        "has_debug": 0,
        "exports": 0,
        "imports": 0,
        "has_relocations": 0,
        "has_resources": 0,
        "has_signature": 0,
        "has_tls": 0,
        "symbols": 0,
    }

    binary = parse_pe(path)
    if binary is None:
        return result

    try:
        result["vsize"] = int(getattr(binary.optional_header, "sizeof_image", 0))
    except Exception:
        pass

    try:
        debug_entries = getattr(binary, "debug", None)
        result["has_debug"] = int(bool(debug_entries))
    except Exception:
        pass

    try:
        if getattr(binary, "has_exports", False):
            export = binary.get_export()
            entries = getattr(export, "entries", []) if export is not None else []
            result["exports"] = int(len(entries))
    except Exception:
        pass

    try:
        total = 0
        for lib in getattr(binary, "imports", []):
            total += len(getattr(lib, "entries", []))
        result["imports"] = int(total)
    except Exception:
        pass

    try:
        relocations = getattr(binary, "relocations", None)
        result["has_relocations"] = int(bool(relocations))
    except Exception:
        pass

    try:
        result["has_resources"] = int(
            getattr(binary, "has_resources", False)
            or getattr(binary, "resources", None) is not None
        )
    except Exception:
        pass

    try:
        signatures = getattr(binary, "signatures", None)
        result["has_signature"] = int(bool(signatures))
    except Exception:
        pass

    try:
        result["has_tls"] = int(
            getattr(binary, "has_tls", False)
            or getattr(binary, "tls", None) is not None
        )
    except Exception:
        pass

    try:
        result["symbols"] = int(getattr(binary.header, "numberof_symbols", 0))
    except Exception:
        pass

    return result


def Header(file_path: str) -> Dict[str, Any]:
    def _enum_name(value) -> str:
        try:
            return getattr(value, "name")
        except Exception:
            try:
                return str(value)
            except Exception:
                return ""

    def _characteristics_from_bitmask(bitmask: int, enum_cls) -> List[str]:
        names: List[str] = []
        try:
            for entry in enum_cls:
                try:
                    if bitmask & int(entry):
                        names.append(getattr(entry, "name", str(entry)))
                except Exception:
                    continue
        except Exception:
            pass
        return names

    def _dll_characteristics_names(opt_header) -> List[str]:
        dll_list = getattr(opt_header, "dll_characteristics_list", None)
        if dll_list:
            names: List[str] = []
            for entry in dll_list:
                try:
                    names.append(getattr(entry, "name", str(entry)))
                except Exception:
                    names.append(str(entry))
            return names
        bitmask = getattr(opt_header, "dll_characteristics", None)
        if bitmask is not None:
            enum_cls = getattr(lief.PE, "DLL_CHARACTERISTICS", getattr(lief.PE, "DllCharacteristics", None))
            if enum_cls is not None:
                return _characteristics_from_bitmask(int(bitmask), enum_cls)
        return []

    result: Dict[str, Any] = {
        "coff": {
            "timestamp": 0,
            "machine": "",
            "characteristics": [],
        },
        "optional": {
            "subsystem": "",
            "dll_characteristics": [],
            "magic": "",
            "major_image_version": 0,
            "minor_image_version": 0,
            "major_linker_version": 0,
            "minor_linker_version": 0,
            "major_operating_system_version": 0,
            "minor_operating_system_version": 0,
            "major_subsystem_version": 0,
            "minor_subsystem_version": 0,
            "sizeof_code": 0,
            "sizeof_headers": 0,
            "sizeof_heap_commit": 0,
        },
    }

    binary = parse_pe(file_path)
    if binary is None:
        return result

    try:
        header = binary.header
    except Exception:
        header = None

    if header is not None:
        try:
            timestamp = int(getattr(header, "time_date_stamp", 0))
            result["coff"]["timestamp"] = timestamp
        except Exception:
            pass

        try:
            machine = getattr(header, "machine", None)
            if machine is not None:
                result["coff"]["machine"] = _enum_name(machine)
            else:
                machine_value = getattr(header, "machine_type", None) or getattr(header, "machine_value", None)
                if machine_value is not None:
                    result["coff"]["machine"] = str(machine_value)
        except Exception:
            pass

        try:
            characteristics_list = getattr(header, "characteristics_list", None)
            if characteristics_list:
                result["coff"]["characteristics"] = [_enum_name(entry) for entry in characteristics_list]
            else:
                bitmask = int(getattr(header, "characteristics", 0))
                enum_cls = getattr(lief.PE.Header, "Characteristics", None)
                if enum_cls is not None and bitmask:
                    result["coff"]["characteristics"] = _characteristics_from_bitmask(bitmask, enum_cls)
        except Exception:
            pass

    try:
        optional = getattr(binary, "optional_header", None) or getattr(binary, "optionalHeader", None)
    except Exception:
        optional = None

    if optional is not None:
        try:
            subsystem = getattr(optional, "subsystem", None)
            if subsystem is not None:
                result["optional"]["subsystem"] = _enum_name(subsystem)
        except Exception:
            pass

        try:
            result["optional"]["dll_characteristics"] = _dll_characteristics_names(optional)
        except Exception:
            result["optional"]["dll_characteristics"] = []

        try:
            magic = getattr(optional, "magic", None)
            if magic is not None:
                result["optional"]["magic"] = _enum_name(magic)
            else:
                fallback = getattr(optional, "magic_value", None) or getattr(optional, "type", None)
                if fallback is not None:
                    result["optional"]["magic"] = str(fallback)
        except Exception:
            pass

        for name in [
            "major_image_version",
            "minor_image_version",
            "major_linker_version",
            "minor_linker_version",
            "major_operating_system_version",
            "minor_operating_system_version",
            "major_subsystem_version",
            "minor_subsystem_version",
        ]:
            try:
                value = getattr(optional, name, None)
                if value is not None:
                    result["optional"][name] = int(value)
            except Exception:
                pass

        try:
            sizeof_code = getattr(optional, "sizeof_code", None) or getattr(optional, "size_of_code", None)
            if sizeof_code is not None:
                result["optional"]["sizeof_code"] = int(sizeof_code)
        except Exception:
            pass

        try:
            sizeof_headers = getattr(optional, "sizeof_headers", None) or getattr(optional, "size_of_headers", None)
            if sizeof_headers is not None:
                result["optional"]["sizeof_headers"] = int(sizeof_headers)
        except Exception:
            pass

        try:
            sizeof_heap_commit = (
                getattr(optional, "sizeof_heap_commit", None)
                or getattr(optional, "size_of_heap_commit", None)
                or getattr(optional, "sizeofheapcommit", None)
            )
            if sizeof_heap_commit is not None:
                result["optional"]["sizeof_heap_commit"] = int(sizeof_heap_commit)
        except Exception:
            pass

    return result


def Sections(file_path: str) -> Dict[str, Any]:
    def _shannon_entropy_bytes(data_bytes: bytes) -> float:
        if not data_bytes:
            return 0.0
        arr = np.frombuffer(data_bytes, dtype=np.uint8)
        counts = np.bincount(arr, minlength=256)
        probs = counts[counts > 0] / counts.sum()
        return float(-(probs * np.log2(probs)).sum())

    def _section_props(section: lief.PE.Section) -> List[str]:
        props: List[str] = []

        try:
            if getattr(section, "size", 0) > 0 or getattr(section, "sizeof_raw_data", 0) > 0:
                props.append("CNT_INITIALIZED_DATA")
        except Exception:
            pass

        characteristics: List[str] = []
        try:
            if hasattr(section, "characteristics_list") and section.characteristics_list:
                characteristics = [getattr(entry, "name", str(entry)).upper() for entry in section.characteristics_list]
        except Exception:
            characteristics = []

        try:
            if not characteristics and hasattr(section, "characteristics"):
                bitmask = int(getattr(section, "characteristics", 0))
                for entry in lief.PE.SECTION_CHARACTERISTICS:
                    try:
                        if bitmask & int(entry):
                            characteristics.append(getattr(entry, "name", str(entry)).upper())
                    except Exception:
                        continue
        except Exception:
            pass

        try:
            if ("MEM_EXECUTE" in " ".join(characteristics)) or getattr(section, "has_characteristic", lambda _: False)(
                lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE
            ):
                if "MEM_EXECUTE" not in props:
                    props.append("MEM_EXECUTE")
        except Exception:
            pass

        try:
            if ("MEM_READ" in " ".join(characteristics)) or getattr(section, "has_characteristic", lambda _: False)(
                lief.PE.SECTION_CHARACTERISTICS.MEM_READ
            ):
                if "MEM_READ" not in props:
                    props.append("MEM_READ")
        except Exception:
            pass

        try:
            if ("MEM_WRITE" in " ".join(characteristics)) or getattr(section, "has_characteristic", lambda _: False)(
                lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE
            ):
                if "MEM_WRITE" not in props:
                    props.append("MEM_WRITE")
        except Exception:
            pass

        try:
            if any("CNT_CODE" in item or "CODE" in item for item in characteristics):
                if "CNT_CODE" not in props:
                    props.append("CNT_CODE")
            if any("UNINITIALIZED" in item or "CNT_UNINITIALIZED" in item for item in characteristics):
                if "CNT_UNINITIALIZED_DATA" not in props:
                    props.append("CNT_UNINITIALIZED_DATA")
        except Exception:
            pass

        if "CNT_INITIALIZED_DATA" not in props:
            try:
                if (
                    (getattr(section, "size", 0) > 0 or getattr(section, "sizeof_raw_data", 0) > 0)
                    and "CNT_UNINITIALIZED_DATA" not in props
                ):
                    props.insert(0, "CNT_INITIALIZED_DATA")
            except Exception:
                pass

        return props

    result: Dict[str, Any] = {
        "section": {"entry": "", "sections": []},
        "imports": {},
        "exports": [],
        "datadirectories": [],
    }

    binary = parse_pe(file_path)
    if binary is None:
        return result

    try:
        sections = []
        for sec in getattr(binary, "sections", []):
            try:
                name = getattr(sec, "name", "")
                name = (name or "").ljust(8)[:8]
            except Exception:
                name = ""

            try:
                size = int(
                    getattr(sec, "size", 0)
                    or getattr(sec, "sizeof_raw_data", 0)
                    or len(bytes(sec.content or []))
                )
            except Exception:
                try:
                    size = len(bytes(getattr(sec, "content", []) or []))
                except Exception:
                    size = 0

            try:
                vsize = int(getattr(sec, "virtual_size", 0) or getattr(sec, "vsize", 0))
            except Exception:
                vsize = 0

            try:
                content_bytes = bytes(getattr(sec, "content", []) or [])
                entropy = _shannon_entropy_bytes(content_bytes)
            except Exception:
                entropy = 0.0

            try:
                props = _section_props(sec)
            except Exception:
                props = []

            sections.append(
                {
                    "name": name,
                    "size": size,
                    "entropy": float(entropy),
                    "vsize": vsize,
                    "props": props,
                }
            )

        result["section"]["sections"] = sections
    except Exception:
        result["section"]["sections"] = []

    try:
        entrypoint = getattr(binary, "entrypoint", None)
        if entrypoint is None:
            entrypoint = getattr(binary, "entrypoint_rva", None)
        entry_name = ""
        if entrypoint is not None:
            for sec in getattr(binary, "sections", []):
                start = int(getattr(sec, "virtual_address", 0))
                vsize = int(getattr(sec, "virtual_size", 0) or getattr(sec, "vsize", 0))
                if start <= entrypoint < (start + vsize):
                    entry_name = (getattr(sec, "name", "") or "").ljust(8)[:8]
                    break
        result["section"]["entry"] = entry_name
    except Exception:
        result["section"]["entry"] = ""

    try:
        imports: Dict[str, List[str]] = {}
        for lib in getattr(binary, "imports", []):
            dll = getattr(lib, "name", "") or ""
            entries: List[str] = []
            for entry in getattr(lib, "entries", []):
                name = getattr(entry, "name", None) or getattr(entry, "symbol", None)
                if name is None:
                    ordinal = getattr(entry, "ordinal", None)
                    if ordinal is not None:
                        entries.append(str(ordinal))
                else:
                    entries.append(name if isinstance(name, str) else name.decode(errors="ignore"))
            imports[dll] = entries
        result["imports"] = imports
    except Exception:
        result["imports"] = {}

    try:
        exports: List[str] = []
        if getattr(binary, "has_exports", False):
            export_table = binary.get_export()
            for entry in getattr(export_table, "entries", []):
                name = getattr(entry, "name", None) or getattr(entry, "entry", None)
                if name:
                    exports.append(name if isinstance(name, str) else name.decode(errors="ignore"))
        result["exports"] = exports
    except Exception:
        result["exports"] = []

    try:
        directories: List[Dict[str, Any]] = []
        data_dirs = (
            getattr(binary, "data_directories", None)
            or getattr(binary.optional_header, "data_directory", None)
            or getattr(binary, "data_directory", None)
        )
        if data_dirs:
            try:
                for index, directory in enumerate(data_dirs):
                    if directory is None:
                        continue
                    name = _DATA_DIR_NAMES[index] if index < len(_DATA_DIR_NAMES) else getattr(directory, "type", str(index))
                    size = int(getattr(directory, "size", 0) or getattr(directory, "Size", 0) or 0)
                    address = int(getattr(directory, "rva", 0) or getattr(directory, "virtual_address", 0) or 0)
                    directories.append({"name": str(name), "size": size, "virtual_address": address})
            except Exception:
                try:
                    for key, directory in dict(data_dirs).items():
                        name = str(key)
                        size = int(getattr(directory, "size", 0) or getattr(directory, "Size", 0) or 0)
                        address = int(getattr(directory, "rva", 0) or getattr(directory, "virtual_address", 0) or 0)
                        directories.append({"name": name, "size": size, "virtual_address": address})
                except Exception:
                    directories = []
        else:
            try:
                for index, name in enumerate(_DATA_DIR_NAMES):
                    try:
                        directory = binary.optional_header.data_directory[index]
                        size = int(getattr(directory, "size", 0) or 0)
                        address = int(getattr(directory, "rva", 0) or getattr(directory, "virtual_address", 0) or 0)
                        directories.append({"name": name, "size": size, "virtual_address": address})
                    except Exception:
                        directories.append({"name": name, "size": 0, "virtual_address": 0})
            except Exception:
                directories = []
        result["datadirectories"] = directories
    except Exception:
        result["datadirectories"] = []

    return result
