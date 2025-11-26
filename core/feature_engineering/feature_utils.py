from __future__ import annotations
import hashlib
import heapq
from typing import Iterable, Dict, List, Any
from pathlib import Path
import re
import mmap

import lief
import numpy as np
from .pe_parser import parse_pe

# 可打印字符ASCII值
PRINTABLE_MIN = 0x20
PRINTABLE_MAX = 0x7E
PRINTABLE_RANGE = PRINTABLE_MAX - PRINTABLE_MIN + 1

# 正则表达式匹配
RE_PRINTABLE = re.compile(rb'[\x20-\x7e]{4,}')
RE_URL = re.compile(
    rb'(?:'
    rb'(?:https?|ftp)://[^\s/$.?#].\S*'
    rb'|'
    rb'www\.[^\s/]+\S*'
    rb'|'
    rb'[A-Za-z0-9.-]+\.(?:com|net|org|edu|gov|mil|info|io|biz|cn|ru|uk|de|jp|fr|au|br|it|nl|es)\S*'
    rb')',
    flags=re.IGNORECASE
)
RE_WIN_PATH = re.compile(
    rb'(?:'
    rb'[A-Za-z]:\\(?:[^\\\r\n<>:"/|?*]+\\)*[^\\\r\n<>:"/|?*]*'
    rb'|'
    rb'\\\\[^\s\\/:*?"<>|]+\\[^\s\\/:*?"<>|]+'
    rb')'
)
RE_REG = re.compile(
    rb'(?:HKEY_(?:CLASSES_ROOT|CURRENT_USER|LOCAL_MACHINE|USERS|CURRENT_CONFIG)\\[^\r\n\"\'\t]+)',
    flags=re.IGNORECASE
)
RE_MZ = re.compile(rb'MZ')
RE_IP = re.compile(
    rb'(?:'
    rb'(?:25[0-5]|2[0-4][0-9]|[01]?\d?\d)\.'
    rb'(?:25[0-5]|2[0-4][0-9]|[01]?\d?\d)\.'
    rb'(?:25[0-5]|2[0-4][0-9]|[01]?\d?\d)\.'
    rb'(?:25[0-5]|2[0-4][0-9]|[01]?\d?\d)'
    rb')'
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

# 表信息
_DATA_DIR_NAMES = [
    "EXPORT_TABLE", "IMPORT_TABLE", "RESOURCE_TABLE", "EXCEPTION_TABLE",
    "CERTIFICATE_TABLE", "BASE_RELOCATION_TABLE", "DEBUG", "ARCHITECTURE",
    "GLOBAL_PTR", "TLS_TABLE", "LOAD_CONFIG_TABLE", "BOUND_IMPORT",
    "IAT", "DELAY_IMPORT_DESCRIPTOR", "CLR_RUNTIME_HEADER"
]


def Hash_md5(file_path: str, size: int = 4 * 1024 * 1024) -> str:
    """
    分块取md5
    :param file_path:
    :param size:
    :return:
    """
    md5 = hashlib.md5()
    with open(file_path, 'rb') as file:
        while chunk := file.read(size):
            md5.update(chunk)

    return md5.hexdigest()


def Hash_sha256(file_path: str, size: int = 4 * 1024 * 1024) -> str:
    """
    分块取sha-256
    :param file_path:
    :param size:
    :return:
    """
    sha = hashlib.sha256()
    with open(file_path, 'rb') as file:
        while chunk := file.read(size):
            sha.update(chunk)

    return sha.hexdigest()


def Label(file_path: str) -> int:
    """
    打标签
    :param file_path:
    :return:
    """
    label = 1 if 'VirusShare' in file_path else 0

    return label



def ByteHistogram(pe_path: str, is_normalize: bool = False) -> np.ndarray:
    """
    字节直方图
    :param pe_path: pe文件路径
    :param is_normalize: 是否归一化，默认不归一化
    :return: 返回值numpy数组
    """
    with open(pe_path, 'rb') as f:
        data = f.read()

    arr = np.frombuffer(data, dtype=np.uint8)
    histogram = np.bincount(arr, minlength=256).astype(np.float32)

    if is_normalize and arr.size > 0:
        histogram /= arr.size

    return histogram


def ByteEntropyHistogram(pe_path: str, window_size: int = 2048) -> np.ndarray:
    """
    提取Byte-Entropy Histogtam特征
    :param pe_path: PE文件路径
    :param window_size: 滑动窗口大小（默认2048B）
    :return:
    """
    shape = (16, 16)
    histogram = np.zeros(shape, dtype=np.float32)
    with open(pe_path, 'rb') as file:
        data = file.read()

    length = len(data)
    if length < window_size:
        return histogram.flatten()

    data = np.frombuffer(data, dtype=np.uint8)

    step = window_size // 2
    for i in range(0, length - window_size + 1, step):
        window = data[i:i + window_size]
        if not window.size:
            continue
        # 获取平均字节值（使用浮点均值避免 uint8 溢出）
        argv_byte = float(window.mean(dtype=np.float64))
        byte_bin = min(int(argv_byte / 16), 15)
        # 计算信息熵
        counts = np.bincount(window, minlength=256)
        probs = counts[counts > 0] / float(len(window))
        entropy = -np.sum(probs * np.log2(probs))
        entropy_bin = min(int(entropy * 2), 15)

        histogram[byte_bin, entropy_bin] += 1

    return histogram.flatten()


def Strings(file_path) -> Dict:
    """提取文件中的可打印字符串统计与样本。"""

    def _entropy_from_counts(counts: np.ndarray) -> float:
        """Shannon 熵（基于可打印字符分布）。"""
        total = counts.sum()
        if total == 0:
            return 0.0
        p = counts[counts > 0] / total
        return float(-(p * np.log2(p)).sum())

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

    p = Path(file_path)
    file_size = p.stat().st_size if p.exists() else 0

    with open(p, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        data = mm[:]
        mz = len(RE_MZ.findall(data))

        for m in RE_PRINTABLE.finditer(data):
            segment = m.group(0)
            length = len(segment)
            numstrings += 1
            total_len += length

            arr = np.frombuffer(segment, dtype=np.uint8)
            mask = (arr >= PRINTABLE_MIN) & (arr <= PRINTABLE_MAX)
            if mask.any():
                vals = arr[mask] - PRINTABLE_MIN
                printable_counts += np.bincount(vals, minlength=PRINTABLE_RANGE)

            text = _decode(segment)
            if not text:
                continue

            lower_text = text.lower()
            if any(keyword in lower_text for keyword in SUSPICIOUS_STRING_KEYWORDS):
                if text not in suspicious_samples and len(suspicious_samples) < MAX_SUSPICIOUS_SAMPLES:
                    suspicious_samples.append(text)

            if len(longest_heap) < MAX_LONGEST_STRINGS:
                heapq.heappush(longest_heap, (length, text))
            else:
                if length > longest_heap[0][0]:
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
            ch = chr(idx + PRINTABLE_MIN)
            top_chars.append({"char": ch, "count": count})

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


def General(path: str) -> Dict:
    """
    使用 LIEF(0.16.6) + 你提供的 parse_pe 提取 EMBER 风格 general 字段。
    返回:
      {
        "size": int, "vsize": int,
        "has_debug": int, "exports": int, "imports": int,
        "has_relocations": int, "has_resources": int,
        "has_signature": int, "has_tls": int, "symbols": int
      }
    """
    p = Path(path)
    size = p.stat().st_size if p.exists() else 0

    out = {
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

    bin = parse_pe(path)
    if bin is None:
        return out  # 非PE/解析失败，按 EMBER 风格返回默认值

    # vsize (SizeOfImage)
    try:
        out["vsize"] = int(getattr(bin.optional_header, "sizeof_image", 0))
    except Exception:
        pass

    # has_debug
    try:
        dbg_list = getattr(bin, "debug", None)  # List[lief.PE.Debug]
        out["has_debug"] = int(bool(dbg_list))  # 非空即 1
    except Exception:
        pass

    # exports: 导出函数数量
    try:
        if getattr(bin, "has_exports", False):
            exp = bin.get_export()  # lief.PE.Export
            entries = getattr(exp, "entries", []) if exp is not None else []
            out["exports"] = int(len(entries))
    except Exception:
        pass

    # imports: 导入函数总数（所有 DLL 的 entries 合计）
    try:
        total = 0
        for lib in getattr(bin, "imports", []):  # List[lief.PE.Import]
            total += len(getattr(lib, "entries", []))
        out["imports"] = int(total)
    except Exception:
        pass

    # has_relocations
    try:
        relocs = getattr(bin, "relocations", None)
        out["has_relocations"] = int(bool(relocs))
    except Exception:
        pass

    # has_resources
    try:
        out["has_resources"] = int(
            getattr(bin, "has_resources", False) or getattr(bin, "resources", None) is not None
        )
    except Exception:
        pass

    # has_signature (Authenticode)
    try:
        sigs = getattr(bin, "signatures", None)  # List[lief.PE.Signature]
        out["has_signature"] = int(bool(sigs))
    except Exception:
        pass

    # has_tls
    try:
        out["has_tls"] = int(getattr(bin, "has_tls", False) or getattr(bin, "tls", None) is not None)
    except Exception:
        pass

    # symbols: COFF 符号表条目数
    try:
        out["symbols"] = int(getattr(bin.header, "numberof_symbols", 0))
    except Exception:
        pass

    return out


def Header(file_path: str) -> Dict:
    """
    提取 header.coff 与 header.optional（EMBER 风格）
    :param file_path: PE 文件路径
    :return: dict 对齐 EMBER 的 header 字段结构
    """

    def _enum_name(val) -> str:
        """尝试获取枚举的 name 属性或 str()，兼容性处理。"""
        try:
            return getattr(val, "name")
        except Exception:
            try:
                return str(val)
            except Exception:
                return ""

    def _characteristics_from_bitmask(bitmask: int, enum_cls) -> List[str]:
        """
        将 bitmask 展开为枚举名列表（兼容 LIEF 的枚举类）。
        enum_cls: 枚举类（如 lief.PE.Header.Characteristics）
        """
        out = []
        try:
            for e in enum_cls:
                try:
                    if bitmask & int(e):
                        name = getattr(e, "name", str(e))
                        out.append(name)
                except Exception:
                    continue
        except Exception:
            # 如果传入的不是枚举类（兼容性）
            pass
        return out

    def _dll_characteristics_names(opt_hdr) -> List[str]:
        """
        获取 DLL characteristics 的名列表，优先使用可能存在的 list 属性，
        否则从位掩码展开。
        """
        # 1) 优先考虑 optional_header.dll_characteristics_list
        dll_list = getattr(opt_hdr, "dll_characteristics_list", None)
        if dll_list:
            names = []
            for e in dll_list:
                try:
                    names.append(getattr(e, "name", str(e)))
                except Exception:
                    names.append(str(e))
            return names

        # 2) 兼容: 有时存在 bitmask 属性 optional_header.dll_characteristics
        bitmask = getattr(opt_hdr, "dll_characteristics", None)
        if bitmask is not None:
            # LIEF 的枚举类：lief.PE.DLL_CHARACTERISTICS
            return _characteristics_from_bitmask(int(bitmask), getattr(lief.PE, "DLL_CHARACTERISTICS",
                                                                       getattr(lief.PE, "DllCharacteristics", None)))

        # 3) 退化为空列表
        return []

    out = {
        "coff": {
            "timestamp": 0,
            "machine": "",
            "characteristics": []
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
            "sizeof_heap_commit": 0
        }
    }

    bin = parse_pe(file_path)
    if bin is None:
        return out

    # ------- COFF header -------
    try:
        hdr = bin.header  # lief.PE.Header
    except Exception:
        hdr = None

    if hdr is not None:
        # timestamp
        try:
            ts = int(getattr(hdr, "time_date_stamp", 0))
            out["coff"]["timestamp"] = ts
        except Exception:
            pass

        # machine
        try:
            m = getattr(hdr, "machine", None)
            if m is not None:
                out["coff"]["machine"] = _enum_name(m)
            else:
                # 兼容：可能有 numeric machine value
                mv = getattr(hdr, "machine_type", None) or getattr(hdr, "machine_value", None)
                if mv is not None:
                    out["coff"]["machine"] = str(mv)
        except Exception:
            pass

        # characteristics: 优先使用 characteristics_list，否则展开 bitmask
        try:
            chars_list = getattr(hdr, "characteristics_list", None)
            if chars_list:
                out["coff"]["characteristics"] = [_enum_name(c) for c in chars_list]
            else:
                # 用 bitmask 展开（hdr.characteristics）
                bitmask = int(getattr(hdr, "characteristics", 0))
                # LIEF 的枚举：lief.PE.Header.Characteristics
                enum_cls = None
                try:
                    enum_cls = lief.PE.Header.Characteristics
                except Exception:
                    # 兼容：某些版本枚举位置不同
                    enum_cls = getattr(lief.PE, "Header", None) and getattr(lief.PE.Header, "Characteristics", None)
                if enum_cls is not None and bitmask:
                    out["coff"]["characteristics"] = _characteristics_from_bitmask(bitmask, enum_cls)
        except Exception:
            pass

    # ------- OPTIONAL header -------
    try:
        opt = getattr(bin, "optional_header", None) or getattr(bin, "optionalHeader", None)
    except Exception:
        opt = None

    if opt is not None:
        # subsystem
        try:
            subs = getattr(opt, "subsystem", None)
            if subs is not None:
                out["optional"]["subsystem"] = _enum_name(subs)
        except Exception:
            pass

        # dll_characteristics -> list
        try:
            out["optional"]["dll_characteristics"] = _dll_characteristics_names(opt)
        except Exception:
            out["optional"]["dll_characteristics"] = []

        # magic (PE32 / PE32+)
        try:
            magic = getattr(opt, "magic", None)
            if magic is not None:
                out["optional"]["magic"] = _enum_name(magic)
            else:
                # 兼容：某些属性名为 'magic_value' 或 'type'
                mv = getattr(opt, "magic_value", None) or getattr(opt, "type", None)
                if mv is not None:
                    out["optional"]["magic"] = str(mv)
        except Exception:
            pass

        # version fields
        for name in ["major_image_version", "minor_image_version",
                     "major_linker_version", "minor_linker_version",
                     "major_operating_system_version", "minor_operating_system_version",
                     "major_subsystem_version", "minor_subsystem_version"]:
            try:
                val = getattr(opt, name, None)
                if val is None:
                    # 某些字段可能在 LIEF 名称中略有不同，如 major_linker_version -> linker_version
                    if name == "major_linker_version":
                        val = getattr(opt, "linker_version", None)
                    elif name == "minor_linker_version":
                        # try to parse if linker_version is tuple
                        val = getattr(opt, "minor_linker_version", None)
                out["optional"][name] = int(val) if val is not None else out["optional"][name]
            except Exception:
                pass

        # sizeof fields
        try:
            sc = getattr(opt, "sizeof_code", None)
            if sc is None:
                sc = getattr(opt, "size_of_code", None)
            out["optional"]["sizeof_code"] = int(sc) if sc is not None else out["optional"]["sizeof_code"]
        except Exception:
            pass

        try:
            sh = getattr(opt, "sizeof_headers", None)
            if sh is None:
                sh = getattr(opt, "size_of_headers", None)
            out["optional"]["sizeof_headers"] = int(sh) if sh is not None else out["optional"]["sizeof_headers"]
        except Exception:
            pass

        try:
            # 名称差异较大，尝试几种常见拼写
            shc = getattr(opt, "sizeof_heap_commit", None)
            if shc is None:
                shc = getattr(opt, "size_of_heap_commit", None)
                if shc is None:
                    shc = getattr(opt, "sizeofheapcommit", None)
            out["optional"]["sizeof_heap_commit"] = int(shc) if shc is not None else out["optional"][
                "sizeof_heap_commit"]
        except Exception:
            pass

    return out


def Sections(file_path: str) -> Dict[str, Any]:
    """
    节区信息,JSON
    :param file_path:
    :return:
    """

    def _shannon_entropy_bytes(data_bytes: bytes) -> float:
        if not data_bytes:
            return 0.0
        arr = np.frombuffer(data_bytes, dtype=np.uint8)
        counts = np.bincount(arr, minlength=256)
        probs = counts[counts > 0] / counts.sum()
        return float(-(probs * np.log2(probs)).sum())

    def _section_props(section: lief.PE.Section) -> List[str]:
        """
        返回类似 EMBER 的 section props 列表，例如：
        CNT_INITIALIZED_DATA, MEM_EXECUTE, MEM_READ, MEM_WRITE
        """
        props: List[str] = []

        # CNT_INITIALIZED_DATA if contains initialized data (non-zero raw size)
        try:
            # In EMBER "CNT_INITIALIZED_DATA" indicates initialized data presence.
            if getattr(section, "size", 0) > 0 or getattr(section, "sizeof_raw_data", 0) > 0:
                props.append("CNT_INITIALIZED_DATA")
        except Exception:
            pass

        # Memory permissions: map LIEF flags -> EMBER style names
        # LIEF has SECTION_CHARACTERISTICS or permissions / characteristics_list
        char_list = []
        try:
            # try characteristics_list first (list of enums)
            if hasattr(section, "characteristics_list") and section.characteristics_list:
                char_list = [getattr(c, "name", str(c)).upper() for c in section.characteristics_list]
        except Exception:
            char_list = []

        # Fallback: use bitmask field 'characteristics' if available
        try:
            if not char_list and hasattr(section, "characteristics"):
                bitmask = int(getattr(section, "characteristics", 0))
                for e in lief.PE.SECTION_CHARACTERISTICS:
                    try:
                        if bitmask & int(e):
                            char_list.append(getattr(e, "name", str(e)).upper())
                    except Exception:
                        continue
        except Exception:
            pass

        # Permissions: many LIEF builds also have .has_characteristic or .has_* helpers
        # We map common IMAGE_SCN flags to EMBER names:
        # IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE
        # We'll also check section.permissions if exists (lief.PE.SECTION_FLAGS)
        try:
            # MEM_EXECUTE
            if ("MEM_EXECUTE" in " ".join(char_list)) or getattr(section, "has_characteristic", lambda x: False)(
                    lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE):
                if "MEM_EXECUTE" not in props:
                    props.append("MEM_EXECUTE")
        except Exception:
            pass

        try:
            if ("MEM_READ" in " ".join(char_list)) or getattr(section, "has_characteristic", lambda x: False)(
                    lief.PE.SECTION_CHARACTERISTICS.MEM_READ):
                if "MEM_READ" not in props:
                    props.append("MEM_READ")
        except Exception:
            pass

        try:
            if ("MEM_WRITE" in " ".join(char_list)) or getattr(section, "has_characteristic", lambda x: False)(
                    lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE):
                if "MEM_WRITE" not in props:
                    props.append("MEM_WRITE")
        except Exception:
            pass

        # Sometimes flags names include CNT_CODE / CNT_UNINITIALIZED_DATA etc.
        try:
            if any("CNT_CODE" in c or "CODE" in c for c in char_list):
                if "CNT_CODE" not in props:
                    props.append("CNT_CODE")
            if any("UNINITIALIZED" in c or "CNT_UNINITIALIZED" in c for c in char_list):
                if "CNT_UNINITIALIZED_DATA" not in props:
                    props.append("CNT_UNINITIALIZED_DATA")
        except Exception:
            pass

        # Keep order consistent with EMBER-like examples
        # Ensure CNT_INITIALIZED_DATA present if no other indicators and section has raw data
        if "CNT_INITIALIZED_DATA" not in props:
            try:
                if (getattr(section, "size", 0) > 0 or getattr(section, "sizeof_raw_data",
                                                               0) > 0) and "CNT_UNINITIALIZED_DATA" not in props:
                    props.insert(0, "CNT_INITIALIZED_DATA")
            except Exception:
                pass

        return props

    out = {
        "section": {
            "entry": "",
            "sections": []
        },
        "imports": {},
        "exports": [],
        "datadirectories": []
    }

    bin = parse_pe(file_path)
    if bin is None:
        return out

    # --- sections ---
    try:
        sections_list = []
        for sec in getattr(bin, "sections", []):
            # name: LIEF may include padding; emulate EMBER trimming to 8 chars style
            try:
                name = getattr(sec, "name", "")
                # Keep visible ascii, but emulate EMBER's often padded names
                name = (name or "").ljust(8)[:8]
            except Exception:
                name = ""

            # raw size: prefer sizeof_raw_data or size
            try:
                size = int(
                    getattr(sec, "size", 0) or getattr(sec, "sizeof_raw_data", 0) or len(bytes(sec.content or [])))
            except Exception:
                # fallback: compute from content
                try:
                    size = len(bytes(getattr(sec, "content", []) or []))
                except Exception:
                    size = 0

            # vsize: virtual size
            try:
                vsize = int(
                    getattr(sec, "virtual_size", 0) or getattr(sec, "vsize", 0) or getattr(sec, "virtual_size", 0))
            except Exception:
                vsize = 0

            # entropy: compute from raw section data
            try:
                content_bytes = bytes(getattr(sec, "content", []) or [])
                entropy = _shannon_entropy_bytes(content_bytes)
            except Exception:
                entropy = 0.0

            # props
            try:
                props = _section_props(sec)
            except Exception:
                props = []

            sections_list.append({
                "name": name,
                "size": size,
                "entropy": float(entropy),
                "vsize": vsize,
                "props": props
            })

        out["section"]["sections"] = sections_list
    except Exception:
        out["section"]["sections"] = []

    # determine entry: section that contains entrypoint RVA
    try:
        ep_rva = getattr(bin, "entrypoint", None)
        if ep_rva is None:
            # some LIEF versions: bin.entrypoint_rva
            ep_rva = getattr(bin, "entrypoint_rva", None)
        entry_section_name = ""
        if ep_rva is not None:
            for sec in getattr(bin, "sections", []):
                start = int(getattr(sec, "virtual_address", 0) or getattr(sec, "virtual_address", 0))
                vsize = int(getattr(sec, "virtual_size", 0) or getattr(sec, "vsize", 0))
                if start <= ep_rva < (start + vsize):
                    entry_section_name = (getattr(sec, "name", "") or "").ljust(8)[:8]
                    break
        out["section"]["entry"] = entry_section_name
    except Exception:
        out["section"]["entry"] = ""

    # --- imports ---
    try:
        imports = {}
        for lib in getattr(bin, "imports", []):
            dll = getattr(lib, "name", "") or ""
            funcs = []
            for e in getattr(lib, "entries", []):
                # e.name may be None if imported by ordinal
                n = getattr(e, "name", None) or getattr(e, "symbol", None) or None
                if n is None:
                    # fallback to ordinal if present
                    ordv = getattr(e, "ordinal", None)
                    if ordv is not None:
                        funcs.append(str(ordv))
                else:
                    funcs.append(n if isinstance(n, str) else n.decode(errors="ignore"))
            imports[dll] = funcs
        out["imports"] = imports
    except Exception:
        out["imports"] = {}

    # --- exports ---
    try:
        exps = []
        if getattr(bin, "has_exports", False):
            exp = bin.get_export()
            for e in getattr(exp, "entries", []):
                name = getattr(e, "name", None) or getattr(e, "entry", None) or None
                if name:
                    exps.append(name if isinstance(name, str) else name.decode(errors="ignore"))
        out["exports"] = exps
    except Exception:
        out["exports"] = []

    # --- data directories ---
    try:
        dd = []
        # LIEF provides optional_header.data_directory or bin.data_directories
        data_dirs = getattr(bin, "data_directories", None) or getattr(bin.optional_header, "data_directory",
                                                                      None) or getattr(bin, "data_directory", None)
        # Try to iterate through a predictable set: LIEF may represent differently; we'll use known names list
        if data_dirs:
            # If it's dict-like keyed by enum, handle accordingly
            try:
                # some LIEF versions return list of DataDirectory objects in same order
                for i, d in enumerate(data_dirs):
                    if d is None:
                        continue
                    name = _DATA_DIR_NAMES[i] if i < len(_DATA_DIR_NAMES) else getattr(d, "type", str(i))
                    size = int(getattr(d, "size", 0) or getattr(d, "Size", 0) or 0)
                    va = int(getattr(d, "rva", 0) or getattr(d, "virtual_address", 0) or 0)
                    dd.append({"name": str(name), "size": size, "virtual_address": va})
            except Exception:
                # fallback: maybe data_dirs is a dict mapping names to entries
                try:
                    for key, d in dict(data_dirs).items():
                        name = str(key)
                        size = int(getattr(d, "size", 0) or getattr(d, "Size", 0) or 0)
                        va = int(getattr(d, "rva", 0) or getattr(d, "virtual_address", 0) or 0)
                        dd.append({"name": name, "size": size, "virtual_address": va})
                except Exception:
                    dd = []
        else:
            # best-effort: iterate IMAGE_DIRECTORY_ENTRY enum
            try:
                for idx, nm in enumerate(_DATA_DIR_NAMES):
                    try:
                        d = bin.optional_header.data_directory[idx]
                        size = int(getattr(d, "size", 0) or 0)
                        va = int(getattr(d, "rva", 0) or getattr(d, "virtual_address", 0) or 0)
                        dd.append({"name": nm, "size": size, "virtual_address": va})
                    except Exception:
                        dd.append({"name": nm, "size": 0, "virtual_address": 0})
            except Exception:
                dd = []
        out["datadirectories"] = dd
    except Exception:
        out["datadirectories"] = []

    return out

