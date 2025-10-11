
#!/usr/bin/env python3
"""LightGBM-based model prediction utilities used by the GUI."""

from __future__ import annotations

import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

# 将项目根加入 sys.path（以便脚本独立运行时也能 import core.*）
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:  # pragma: no cover - optional dependency in tests
    import lightgbm as lgb
except Exception as exc:  # pragma: no cover - provide helpful guidance
    raise ImportError("请先安装 lightgbm: pip install lightgbm") from exc

import numpy as np

from core.feature_engineering import extract_features, vectorize_features

PE_SUFFIXES = {".exe", ".dll", ".sys", ".bin", ".scr", ".ocx"}
DEFAULT_MODEL = ROOT / "model.txt"
MAX_TO_SCAN = 1500
DEFAULT_THRESHOLD = 0.0385

SUSPICIOUS_API_HINTS: Dict[str, str] = {
    "virtualalloc": "调用 VirtualAlloc 在内存中划分可执行区域，常见于自解压或恶意注入。",
    "virtualprotect": "调用 VirtualProtect 修改页面权限，可能用于执行自解密代码。",
    "writeprocessmemory": "能够向其他进程写入数据，常见于进程注入。",
    "createremotethread": "创建远程线程执行外部代码，典型的恶意行为。",
    "setthreadcontext": "修改线程上下文，可能用于线程劫持。",
    "shellexecute": "通过 ShellExecute 执行系统命令。",
    "winexec": "通过 WinExec 执行命令行或外部程序。",
    "urldownloadtofile": "可从网络下载额外的有效载荷。",
    "internetopen": "初始化 WinINet 网络通信。",
    "internetreadfile": "读取网络资源内容。",
    "ftpgetfile": "FTP 文件下载行为。",
    "regsetvalue": "修改注册表键值，可能用于持久化。",
    "regcreatekey": "创建注册表键值，可能用于持久化。",
    "cryptencrypt": "使用 CryptoAPI 进行加密，可能隐藏通信内容。",
    "cryptimportkey": "导入密钥，可能用于自定义加密流程。",
    "addvectoredexceptionhandler": "注册异常处理器，常被用来隐藏控制流。",
}

BENIGN_API_HINTS: Dict[str, str] = {
    "user32": "大量使用 GUI 相关 API，符合常见应用行为。",
    "gdi32": "包含图形绘制相关 API，常见于图形界面程序。",
    "kernel32.getmodulehandle": "常规的模块查询调用。",
    "advapi32.regopenkey": "标准的注册表读取操作。",
}

PACKER_SECTION_KEYWORDS = [
    "upx",
    "themida",
    "aspack",
    "mpress",
    "kkrunchy",
    "petite",
    "pecompact",
    "fsg",
    "enigma",
    "obsidium",
]



@dataclass(frozen=True)
class PredictionLog:
    """Structured log emitted during prediction."""

    type: str
    message: str = ""
    index: int = 0
    total: int = 0
    extra: Dict[str, object] | None = None


def collect_pe_files(target: Path) -> List[Path]:
    """Collect PE files from a file or directory."""
    if target.is_file():
        return [target]
    if not target.exists() or not target.is_dir():
        raise FileNotFoundError(f"指定路径不存在或不是目录: {target}")

    files: List[Path] = []
    for p in target.rglob("*"):
        if p.is_file() and p.suffix.lower() in PE_SUFFIXES:
            files.append(p)
    return files


def _predict_single(booster: "lgb.Booster", file_path: Path, threshold: float) -> Tuple[float, str]:
    features = extract_features(file_path)
    vector = vectorize_features(features)
    arr = np.asarray(vector, dtype=np.float32).reshape(1, -1)
    prob = float(booster.predict(arr)[0])
    verdict = "恶意" if prob >= threshold else "良性"
    return prob, verdict


def _display_probability(prob: float, threshold: float) -> float:
    """Map raw model probability to a user friendly percentage.

    The mapping guarantees:
    * values grow strictly as the raw probability increases;
    * a score equal to the threshold is rendered as ``50.0001`` percent;
    * the displayed percentage never reaches 100.
    """

    # Normalise the probability relative to the decision threshold so that
    # values above the threshold scale towards ``1`` and values below it towards
    # ``0``.  A logarithmic curve provides a gentle growth rate while preserving
    # monotonicity.
    if prob >= threshold:
        # Map the ``[threshold, 1]`` range to ``[0, 1]`` and apply a logarithmic
        # easing so that confidence rises slowly for values just above the
        # threshold and accelerates only for much higher scores.
        span = max(1e-9, 1.0 - threshold)
        ratio = (prob - threshold) / span
        # ``scale_pos`` controls how aggressively the tail grows; a value of ``9``
        # keeps the increase close to logarithmic while ensuring the maximum
        # score remains bounded well below 100%.
        scale_pos = 9.0
        gain = math.log1p(scale_pos * min(ratio, 1.0)) / math.log1p(scale_pos)
        percentage = 50.0001 + gain * 49.9997
    else:
        # Symmetrically scale values below the threshold.  The logarithmic
        # profile keeps the perceived risk low until the score drops
        # substantially below the decision boundary.
        span = max(1e-9, threshold)
        ratio = (threshold - prob) / span
        scale_neg = 9.0
        reduction = math.log1p(scale_neg * min(ratio, 1.0)) / math.log1p(scale_neg)
        percentage = 50.0001 - reduction * 49.9997

    return min(99.9999, max(0.0001, percentage))


def _analyse_features_for_explanation(features: Dict[str, Any]) -> Dict[str, Any]:
    general = dict(features.get("general") or {})
    strings = dict(features.get("strings") or {})
    section_info = features.get("section") or {}
    sections = list(section_info.get("sections") or [])
    imports = features.get("imports") or {}
    header = features.get("header") or {}
    coff_header = dict((header.get("coff") or {}))
    optional_header = dict((header.get("optional") or {}))
    exports = list(features.get("exports") or [])
    data_directories = list(features.get("datadirectories") or [])

    total_imports = 0
    suspicious_hits: List[Dict[str, str]] = []
    benign_hits: List[str] = []

    for dll, funcs in imports.items():
        for func in funcs:
            if not func:
                continue
            total_imports += 1
            lowered = f"{dll}.{func}".lower()
            for key, desc in SUSPICIOUS_API_HINTS.items():
                if key in lowered:
                    suspicious_hits.append({
                        "api": f"{dll}!{func}",
                        "hint": desc,
                    })
                    break
            else:
                for key, desc in BENIGN_API_HINTS.items():
                    if key in lowered:
                        benign_hits.append(f"{dll}!{func}")
                        break

    high_entropy_sections: List[Dict[str, Any]] = []
    packer_sections: List[str] = []
    entropy_values: List[float] = []
    for sec in sections:
        entropy = float(sec.get("entropy", 0.0) or 0.0)
        entropy_values.append(entropy)
        if entropy >= 7.0 and (sec.get("size") or 0) > 0:
            sec_name = str(sec.get("name", "")).strip()
            high_entropy_sections.append({
                "name": sec_name,
                "entropy": entropy,
                "size": int(sec.get("size", 0) or 0),
            })
        sec_name_lower = str(sec.get("name", "")).lower()
        if any(keyword in sec_name_lower for keyword in PACKER_SECTION_KEYWORDS):
            packer_sections.append(sec_name_lower.strip())

    avg_entropy = sum(entropy_values) / len(entropy_values) if entropy_values else 0.0

    # Section overview sorted by physical size (fall back to virtual size).
    def _section_size(entry: Dict[str, Any]) -> int:
        try:
            return int(entry.get("size", 0) or 0)
        except Exception:
            try:
                return int(entry.get("virtual_size", 0) or 0)
            except Exception:
                return 0

    sections_sorted = sorted(sections, key=_section_size, reverse=True)
    section_overview: List[Dict[str, Any]] = []
    for sec in sections_sorted[:10]:
        section_overview.append(
            {
                "name": str(sec.get("name", "")).strip() or "<unnamed>",
                "size": int(sec.get("size", 0) or 0),
                "virtual_size": int(sec.get("virtual_size", 0) or 0),
                "entropy": float(sec.get("entropy", 0.0) or 0.0),
                "characteristics": list(sec.get("characteristics", []) or []),
            }
        )

    # Import statistics grouped per DLL for richer explanations.
    dll_usage: List[Dict[str, Any]] = []
    for dll, funcs in imports.items():
        dll_usage.append({
            "dll": dll,
            "count": len(funcs or []),
        })
    dll_usage.sort(key=lambda item: item["count"], reverse=True)

    risk_score = 0.0
    risk_factors: List[Dict[str, Any]] = []
    mitigations: List[Dict[str, Any]] = []

    def _add_risk(condition: bool, weight: float, title: str, detail: str) -> None:
        nonlocal risk_score
        if condition and weight > 0:
            risk_score += weight
            risk_factors.append({"title": title, "weight": weight, "detail": detail})

    def _add_mitigation(condition: bool, title: str, detail: str) -> None:
        if condition:
            mitigations.append({"title": title, "detail": detail})

    suspicious_count = len(suspicious_hits)
    high_entropy_count = len(high_entropy_sections)
    url_strings = summary_url_strings = int(strings.get("urls", 0) or 0)
    registry_strings = summary_registry_strings = int(strings.get("registry", 0) or 0)
    printable_strings = int(strings.get("printables", 0) or 0)
    suspicious_string_samples = list(strings.get("suspicious_strings", []) or [])

    _add_risk(
        suspicious_count > 0,
        min(3.0, 1.2 + 0.35 * min(suspicious_count, 8)),
        "高风险 API 调用",
        f"命中 {suspicious_count} 个高风险 API，可能具备注入、下载或加密能力。",
    )
    _add_risk(
        high_entropy_count > 0,
        min(2.5, 1.0 + 0.3 * min(high_entropy_count, 6)),
        "节区熵值异常",
        f"检测到 {high_entropy_count} 个高熵节区，疑似包含压缩或加密载荷。",
    )
    _add_risk(
        not bool(general.get("has_signature")),
        1.2,
        "缺少数字签名",
        "文件未发现 Authenticode 签名，可信度下降。",
    )
    _add_risk(
        url_strings >= 25,
        1.4 if url_strings >= 100 else 0.8,
        "可疑网络通信字符串",
        f"字符串中包含 {url_strings} 个 URL 片段，可能用于联络 C2 或下载载荷。",
    )
    _add_risk(
        registry_strings >= 5,
        1.1 if registry_strings >= 20 else 0.6,
        "注册表操作痕迹",
        f"检测到 {registry_strings} 个注册表路径字符串，可能试图修改系统配置。",
    )
    _add_risk(
        general.get("imports", 0) and general.get("imports", 0) > 200,
        0.8,
        "导入函数数量异常",
        f"导入函数总数达到 {general.get('imports')}，远高于常规应用平均水平。",
    )
    _add_risk(
        general.get("exports", 0) == 0 and general.get("imports", 0) > 0 and printable_strings < 50,
        0.5,
        "导出缺失但包含大量代码",
        "文件没有导出函数却导入大量 API，常见于隐蔽的执行主体。",
    )
    _add_risk(
        bool(suspicious_string_samples),
        min(1.5, 0.6 + 0.2 * len(suspicious_string_samples)),
        "可疑命令行或执行脚本",
        "检测到疑似命令行/脚本片段，可能用于横向移动或持久化。",
    )
    entry_section = str(section_info.get("entry") or "").strip()
    _add_risk(
        bool(entry_section) and entry_section.lower() not in {".text", "text"},
        0.6,
        "入口点位于非常规节区",
        f"程序入口位于 `{entry_section or '未知'}` 节区，可能通过壳或自定义载入方式隐藏。",
    )
    _add_risk(
        bool(packer_sections),
        min(1.8, 0.9 + 0.3 * len(set(packer_sections))),
        "节区名称疑似壳特征",
        "节区名包含常见壳标识，可能进行了加壳或混淆。",
    )

    timestamp = int(coff_header.get("timestamp", 0) or 0)
    if timestamp <= 0:
        _add_risk(True, 0.4, "编译时间异常", "PE 头部时间戳为 0，可能被篡改以规避检测。")

    # Positive indicators.
    _add_mitigation(bool(general.get("has_signature")), "检测到数字签名", "Authenticode 签名可提升可信度，但仍需验证证书链。")
    _add_mitigation(bool(benign_hits), "常见系统 API", f"大量导入 {len(benign_hits)} 个 GUI/系统相关 API，符合常见应用行为。")
    _add_mitigation(not high_entropy_sections, "节区熵值平稳", "未检测到高熵节区，代码段分布均衡。")
    _add_mitigation(bool(general.get("has_tls")), "存在 TLS 数据目录", "包含 TLS 初始化数据，常见于正规受保护程序。")
    _add_mitigation(bool(exports), "存在导出函数", f"检测到 {len(exports)} 个导出函数，可用于合法 API 暴露。")

    risk_score = min(10.0, round(risk_score, 2))
    if risk_score >= 6.0:
        risk_level = "高风险"
    elif risk_score >= 3.0:
        risk_level = "中等风险"
    else:
        risk_level = "低风险"

    active_data_directories = [
        {
            "name": str(entry.get("name", "")),
            "size": int(entry.get("size", 0) or 0),
            "virtual_address": int(entry.get("virtual_address", 0) or 0),
        }
        for entry in data_directories
        if entry and int(entry.get("size", 0) or 0) > 0
    ]

    summary = {
        "general": general,
        "strings": strings,
        "total_imports": total_imports,
        "suspicious_api_hits": suspicious_hits,
        "benign_api_hits": benign_hits,
        "high_entropy_sections": high_entropy_sections,
        "average_entropy": avg_entropy,
        "url_strings": summary_url_strings,
        "registry_strings": summary_registry_strings,
        "path_strings": int(strings.get("paths", 0) or 0),
        "printable_strings": int(strings.get("printables", 0) or 0),
        "string_entropy": float(strings.get("entropy", 0.0) or 0.0),
        "strings_per_kb": float(strings.get("strings_per_kb", 0.0) or 0.0),
        "string_samples": {
            "urls": list(strings.get("sample_urls", []) or []),
            "paths": list(strings.get("sample_paths", []) or []),
            "registry": list(strings.get("sample_registry", []) or []),
            "ips": list(strings.get("sample_ips", []) or []),
            "suspicious": suspicious_string_samples,
            "longest": list(strings.get("longest_strings", []) or []),
            "top_chars": list(strings.get("top_printable_chars", []) or []),
        },
        "section_overview": section_overview,
        "dll_usage": dll_usage,
        "section_count": len(sections),
        "entry_section": entry_section,
        "packer_sections": packer_sections,
        "header": {
            "timestamp": timestamp,
            "machine": coff_header.get("machine", ""),
            "characteristics": list(coff_header.get("characteristics", []) or []),
            "subsystem": optional_header.get("subsystem", ""),
            "dll_characteristics": list(optional_header.get("dll_characteristics", []) or []),
            "sizeof_code": int(optional_header.get("sizeof_code", 0) or 0),
            "sizeof_headers": int(optional_header.get("sizeof_headers", 0) or 0),
        },
        "exports": exports,
        "data_directories": data_directories,
        "active_data_directories": active_data_directories,
        "risk_assessment": {
            "score": risk_score,
            "level": risk_level,
            "factors": risk_factors,
            "mitigations": mitigations,
        },
    }

    return summary


def _build_reasoning(verdict: str, summary: Dict[str, Any]) -> Dict[str, Any]:
    bullets: List[str] = []
    general = summary.get("general", {})
    total_imports = summary.get("total_imports", 0)
    suspicious_hits = summary.get("suspicious_api_hits", [])
    benign_hits = summary.get("benign_api_hits", [])
    high_entropy_sections = summary.get("high_entropy_sections", [])
    risk_info = summary.get("risk_assessment", {})
    risk_level = risk_info.get("level")
    risk_score = risk_info.get("score")
    string_samples = summary.get("string_samples", {})
    suspicious_strings = string_samples.get("suspicious", []) if isinstance(string_samples, dict) else []
    packer_sections = summary.get("packer_sections", [])
    entry_section = summary.get("entry_section")

    has_signature = bool(general.get("has_signature"))
    has_tls = bool(general.get("has_tls"))
    url_strings = summary.get("url_strings", 0)
    registry_strings = summary.get("registry_strings", 0)

    if verdict == "恶意":
        if risk_level:
            bullets.append(f"综合风险评估为 {risk_level} (得分 {risk_score:.1f}/10)。")
        if suspicious_hits:
            highlighted = ", ".join(hit["api"] for hit in suspicious_hits[:5])
            bullets.append(f"导入了高风险 API：{highlighted}。")
        if high_entropy_sections:
            sections_desc = ", ".join(
                f"{sec['name']} (熵 {sec['entropy']:.2f})" for sec in high_entropy_sections[:3]
            )
            bullets.append(f"存在高熵节区，可能包含压缩或加密代码：{sections_desc}。")
        if not has_signature:
            bullets.append("缺少数字签名，降低可信度。")
        if url_strings:
            bullets.append(f"字符串中包含 {url_strings} 个 URL 片段，疑似具备网络通信能力。")
        if registry_strings:
            bullets.append(f"检测到 {registry_strings} 个注册表路径字符串，可能修改系统配置。")
        if suspicious_strings:
            bullets.append("发现疑似命令行或脚本片段，例如：" + "; ".join(suspicious_strings[:3]) + "。")
        if packer_sections:
            bullets.append("节区名称包含常见壳标识，疑似经过加壳处理。")
        if not bullets:
            bullets.append("模型判定得分显著高于阈值，整体特征与恶意样本高度相似。")
        headline = "模型认为该文件可能为恶意样本。"
    else:
        if risk_level:
            bullets.append(f"综合风险评估为 {risk_level} (得分 {risk_score:.1f}/10)。")
        if has_signature:
            bullets.append("文件包含数字签名，提升可信度。")
        if total_imports and total_imports < 50:
            bullets.append(f"导入函数数量较少（共 {total_imports} 个），符合轻量级应用特征。")
        if benign_hits:
            sample = ", ".join(benign_hits[:5])
            bullets.append(f"导入集中于常见 GUI/API：{sample}。")
        if not high_entropy_sections:
            bullets.append("未发现高熵节区，代码区分布平稳。")
        if not bullets:
            bullets.append("模型得分低于阈值，整体行为与已知良性样本相似。")
        if has_tls:
            bullets.append("包含 TLS 数据目录，常见于正规受保护程序。")
        if entry_section:
            bullets.append(f"入口点位于 `{entry_section}` 节区，符合常见的程序结构。")
        headline = "模型认为该文件更可能为良性样本。"

    return {"headline": headline, "bullets": bullets}


def MODEL_PREDICT(
    input_path: str,
    output_dir: Optional[str] = None,
    model_path: Optional[str] = None,
    threshold: float = DEFAULT_THRESHOLD,
    max_to_scan: int = MAX_TO_SCAN,
) -> Iterator[PredictionLog]:
    """Run model prediction for PE files under ``input_path``.

    Parameters
    ----------
    input_path:
        File or directory to scan.
    output_dir:
        Optional directory reserved for future extensions.  The current
        implementation keeps prediction results in memory only and does not
        write any files.
    model_path:
        Optional custom LightGBM model path.  Defaults to ``model.txt`` at the
        repository root.
    threshold:
        Probability threshold distinguishing malicious vs benign.
    max_to_scan:
        Maximum number of files to analyse in one run.

    Yields
    ------
    PredictionLog
        Structured log entries that describe progress for GUI display.
    """

    target = Path(input_path).expanduser().resolve()
    output_root: Optional[Path] = None
    if output_dir:
        output_root = Path(output_dir).expanduser().resolve()
        output_root.mkdir(parents=True, exist_ok=True)

    model_file = Path(model_path).expanduser().resolve() if model_path else DEFAULT_MODEL
    if not model_file.exists():
        raise FileNotFoundError(f"未找到模型文件: {model_file}")

    files = collect_pe_files(target)
    total_files = min(len(files), max_to_scan)
    files = files[:total_files]

    yield PredictionLog(
        type="start",
        message=f"开始扫描 {target}\n使用模型 {model_file}",
        total=total_files,
        extra={"output_dir": str(output_root) if output_root else None},
    )

    if total_files == 0:
        yield PredictionLog(
            type="finished",
            message="未找到任何可识别的 PE 文件。",
            total=0,
            extra={"output": None, "processed": 0, "malicious": 0},
        )
        return

    booster = lgb.Booster(model_file=str(model_file))
    processed = 0
    malicious = 0

    for idx, file_path in enumerate(files, 1):
        try:
            prob, verdict = _predict_single(booster, file_path, threshold)
            display_prob = _display_probability(prob, threshold)
            processed += 1
            if verdict == "恶意":
                malicious += 1
            message = (
                f"{idx}/{total_files} {file_path} -> 恶意概率: {display_prob:.6f}% "
                # f"({verdict}, 恶意概率 {display_prob:.4f}%)"
            )
            log_type = "progress"
        except Exception as exc:  # pragma: no cover - runtime feedback
            message = f"{idx}/{total_files} {file_path} -> 预测失败: {exc}"
            log_type = "error"
        yield PredictionLog(type=log_type, message=message, index=idx, total=total_files)

    if processed:
        summary_msg = (
            f"预测完成，共处理 {processed}/{total_files} 个文件，其中 {malicious} 个被判定为恶意。"
        )
    else:
        summary_msg = "没有成功的预测结果。"

    yield PredictionLog(
        type="finished",
        message=summary_msg,
        total=total_files,
        extra={
            "output": None,
            "processed": processed,
            "malicious": malicious,
            "failed": total_files - processed,
        },
    )


def predict_file_with_features(
    file_path: str,
    model_path: Optional[str] = None,
    threshold: float = DEFAULT_THRESHOLD,
) -> Dict[str, Any]:
    target = Path(file_path).expanduser().resolve()
    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"未找到需要分析的文件: {target}")

    model_file = Path(model_path).expanduser().resolve() if model_path else DEFAULT_MODEL
    if not model_file.exists():
        raise FileNotFoundError(f"未找到模型文件: {model_file}")

    features = extract_features(target)
    vector = vectorize_features(features)
    arr = np.asarray(vector, dtype=np.float32).reshape(1, -1)

    booster = lgb.Booster(model_file=str(model_file))
    prob = float(booster.predict(arr)[0])
    verdict = "恶意" if prob >= threshold else "良性"
    display_prob = _display_probability(prob, threshold)

    summary = _analyse_features_for_explanation(features)
    reasoning = _build_reasoning(verdict, summary)

    return {
        "file_path": str(target),
        "probability": prob,
        "display_probability": display_prob,
        "threshold": threshold,
        "verdict": verdict,
        "model_path": str(model_file),
        "features": features,
        "summary": summary,
        "reasoning": reasoning,
    }


def main() -> None:  # pragma: no cover - manual execution helper
    import argparse

    parser = argparse.ArgumentParser(description="批量预测PE文件是否恶意")
    parser.add_argument("input", help="待扫描的文件或目录")
    parser.add_argument("output", help="结果保存目录")
    parser.add_argument("--model", help="LightGBM模型路径", default=None)
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    parser.add_argument("--max", type=int, default=MAX_TO_SCAN)
    args = parser.parse_args()

    for log in MODEL_PREDICT(
        args.input,
        args.output,
        model_path=args.model,
        threshold=args.threshold,
        max_to_scan=args.max,
    ):
        if log.message:
            print(log.message)


if __name__ == "__main__":  # pragma: no cover - CLI entry
    main()