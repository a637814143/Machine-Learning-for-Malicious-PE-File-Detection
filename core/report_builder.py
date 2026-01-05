"""Shared helpers for producing markdown detection reports."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from collections.abc import Iterable as IterableABC
from typing import Any, Iterable, Sequence


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _to_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _format_table(rows: Iterable[Sequence[str]]) -> list[str]:
    return ["| " + " | ".join(row) + " |" for row in rows]


def _confidence_label(probability: float, threshold: float) -> str:
    margin = abs(probability - threshold)
    if margin >= 0.25:
        return "非常高"
    if margin >= 0.15:
        return "较高"
    if margin >= 0.07:
        return "中等"
    return "谨慎"


def _normalise_entries(entries: Any) -> list[Any]:
    if not entries:
        return []
    if isinstance(entries, IterableABC) and not isinstance(entries, (str, bytes, dict)):
        return list(entries)
    return [entries]


def _stringify_value(value: Any) -> str:
    if isinstance(value, dict):
        return ", ".join(f"{k}={_stringify_value(v)}" for k, v in value.items())
    if isinstance(value, (list, tuple, set)):
        return ", ".join(_stringify_value(v) for v in value)
    return str(value)


def _summarise_dynamic(dynamic: dict[str, Any]) -> dict[str, Any]:
    if isinstance(dynamic, dict) and isinstance(dynamic.get("events"), dict):
        return _summarise_dynamic_v2(dynamic)
    return _summarise_dynamic_v1(dynamic)


def _summarise_dynamic_v1(dynamic: dict[str, Any]) -> dict[str, Any]:
    mapping = {
        "file_operations": ("文件操作", 0.25, 12),
        "network_activity": ("网络通信", 0.6, 12),
        "registry_changes": ("注册表改动", 0.35, 12),
        "process_creations": ("进程创建", 0.5, 10),
    }

    counts: list[tuple[str, int]] = []
    highlights: list[str] = []
    score = 0.0
    total_events = 0

    for key, (title, weight, cap) in mapping.items():
        entries = _normalise_entries(dynamic.get(key))
        count = len(entries)
        counts.append((title, count))
        total_events += count
        score += min(count, cap) * weight
        for entry in entries[: min(3, len(entries))]:
            highlights.append(f"{title}: {_stringify_value(entry)}")

    api_calls = _normalise_entries(dynamic.get("api_calls"))
    if api_calls:
        total_events += len(api_calls)
        score += min(len(api_calls), 25) * 0.1

    errors = [
        _stringify_value(entry) for entry in _normalise_entries(dynamic.get("errors"))
    ]

    score = min(10.0, round(score, 2))
    if score >= 6.5:
        risk_level = "高风险"
        guidance = "捕获到大量动态恶意行为，请结合静态分析立即响应。"
    elif score >= 3.2:
        risk_level = "中等风险"
        guidance = "存在可疑的系统改动或网络活动，建议继续跟进。"
    else:
        risk_level = "低风险"
        guidance = "动态行为有限，建议结合模型输出综合判断。"

    return {
        "counts": counts,
        "score": score,
        "risk_level": risk_level,
        "guidance": guidance,
        "highlights": highlights,
        "errors": errors,
        "total_events": total_events,
    }


def _summarise_dynamic_v2(dynamic: dict[str, Any]) -> dict[str, Any]:
    events = dynamic.get("events") if isinstance(dynamic.get("events"), dict) else {}
    summary_counts = dynamic.get("summary") if isinstance(dynamic.get("summary"), dict) else {}

    categories = [
        ("file", "文件 / IO", 0.22, 40),
        ("net", "网络通信", 0.8, 25),
        ("reg", "注册表操作", 0.35, 16),
        ("proc", "进程 / 命令", 0.6, 15),
        ("summary", "聚合统计", 0.2, 8),
        ("misc", "其他事件", 0.1, 8),
    ]

    counts: list[tuple[str, int]] = []
    highlights: list[str] = []
    score = 0.0
    total_events = 0

    for key, title, weight, cap in categories:
        entries = _normalise_entries(events.get(key))
        count = _to_int(summary_counts.get(f"{key}_count"), len(entries))
        total_events += count
        counts.append((title, count))
        score += min(count, cap) * weight
        for entry in entries[: min(3, len(entries))]:
            highlights.append(f"{title}: {_stringify_value(entry)}")

    errors = [
        _stringify_value(entry) for entry in _normalise_entries(events.get("error"))
    ]
    if errors:
        total_events += len(errors)
        score += min(len(errors), 5) * 0.1

    score = min(10.0, round(score, 2))
    if score >= 7.0:
        risk_level = "高风险"
        guidance = "观察到明显的进程/网络/注册表操作，请结合静态分析立即响应。"
    elif score >= 4.0:
        risk_level = "中等风险"
        guidance = "检测到可疑外联或系统修改，建议继续跟进。"
    else:
        risk_level = "低风险"
        guidance = "行为事件有限，建议结合模型输出综合判断。"

    return {
        "counts": counts,
        "score": score,
        "risk_level": risk_level,
        "guidance": guidance,
        "highlights": highlights,
        "errors": errors,
        "total_events": total_events,
    }


def _format_dynamic_markdown(dynamic: dict[str, Any]) -> list[str]:
    summary = _summarise_dynamic(dynamic)
    meta = dynamic.get("meta") if isinstance(dynamic.get("meta"), dict) else {}
    lines = [
        "## 动态分析摘要",
        "",
        f"- 风险评级: **{summary['risk_level']}** (行为得分 {summary['score']:.1f}/10)",
        f"- 采集到的行为事件总数: {summary['total_events']}",
    ]

    meta_parts: list[str] = []
    if meta:
        exe_name = meta.get("exe_name") or meta.get("file")
        profile = meta.get("profile")
        timeout = meta.get("timeout")
        max_events = meta.get("max_events")
        start = meta.get("start_time")
        end = meta.get("end_time")
        if exe_name:
            meta_parts.append(f"样本 {exe_name}")
        if profile:
            meta_parts.append(f"profile {profile}")
        if timeout:
            meta_parts.append(f"超时时间 {timeout}s")
        if max_events:
            meta_parts.append(f"最大事件 {max_events}")
        try:
            if start is not None and end is not None and float(end) >= float(start):
                meta_parts.append(f"运行时长 {float(end) - float(start):.1f}s")
        except Exception:
            pass

    if meta_parts:
        lines.append(f"- 运行信息: {'； '.join(meta_parts)}")

    if summary["guidance"]:
        lines.append(f"- 建议: {summary['guidance']}")

    lines.append("")
    lines.extend(
        _format_table(
            [["行为类别", "事件数量"], ["---", "---"]]
            + [[title, str(count)] for title, count in summary["counts"]]
        )
    )

    if summary["highlights"]:
        lines.append("")
        lines.append("**关键事件样本**")
        for item in summary["highlights"][:6]:
            lines.append(f"- {item}")

    if summary["errors"]:
        lines.append("")
        lines.append("**执行异常**")
        for item in summary["errors"][:6]:
            lines.append(f"- {item}")

    return lines


def build_markdown_report(file_path: str | Path, result: dict[str, Any]) -> str:
    """Create a markdown report identical to the desktop GUI output."""

    path = Path(file_path)
    summary = result.get("summary", {}) if isinstance(result, dict) else {}
    reasoning = result.get("reasoning", {}) if isinstance(result, dict) else {}

    general = summary.get("general", {}) if isinstance(summary, dict) else {}
    strings = summary.get("strings", {}) if isinstance(summary, dict) else {}
    suspicious_hits = summary.get("suspicious_api_hits", []) or []
    high_entropy_sections = summary.get("high_entropy_sections", []) or []
    section_overview = summary.get("section_overview", []) or []
    dll_usage = summary.get("dll_usage", []) or []
    header_info = summary.get("header", {}) if isinstance(summary, dict) else {}
    risk_info = summary.get("risk_assessment", {}) if isinstance(summary, dict) else {}
    mitigations = risk_info.get("mitigations", []) or []
    risk_factors = risk_info.get("factors", []) or []
    string_samples = summary.get("string_samples", {}) if isinstance(summary, dict) else {}
    active_data_dirs = summary.get("active_data_directories", []) or []
    exports = summary.get("exports", []) or []
    packer_sections = summary.get("packer_sections", []) or []
    entry_section = summary.get("entry_section")

    avg_string_length = _to_float(strings.get("avlength"))
    printable_strings = _to_int(strings.get("printables"))
    mz_count = _to_int(strings.get("MZ"))

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    verdict = result.get("verdict", "未知")
    display_prob = _to_float(result.get("display_probability"))
    raw_prob = _to_float(result.get("probability"))
    threshold = _to_float(result.get("threshold"))
    score_interpretation = result.get("score_interpretation")
    detection_mode = result.get("detection_mode") or {}
    model_path = result.get("model_path", "未知")

    risk_score = _to_float(risk_info.get("score"))
    risk_level = risk_info.get("level", "未知")

    lines: list[str] = [
        "# 恶意 PE 文件检测报告",
        "",
        f"- **生成时间**: {generated_at}",
        f"- **文件名**: `{path.name}`",
        f"- **文件路径**: `{path}`",
        f"- **模型文件**: `{model_path}`",
        "",
        "## 预测结果",
        "",
        f"- 模型判定: **{verdict}**",
        f"- 恶意概率 (展示): **{display_prob:.4f}%**",
        f"- 原始模型得分: {raw_prob:.6f}",
        f"- 判定阈值: {threshold:.4f}",
    ]

    if detection_mode:
        mode_label = detection_mode.get("label", "未知模式")
        mode_desc = detection_mode.get("description", "")
        extra = f"，{mode_desc}" if mode_desc else ""
        lines.append(
            f"- 检测模式: {mode_label} (阈值 {threshold:.4f}{extra})"
        )

    if score_interpretation:
        lines.append(f"- 检测结论: {score_interpretation}")

    lines.extend([
        "",
        "## 模型信心与风险评估",
        "",
        f"- 综合风险等级: **{risk_level}**",
        f"- 综合风险得分: **{risk_score:.1f} / 10**",
    ])

    confidence = _confidence_label(raw_prob, threshold)
    lines.extend([f"- 判定信心: **{confidence}** (与阈值差距 {abs(raw_prob - threshold):.4f})", ""])

    if risk_factors:
        lines.extend(
            _format_table([
                ("主要恶意信号", "贡献分值", "说明"),
                ("---", "---", "---"),
            ])
        )
        for factor in risk_factors:
            weight = _to_float(factor.get("weight"))
            title = factor.get("title", "未知")
            detail = factor.get("detail", "")
            lines.append(f"| {title} | {weight:.2f} | {detail} |")
        lines.append("")

    if mitigations:
        lines.extend(["**潜在缓解因素**", ""])
        for item in mitigations:
            title = item.get("title", "未知")
            detail = item.get("detail", "")
            lines.append(f"- {title}: {detail}")
        lines.append("")

    lines.extend(["## 判定依据", ""])

    headline = reasoning.get("headline") if isinstance(reasoning, dict) else None
    if headline:
        lines.append(str(headline))

    bullets = reasoning.get("bullets", []) if isinstance(reasoning, dict) else []
    if bullets:
        lines.extend(f"- {item}" for item in bullets)
    else:
        lines.append("- 模型未提供额外判定依据。")

    lines.extend([
        "",
        "## 文件特征概览",
        "",
        f"- 文件大小: {general.get('size', '未知')} 字节",
        f"- 虚拟大小 (SizeOfImage): {general.get('vsize', '未知')}",
        f"- 是否包含数字签名: {'是' if general.get('has_signature') else '否'}",
        f"- 导入函数数量: {summary.get('total_imports', 0)}",
        f"- 字符串熵: {float(summary.get('string_entropy', 0.0) or 0.0):.2f}",
        f"- URL 字符串数量: {summary.get('url_strings', 0)}",
        f"- 注册表字符串数量: {summary.get('registry_strings', 0)}",
        f"- 字符串密度: {float(summary.get('strings_per_kb', 0.0) or 0.0):.2f} 条/KB",
        f"- 节区数量: {summary.get('section_count', 0)}",
        f"- 入口节区: {entry_section or '未知'}",
    ])

    if header_info:
        lines.extend(["", "## PE 头部信息", ""])
        header_lines = [f"- 机器类型: {header_info.get('machine', '未知') or '未知'}"]
        timestamp = _to_int(header_info.get("timestamp"))
        if timestamp > 0:
            build_time = datetime.utcfromtimestamp(timestamp)
            header_lines.append(f"- 编译时间: {build_time.strftime('%Y-%m-%d %H:%M:%S')} (UTC)")
        else:
            header_lines.append("- 编译时间: 未知/异常 (时间戳为 0)")
        header_lines.extend(
            [
                f"- 子系统: {header_info.get('subsystem', '未知') or '未知'}",
                f"- 代码区大小: {header_info.get('sizeof_code', 0)}",
                f"- 头部大小: {header_info.get('sizeof_headers', 0)}",
            ]
        )
        dll_chars = header_info.get("dll_characteristics", []) or []
        if dll_chars:
            header_lines.append("- DLL 特征: " + ", ".join(str(item) for item in dll_chars[:12]))
        characteristics = header_info.get("characteristics", []) or []
        if characteristics:
            header_lines.append("- COFF 标志: " + ", ".join(str(item) for item in characteristics[:12]))
        lines.extend(header_lines)

    if suspicious_hits:
        lines.extend(["", "## 高风险 API", ""])
        for hit in suspicious_hits[:10]:
            api = hit.get("api", "未知")
            hint = hit.get("hint", "")
            lines.append(f"- `{api}`: {hint}")

    if high_entropy_sections:
        lines.extend(["", "## 高熵节区", ""])
        for sec in high_entropy_sections[:10]:
            name = sec.get("name", "未知")
            size = sec.get("size", "未知")
            entropy = _to_float(sec.get("entropy"))
            lines.append(f"- `{name}` — 大小 {size} 字节，熵 {entropy:.2f}")

    if packer_sections:
        lines.extend(["", "## 可能的加壳迹象", ""])
        unique_packers: list[str] = []
        for name in packer_sections:
            if name not in unique_packers:
                unique_packers.append(name)
        for name in unique_packers:
            lines.append(f"- 节区名包含 `{name}`，疑似常见壳标识。")

    benign_hits = summary.get("benign_api_hits", []) or []
    if benign_hits:
        lines.extend(["", "## 常见系统 API", ""])
        for api in benign_hits[:10]:
            lines.append(f"- `{api}`")

    if strings:
        lines.extend([
            "",
            "## 字符串统计",
            "",
            f"- 可打印字符串数量: {printable_strings}",
            f"- 平均字符串长度: {avg_string_length:.2f}",
            f"- MZ 标记次数: {mz_count}",
        ])

    if isinstance(string_samples, dict):
        url_samples = string_samples.get("urls", []) or []
        ip_samples = string_samples.get("ips", []) or []
        path_samples = string_samples.get("paths", []) or []
        reg_samples = string_samples.get("registry", []) or []
        suspicious_strings = string_samples.get("suspicious", []) or []
        longest_strings = string_samples.get("longest", []) or []
        top_chars = string_samples.get("top_chars", []) or []

        if url_samples:
            lines.extend(["", "### URL 样本", ""])
            for item in url_samples[:10]:
                lines.append(f"- {item}")

        if ip_samples:
            lines.extend(["", "### IP 样本", ""])
            for item in ip_samples[:10]:
                lines.append(f"- {item}")

        if path_samples:
            lines.extend(["", "### 路径样本", ""])
            for item in path_samples[:10]:
                lines.append(f"- {item}")

        if reg_samples:
            lines.extend(["", "### 注册表样本", ""])
            for item in reg_samples[:10]:
                lines.append(f"- {item}")

        if suspicious_strings:
            lines.extend(["", "### 可疑字符串", ""])
            for item in suspicious_strings[:10]:
                lines.append(f"- {item}")

        if longest_strings:
            lines.extend(["", "### 最长字符串", ""])
            for item in longest_strings[:10]:
                lines.append(f"- {item}")

        if top_chars:
            lines.extend(["", "### 高频字符", ""])
            for item in top_chars[:10]:
                char = item.get("char", "?") if isinstance(item, dict) else item
                freq = item.get("frequency", "?") if isinstance(item, dict) else "?"
                lines.append(f"- `{char}`: {freq}")

    if section_overview:
        lines.extend(["", "## 节区概览", ""])
        table_rows = _format_table([
            ("节区名", "原始大小", "虚拟大小", "熵"),
            ("---", "---", "---", "---"),
        ])
        lines.extend(table_rows)
        for section in section_overview[:10]:
            name = section.get("name", "未知")
            raw_size = section.get("raw_size", "未知")
            virtual_size = section.get("virtual_size", "未知")
            entropy = _to_float(section.get("entropy"))
            lines.append(f"| {name} | {raw_size} | {virtual_size} | {entropy:.2f} |")

    if dll_usage:
        lines.extend(["", "## DLL 调用统计", ""])
        for dll in dll_usage[:10]:
            name = dll.get("name", "未知")
            count = dll.get("count", 0)
            lines.append(f"- {name}: {count} 次调用")

    if active_data_dirs:
        lines.extend(["", "## 活跃数据目录", ""])
        for directory in active_data_dirs[:8]:
            entry = directory.get("name", "未知") if isinstance(directory, dict) else directory
            lines.append(f"- {entry}")

    if exports:
        lines.extend(["", "## 导出符号", ""])
        for symbol in exports[:20]:
            lines.append(f"- {symbol}")

    dynamic_result = result.get("dynamic_analysis")
    if isinstance(dynamic_result, dict) and dynamic_result:
        lines.append("")
        lines.extend(_format_dynamic_markdown(dynamic_result))

    lines.append("")
    lines.append("报告生成自：Machine Learning for Malicious PE File Detection 项目")

    return "\n".join(lines)


__all__ = ["build_markdown_report"]
