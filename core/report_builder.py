"""Shared helpers for producing markdown detection reports."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
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
        "",
        "## 模型信心与风险评估",
        "",
        f"- 综合风险等级: **{risk_level}**",
        f"- 综合风险得分: **{risk_score:.1f} / 10**",
    ]

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

    lines.append("")
    lines.append("报告生成自：Machine Learning for Malicious PE File Detection 项目")

    return "\n".join(lines)


__all__ = ["build_markdown_report"]