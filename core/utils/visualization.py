# core/utils/visualization.py
from pathlib import Path
import datetime
import hashlib
import pefile
import math
from PyQt5.QtWidgets import (
    QApplication, QDialog, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem,
    QTextEdit
)


def parse_rich_header(pe):
    """解析 Rich Header 信息，返回 VS 编译器版本"""
    try:
        if hasattr(pe, "RICH_HEADER") and pe.RICH_HEADER is not None:
            rich_data = pe.RICH_HEADER.values
            versions = set([entry['version'] for entry in rich_data if 'version' in entry])
            if versions:
                return f"MSVC (RichHeader: {', '.join(map(str, versions))})"
        return None
    except Exception:
        return None


def guess_compiler(pe):
    """根据 Linker 版本 + Section 名字 + Rich Header 推测编译器"""
    try:
        linker_ver = f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"
        section_names = [s.Name.decode(errors="ignore").strip("\x00") for s in pe.sections]
        rich_info = parse_rich_header(pe)
        if rich_info:
            return rich_info
        if any(".gcc_except_table" in s or ".eh_frame" in s for s in section_names):
            return f"GCC (linker {linker_ver})"
        elif any(".drectve" in s or ".code" in s for s in section_names):
            return f"Borland/Delphi (linker {linker_ver})"
        elif "CLR_HEADER" in dir(pe.OPTIONAL_HEADER):
            return f".NET (linker {linker_ver})"
        else:
            return f"MSVC/Unknown (linker {linker_ver})"
    except Exception:
        return "Unknown"


def file_hashes(file_path: Path):
    """计算 MD5、SHA1、SHA256"""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def section_entropy(data: bytes) -> float:
    """计算节区熵"""
    if not data:
        return 0.0
    occur = [0]*256
    for b in data:
        occur[b] += 1
    entropy = 0.0
    length = len(data)
    for count in occur:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def show_pe_info(path: Path):
    """使用 PyQt5 弹窗显示完整 PE 文件信息"""
    pe = pefile.PE(str(path), fast_load=False)
    fsize = path.stat().st_size
    timestamp = datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).strftime("%Y-%m-%d %H:%M:%S")

    # 文件类型
    if pe.FILE_HEADER.Characteristics & 0x2000:
        ftype = "DLL"
    elif pe.FILE_HEADER.Characteristics & 0x1000:
        ftype = "SYS"
    else:
        ftype = "EXE"

    compiler = guess_compiler(pe)
    md5, sha1, sha256 = file_hashes(path)

    # 节区信息及熵
    section_info = []
    for s in pe.sections:
        data = s.get_data()
        entropy = section_entropy(data)
        section_info.append((
            s.Name.decode(errors="ignore").strip("\x00"),
            hex(s.VirtualAddress),
            hex(s.Misc_VirtualSize),
            hex(s.SizeOfRawData),
            f"{entropy:.3f}"
        ))

    # 导入表
    imports = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors="ignore")
            funcs = [imp.name.decode(errors="ignore") if imp.name else "None" for imp in entry.imports]
            imports.append(f"{dll_name}: {', '.join(funcs[:10])}")  # 前10个函数

    # 导出表
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT.symbols:
        exports = [exp.name.decode(errors="ignore") if exp.name else "None" for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols]

    # 数字签名
    signed = "未检测"
    try:
        if hasattr(pe, "VS_FIXEDFILEINFO"):
            signed = "未知/可能无签名"
    except Exception:
        signed = "未签名"

    # PyQt5 窗口
    app = QApplication.instance() or QApplication([])
    dialog = QDialog()
    dialog.setWindowTitle(f"PE 文件信息 - {path.name}")
    layout = QVBoxLayout(dialog)

    layout.addWidget(QLabel(
        f"<b>文件:</b> {path.name}<br>"
        f"<b>大小:</b> {fsize} bytes<br>"
        f"<b>类型:</b> {ftype}<br>"
        f"<b>编译时间:</b> {timestamp}<br>"
        f"<b>编译器:</b> {compiler}<br>"
        f"<b>数字签名:</b> {signed}<br>"
        f"<b>MD5:</b> {md5}<br>"
        f"<b>SHA1:</b> {sha1}<br>"
        f"<b>SHA256:</b> {sha256}<br>"
    ))

    # 节区表格
    sec_table = QTableWidget(len(section_info), 5)
    sec_table.setHorizontalHeaderLabels(["Name", "VirtualAddress", "VirtualSize", "RawSize", "Entropy"])
    for i, (name, va, vs, rs, ent) in enumerate(section_info):
        sec_table.setItem(i, 0, QTableWidgetItem(name))
        sec_table.setItem(i, 1, QTableWidgetItem(va))
        sec_table.setItem(i, 2, QTableWidgetItem(vs))
        sec_table.setItem(i, 3, QTableWidgetItem(rs))
        sec_table.setItem(i, 4, QTableWidgetItem(ent))
    layout.addWidget(QLabel("<b>节区信息:</b>"))
    layout.addWidget(sec_table)

    # 导入函数
    layout.addWidget(QLabel("<b>导入函数:</b>"))
    imp_box = QTextEdit("\n".join(imports))
    imp_box.setReadOnly(True)
    layout.addWidget(imp_box)

    # 导出函数
    layout.addWidget(QLabel("<b>导出函数:</b>"))
    exp_box = QTextEdit("\n".join(exports))
    exp_box.setReadOnly(True)
    layout.addWidget(exp_box)

    dialog.setLayout(layout)
    dialog.resize(900, 700)
    dialog.exec_()


def get_pe_info_html(path: Path) -> str:
    """返回 HTML 格式信息，用于 QTextBrowser 显示"""
    pe = pefile.PE(str(path), fast_load=False)
    fsize = path.stat().st_size
    timestamp = datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).strftime("%Y-%m-%d %H:%M:%S")

    if pe.FILE_HEADER.Characteristics & 0x2000:
        ftype = "DLL"
    elif pe.FILE_HEADER.Characteristics & 0x1000:
        ftype = "SYS"
    else:
        ftype = "EXE"

    compiler = guess_compiler(pe)
    md5, sha1, sha256 = file_hashes(path)

    html = f"<h3>文件信息 - {path.name}</h3>"
    html += f"<b>大小:</b> {fsize} bytes<br>"
    html += f"<b>类型:</b> {ftype}<br>"
    html += f"<b>编译时间:</b> {timestamp}<br>"
    html += f"<b>编译器:</b> {compiler}<br>"
    html += f"<b>MD5:</b> {md5}<br>"
    html += f"<b>SHA1:</b> {sha1}<br>"
    html += f"<b>SHA256:</b> {sha256}<br>"

    # 节区信息
    html += "<h4>节区信息:</h4><table border='1' cellspacing='0' cellpadding='2'>"
    html += "<tr><th>Name</th><th>VirtualAddress</th><th>VirtualSize</th><th>RawSize</th><th>Entropy</th></tr>"
    for s in pe.sections:
        name = s.Name.decode(errors="ignore").strip("\x00")
        va = hex(s.VirtualAddress)
        vs = hex(s.Misc_VirtualSize)
        rs = hex(s.SizeOfRawData)
        data = s.get_data()
        ent = f"{section_entropy(data):.3f}"
        html += f"<tr><td>{name}</td><td>{va}</td><td>{vs}</td><td>{rs}</td><td>{ent}</td></tr>"
    html += "</table>"

    # 导入
    html += "<h4>导入函数(前10个):</h4><ul>"
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors="ignore")
            funcs = [imp.name.decode(errors="ignore") if imp.name else "None" for imp in entry.imports]
            html += f"<li>{dll_name}: {', '.join(funcs[:10])}</li>"
    html += "</ul>"

    # 导出
    html += "<h4>导出函数:</h4><ul>"
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT.symbols:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            html += f"<li>{exp.name.decode(errors='ignore') if exp.name else 'None'}</li>"
    html += "</ul>"

    return html
