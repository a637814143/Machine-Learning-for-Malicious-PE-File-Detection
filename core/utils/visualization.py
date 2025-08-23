# core/utils/visualization.py
from pathlib import Path
import datetime
import pefile
from PyQt5.QtWidgets import (
    QApplication, QDialog, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem,
    QTextEdit
)


def parse_rich_header(pe):
    """
    尝试解析 Rich Header 信息（MSVC 编译器特有）
    返回 VS 编译器版本信息
    """
    try:
        if hasattr(pe, "RICH_HEADER") and pe.RICH_HEADER is not None:
            rich_data = pe.RICH_HEADER.values
            # RICH_HEADER.values 是一个 list，每个元素是 {'id': X, 'count': Y, 'version': Z}
            versions = set([entry['version'] for entry in rich_data if 'version' in entry])
            if versions:
                return f"MSVC (RichHeader: {', '.join(map(str, versions))})"
        return None
    except Exception:
        return None


def guess_compiler(pe):
    """
    根据 Linker 版本 + Section 名字 + Rich Header 推测编译器
    """
    try:
        linker_ver = f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"

        # Section 名字
        section_names = [s.Name.decode(errors="ignore").strip("\x00") for s in pe.sections]

        # 1) Rich Header 检测
        rich_info = parse_rich_header(pe)
        if rich_info:
            return rich_info

        # 2) 根据 section 名字推测
        if any(".gcc_except_table" in s or ".eh_frame" in s for s in section_names):
            return f"GCC (linker {linker_ver})"
        elif any(".drectve" in s or ".code" in s for s in section_names):
            return f"Borland/Delphi (linker {linker_ver})"
        elif "CLR_HEADER" in dir(pe.OPTIONAL_HEADER):  # .NET 可执行文件
            return f".NET (linker {linker_ver})"
        else:
            return f"MSVC/Unknown (linker {linker_ver})"
    except Exception:
        return "Unknown"


def show_pe_info(path: Path):
    """
    使用 PyQt5 展示单个 PE 文件的详细信息
    """
    pe = pefile.PE(str(path), fast_load=False)

    # ===== 基础信息 =====
    fsize = path.stat().st_size
    timestamp = datetime.datetime.fromtimestamp(
        pe.FILE_HEADER.TimeDateStamp
    ).strftime("%Y-%m-%d %H:%M:%S")

    if pe.FILE_HEADER.Characteristics & 0x2000:
        ftype = "DLL"
    elif pe.FILE_HEADER.Characteristics & 0x1000:
        ftype = "SYS"
    else:
        ftype = "EXE"

    compiler = guess_compiler(pe)

    # ===== 节区信息 =====
    section_info = []
    for section in pe.sections:
        section_info.append((
            section.Name.decode(errors="ignore").strip("\x00"),
            hex(section.VirtualAddress),
            hex(section.Misc_VirtualSize),
            hex(section.SizeOfRawData)
        ))

    # ===== 导入表 =====
    imports = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors="ignore")
            funcs = [imp.name.decode(errors="ignore") if imp.name else "None" for imp in entry.imports]
            imports.append(f"{dll_name}: {', '.join(funcs[:10])}")  # 只展示前 10 个函数

    # ======== PyQt5 窗口展示 ========
    app = QApplication.instance() or QApplication([])

    dialog = QDialog()
    dialog.setWindowTitle(f"PE 文件信息 - {path.name}")
    layout = QVBoxLayout(dialog)

    # 基本信息
    layout.addWidget(QLabel(
        f"<b>文件:</b> {path.name}<br>"
        f"<b>大小:</b> {fsize} bytes<br>"
        f"<b>类型:</b> {ftype}<br>"
        f"<b>编译时间:</b> {timestamp}<br>"
        f"<b>编译器:</b> {compiler}<br>"
    ))

    # 节区表格
    sec_table = QTableWidget(len(section_info), 4)
    sec_table.setHorizontalHeaderLabels(["Name", "VirtualAddress", "VirtualSize", "RawSize"])
    for i, (name, va, vs, rs) in enumerate(section_info):
        sec_table.setItem(i, 0, QTableWidgetItem(name))
        sec_table.setItem(i, 1, QTableWidgetItem(va))
        sec_table.setItem(i, 2, QTableWidgetItem(vs))
        sec_table.setItem(i, 3, QTableWidgetItem(rs))
    layout.addWidget(QLabel("<b>节区信息:</b>"))
    layout.addWidget(sec_table)

    # 导入函数
    layout.addWidget(QLabel("<b>导入函数:</b>"))
    imp_box = QTextEdit("\n".join(imports))
    imp_box.setReadOnly(True)
    layout.addWidget(imp_box)

    dialog.setLayout(layout)
    dialog.resize(800, 600)
    dialog.exec_()


if __name__ == "__main__":
    test_file = Path(r"C:\Users\86133\PycharmProjects\毕业设计_基于机器学习的恶意软件检测\data\raw\malware\VirusShare_7023fdcb1f13c1f2aaf564754fae58d0")  # 替换成你要测试的路径
    show_pe_info(test_file)
