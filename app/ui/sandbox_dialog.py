"""Dialog presenting sandbox detection resources and workflow guidance."""

from __future__ import annotations

from PyQt5 import QtWidgets


class SandboxDialog(QtWidgets.QDialog):
    """Provide guidance and links for sandbox-based dynamic analysis."""

    def __init__(self, parent: QtWidgets.QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("沙箱检测指南")
        self.resize(720, 520)
        self.setModal(False)
        self._build_ui()
        self._populate_content()

    def _build_ui(self) -> None:
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        header = QtWidgets.QLabel(
            "<h2>动态沙箱分析</h2>"
            "<p>将可疑样本上传到受信任的在线沙箱或部署本地沙箱，"
            "可以采集运行时行为、网络通信和持久化线索。</p>"
        )
        header.setWordWrap(True)
        layout.addWidget(header)

        self.resourceBrowser = QtWidgets.QTextBrowser()
        self.resourceBrowser.setOpenExternalLinks(True)
        layout.addWidget(self.resourceBrowser, 1)

        workflow_group = QtWidgets.QGroupBox("推荐工作流")
        workflow_layout = QtWidgets.QVBoxLayout(workflow_group)
        workflow_layout.setSpacing(6)

        steps = [
            "1. 在隔离环境准备可疑样本，记录原始哈希。",
            "2. 使用多个在线沙箱（如下）交叉验证行为。",
            "3. 若样本含敏感信息或涉密，优先在本地沙箱（Cuckoo、CAPEv2 等）运行。",
            "4. 汇总 API 调用、进程树、网络访问、文件/注册表改动，并与模型结果对比。",
            "5. 将关键信息导出为报告，便于威胁溯源与规则编写。",
        ]
        for step in steps:
            label = QtWidgets.QLabel(step)
            label.setWordWrap(True)
            workflow_layout.addWidget(label)

        layout.addWidget(workflow_group)

    def _populate_content(self) -> None:
        resources = [
            (
                "VirusTotal Dynamic Analysis",
                "提供混合静态/动态分析、网络流量和内存快照。",
                "https://www.virustotal.com/gui/home/upload",
            ),
            (
                "Hybrid Analysis",
                "CrowdStrike 维护的沙箱，支持 Windows/Android，并给出行为评分。",
                "https://www.hybrid-analysis.com/",
            ),
            (
                "ANY.RUN",
                "交互式沙箱，可实时观察进程和网络行为，支持生成共享报告。",
                "https://any.run/",
            ),
            (
                "Tencent Habo",
                "针对中文用户的在线沙箱，提供详细的行为路径与IOC。",
                "https://habo.qq.com/",
            ),
            (
                "CAPE Sandbox",
                "开源可扩展沙箱，可在本地部署并提取 YARA/网络特征。",
                "https://github.com/kevoreilly/CAPEv2",
            ),
        ]

        lines = ["<ul>"]
        for name, desc, url in resources:
            lines.append(
                "<li><b>{name}</b> - {desc}<br/><a href=\"{url}\">{url}</a></li>".format(
                    name=name, desc=desc, url=url
                )
            )
        lines.append("</ul>")
        self.resourceBrowser.setHtml("\n".join(lines))
