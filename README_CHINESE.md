# 基于机器学习的恶意 PE 文件检测系统

> GUI + Web 的恶意软件分析工具链：特征提取、向量化、LightGBM 训练、批量检测与报告生成一站式完成。

## 目录

1. [项目概述](#项目概述)
2. [核心能力](#核心能力)
3. [技术栈与目录结构](#技术栈与目录结构)
4. [环境准备](#环境准备)
5. [数据准备流程](#数据准备流程)
6. [GUI 使用指南](#gui-使用指南)
7. [Flask Web 服务](#flask-web-服务)
8. [文档与报告](#文档与报告)
9. [常见问题](#常见问题)
10. [交流与贡献](#交流与贡献)

---

## 项目概述

本仓库围绕「基于机器学习的恶意 PE 文件检测」这一毕业 / 研究课题构建，提供一整套从样本管理、特征工程、模型训练到部署与报告的解决方案：

- **桌面端**：PyQt5 GUI 负责特征提取、特征转换、模型训练/测试/检测以及实时报告预览。
- **后端核心**：`core/` 中实现特征解析、向量化、模型管理和报告构建。
- **Web 服务**：`Flask/` 提供 HTTP API，方便接入自动化平台或远程上传检测。
- **文档沉淀**：生成的检测报告集中存储在 `docs/`，并配套 `thesis.md`、`simple_thesis.md` 等研究说明。

在线体验地址 **http://1.95.159.199**（上传 `.exe` 即可获取检测结果）。

---

## 核心能力

- **端到端流水线**：原始 `.exe` → `.jsonl` 特征 → `.npz` 向量 → LightGBM 模型 → 批量/交互式检测。
- **异步 GUI**：任务进度、日志、HTML 报告实时展示，无需担心长耗时任务卡死。
- **报告自动化**：每次检测都会生成 Markdown/HTML 报告（位于 `docs/`），便于审计与分享。
- **一键部署**：Flask 服务共享核心模块，实现桌面 / Web 行为一致性。
- **脚本辅助**：`scripts/` 内提供数据清理、依赖安装、批量扫描等工具。

---

## 技术栈与目录结构

| 模块 | 技术 |
| --- | --- |
| 编程语言 | Python 3.10+，NumPy / SciPy / scikit-learn / LightGBM |
| 桌面端 | PyQt5、自定义 QSS、任务调度、HTML 预览 |
| 特征工程 | `pefile`、`lief`、`capstone`、自研解析器 |
| Web 服务 | Flask 3、Werkzeug（可扩展至 WSGI 部署） |
| 其他 | `rich`、`tqdm`、`frida`、`networkx`、`requests` |

主要目录：

```
machine/
├── app/            # PyQt5 主程序、UI、任务注册
├── core/           # 数据处理、特征工程、建模、报告
├── Flask/          # HTTP 服务
├── data/           # 数据集及中间产物
├── docs/           # 生成的检测报告
├── scripts/        # 实用脚本
├── tests/          # 自动化测试
├── PNG/            # 文档截图
├── thesis.md       # 完整论文
└── simple_thesis.md# 精简版说明
```

---

## 环境准备

```powershell
python -m venv .venv
.\\.venv\\Scripts\\activate
pip install -r requirements.txt
```

> 若 `lightgbm` / `lief` / `pefile` 编译受限，可执行 `python scripts\\PIP_INSTALL.py` 由脚本自动切换镜像并重试。

---

## 数据准备流程

1. **原始样本**：  
   - 良性：`data/raw/benign/`  
   - 恶意：`data/raw/malware/`  
   - 自定义测试集（可选）：`data/raw/test/`
2. **隔离区**：损坏或来源可疑的文件放入 `data/quarantine/invalid/`，避免参与训练。
3. **中间产物（自动生成）**：  
   - 特征：`data/processed/jsonl/*.jsonl`  
   - 向量：`data/processed/npy|npz/`  
   - 模型：`data/processed/models/` 或根目录 `model.txt`

---

## GUI 使用指南

启动 GUI：

```powershell
python app\\main.py
```

典型工作流：

1. **提取特征**  
   - 选择待处理目录与输出 `.jsonl`。  
   - 支持多线程与实时写入，可针对良性/恶意分别提取后再合并。
2. **特征转换**  
   - 将合并后的 `.jsonl` 变为 `.npz` / `.npy`，供模型训练使用。
3. **模型训练**  
   - 载入 `.npz` 数据，训练 LightGBM，调节阈值，输出 `model.txt`。
4. **模型测试**  
   - 观察准确率、误报率和风险评级等指标，辅助阈值选择。
5. **模型检测**  
   - 对任意目录进行批量扫描，生成 HTML/Markdown 报告（默认写在 `docs/`）。

GUI 依赖 `app/tasks/default_tasks.py` 中的任务注册机制，所有长任务都会回报进度与日志，确保界面保持响应。

---

## Flask Web 服务

```powershell
python -m Flask.app --host 0.0.0.0 --port 8000 --debug
```

- API 复用 `core/` 模块，检测结果与 GUI 保持一致。  
- 适合构建自动化提交流程、SOC 工具链或远程扫描平台。  
- 上线生产环境时请关闭 `--debug` 并放置在 WSGI / 反向代理之后。

---

## 文档与报告

- `docs/`：历史检测报告、威胁情报记录（含 Markdown 与 HTML 片段）。  
- `thesis.md` / `simple_thesis.md`：研究背景、设计思路、评估数据。  
- `README.md`：中英双语总览。  
- `log.txt`：运行日志，可辅助排错。

---

## 常见问题

1. **LightGBM 安装失败？**  
   - 确保使用 Python 3.10+，优先尝试 `pip install -r requirements.txt`。  
   - Windows 环境可借助 `scripts/PIP_INSTALL.py` 设置国内镜像。  
   - 仍失败时建议安装 Visual C++ Build Tools 或改用预编译 wheel。

2. **GUI 卡在“无响应”？**  
   - 使用最新版代码；所有核心任务均已异步化，如仍卡顿可查看 `logs/` 或终端输出。  
   - 确认输出目录可写，避免实时写入被杀毒软件阻拦。

3. **模型结果偏差大？**  
   - 检查良性/恶意样本数量是否平衡。  
   - 在“模型训练”步骤调整阈值或切换特征组合。  
   - 使用 `模型测试` 功能观察指标后再决定是否重新训练。

---

## 交流与贡献

- 使用 `issues` / `pull requests` 提交反馈或贡献代码（请附带复现步骤与脱敏日志）。  
- 欢迎分享新的样本集、报告模板或可视化想法，帮助完善整体解决方案。  
- 若在使用过程中遇到阻碍，也可以在 README 中的联系方式（如存在）与作者沟通。

感谢关注与支持！
