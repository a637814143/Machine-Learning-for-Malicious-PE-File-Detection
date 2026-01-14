# Machine Learning for Malicious PE File Detection
基于 LightGBM 的静态 + 动态恶意 PE 文件检测与可视化套件。

## 核心能力
- EMBER 风格的静态特征（哈希、节区、字符串、熵直方图等）+ LightGBM 模型，附带预训练模型 `model.txt`。
- PyQt5 桌面端：数据清洗 → 特征提取 → 向量化 → 训练/测试 → 批量预测，全流程可视化进度与日志。
- 轻量“一键检测”窗口（`app/dete.py`）：本地静态检测 + 将样本上传到沙箱 `/upload` 端点收集动态行为。
- REST API（Flask）：与桌面端同逻辑的 `/predict` 接口，返回 JSON 结果与 Markdown 报告内容。
- Frida 动态沙箱脚本（`Frida dynamic testing/get.py`），可部署在隔离环境里提供 `/upload` 动态分析服务。
- 自动生成的 Markdown 报告示例见 `docs/`，可直接复用到工单/邮件。

## 目录速览
- `core/`：特征工程、向量化与 LightGBM 训练推理工具。
- `app/`：PyQt5 桌面端（全功能主界面与“一键检测”小窗）。
- `Flask/`：REST API 服务端及前端模板。
- `scripts/`：GUI 任务适配器、批量预测 CLI（`D.py`）、数据清洗/特征/训练脚本。
- `Frida dynamic testing/`：基于 Frida 的动态沙箱上传服务与脚本。
- `data/`：样例数据（原始样本、提取后的 jsonl、向量 npz、模型）。
- `docs/`：历史检测报告与日志。

## 环境与安装
- Python 3.10+，建议在虚拟环境中使用。
- 安装依赖：
  ```bash
  pip install -r requirements.txt
  ```
  如 LightGBM/LIEF 安装失败，请先安装对应的编译工具链或使用预编译轮子。
- 可选：动态分析需要 `frida`，已在 requirements 中列出。

## 快速体验
- **全功能桌面端**（含任务面板）：  
  ```bash
  python app/main.py
  ```
  支持数据清洗、特征提取、向量化、模型训练/测试、批量预测、依赖安装、沙箱指引等。

- **轻量一键检测 + 沙箱上传**：  
  ```bash
  python app/dete.py
  ```
  选择 PE 文件 → （可选）填写沙箱 `http://<host>:<port>/upload` → 选择检测模式（高精度 / 高敏感）→ 一键检测。

- **批量扫描 CLI（静态）**：  
  ```bash
  python scripts/D.py <file_or_dir> out/predictions --model model.txt --mode high_precision --threshold 0.0385 --max 1500
  ```
  将递归扫描目录内的 `.exe/.dll/.sys`，生成带 Markdown 报告的结果文件。

- **REST API 服务**：  
  ```bash
  python Flask/app.py --host 0.0.0.0 --port 5555
  curl -F "file=@suspect.exe" http://127.0.0.1:5555/predict
  ```
  返回 JSON，包括 `report_markdown` 与建议的报告文件名。

- **模型训练 CLI（LightGBM）**：  
  ```bash
  python cli.py data/npz/train.npz data/npz/v.npz data/npz/t.npz \
    --model-out model.txt --threads 8 --early-stopping 50
  ```
  训练完成后会输出 train/valid/test 的精度、召回、F1 等指标，并保存模型。

- **单文件脚本调用**：  
  ```python
  from scripts.D import predict_file_with_features
  result = predict_file_with_features(r"C:\samples\test.exe")
  print(result["verdict"], result["display_probability"], result["report_markdown"][:200], "...")
  ```

## 数据处理流水线（静态特征）
1. **数据清洗**（去重/过滤非 PE，可在 GUI“数据清洗”任务触发，或直接调用 `scripts.DATA_CLEAN.DATA_CLEAN`）。
2. **特征提取 → jsonl**：  
   ```python
   from core.feature_engineering import extract_from_directory
   extract_from_directory("data/pefile/train", "data/jsonl", max_workers=8, realtime_write=True)
   ```
3. **向量化 → npz**（与 EMBER 兼容的 2381 维向量）：  
   ```python
   from core.feature_engineering import vectorize_feature_file
   vectorize_feature_file("data/jsonl/your_features.jsonl", "data/npz", max_workers=8, realtime_write=True)
   ```
4. **模型训练/评估**：使用上面的 `cli.py`，或在 GUI“训练模型/测试模型”任务中选择向量文件。

## 动态分析与沙箱
- **Frida 动态沙箱服务**：在隔离虚拟机中运行  
  ```bash
  python "Frida dynamic testing/get.py"
  ```
  默认监听 `0.0.0.0:5007`，提供 `/upload` 上传接口，返回 API 调用/网络/注册表等行为摘要。
- **GUI 集成**：在 `app/dete.py` 窗口或主界面“沙箱检测”中填写沙箱地址（例如 `http://127.0.0.1:5007/upload`），静态检测后自动附加动态结果并生成综合报告。

## 报告与样例
- 生成的 Markdown 报告默认保存在 `docs/`（示例：`docs/Locky_report_*.md`），也可通过 REST API 返回内容自行保存。
- 报告内容包含静态风险解读、可疑 API/节区提示、动态行为摘要（若提供），便于直接粘贴到工单或邮件。

## 常见问题
- **LightGBM 或 LIEF 导入失败**：确认已安装编译依赖（Windows 需 VC++ 构建工具），或安装对应平台的预编译轮子。
- **模型文件缺失**：默认使用仓库根目录的 `model.txt`，如需自训模型请按上文训练流程生成并更新路径。
- **沙箱连接报错**：确认填入完整 URL（包含 `/upload`），并确保沙箱和本地网络互通；动态服务务必运行在隔离环境。

## 许可与贡献
欢迎提交 Issue / PR 优化特征工程、模型参数或 GUI 体验。使用本项目进行动态分析时请确保样本合规，并在隔离环境中操作。
