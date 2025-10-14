# Flask 恶意软件检测服务

该目录提供了一个独立的 Flask Web 服务，用于在线检测用户上传的 Windows 可执行文件（PE）并生成检测报告。服务内置了与项目 ``model.txt`` 相同的特征提取与向量化流程，可直接加载 LightGBM 模型进行预测。

## 目录结构

```
Flask/
├── app.py             # Flask 应用主入口，完全自包含
├── README.md          # 使用说明
├── requirements.txt   # 运行服务所需的Python依赖
├── ml_pipeline/       # 复制自核心代码的特征提取与向量化逻辑
├── static/
│   └── styles.css     # 页面样式
└── templates/
    ├── index.html     # 上传页面
    └── report.html    # 检测结果展示
```

## 快速开始

1. 建议使用 Python 3.9+。
2. 安装依赖：
   ```bash
   pip install -r requirements.txt
   ```
3. 确保项目根目录存在训练得到的 `model.txt`（LightGBM 文本模型）。
4. 运行服务：
   ```bash
   python app.py
   ```
5. 浏览器访问 `http://127.0.0.1:8000/`，上传 PE 文件即可查看检测结果与 JSON 报告。

## 接入自定义模型

- 默认会从仓库根目录读取 `model.txt`：
  ```python
  MODEL_PATH = BASE_DIR.parent / "model.txt"
  ```
  也可以通过环境变量 `MALWARE_MODEL` 指向自定义路径。
- `ml_pipeline/` 中包含了 `extract_features` 与 `vectorize_features`，流程与核心项目保持一致。
- 如果需要替换模型，只需提供同样使用 2381 维向量的 LightGBM 模型；其它类型模型可在 `ModelWrapper.predict` 中自行扩展。
- 报告页面会展示模型概率、可疑字符串、高熵节区等摘要，便于排查样本。

## 生成的报告

- 成功分析后，会在 `Flask/reports/` 目录生成一份 JSON 报告文件。
- 上传文件会备份到 `Flask/uploads/` 目录，文件名自动带有时间戳。
- 前端页面提供报告下载链接，便于保留检测结果。

## 注意事项

- 默认允许上传的文件扩展名为 `exe`、`dll`、`sys`、`drv`、`ocx`，如需调整可修改 `ALLOWED_EXTENSIONS`。
- 单个文件上传大小限制为 25 MiB，可通过修改 `MAX_CONTENT_LENGTH` 调整。
- 如果未检测到模型文件，系统会回退到基于特征的启发式打分，请勿将其用于生产环境。
