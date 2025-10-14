# 基于机器学习的恶意 PE 文件检测

## 项目概述

本项目旨在构建一个基于机器学习的系统，用于检测恶意 PE（可移植可执行文件）文件。
系统集成了特征提取、模型训练、预测和报告功能，并提供 GUI 界面以便进行分析和可视化。
目标是提供一个完整的恶意软件检测和威胁评估管道。


---

## 项目结构

```
Graduation-Project-ML-Malicious-PE/
├── app/ # 主应用程序
│ ├── main.py # 入口文件
│ ├── ui/ # 界面模块
│ │ ├── main_window.py
│ │ ├── report_view.py
│ │ ├── progress_dialog.py
│ │ └── resources.py # 图标和资源
│ ├── controllers/ # 应用控制器
│ │ ├── analysis_controller.py
│ │ └── file_controller.py
│ └── models/ # UI 数据模型
│ ├── analysis_model.py
│ └── report_model.py
├── core/ # 核心功能
│ ├── feature_engineering/ # 特征提取
│ │ ├── pe_parser.py
│ │ ├── static_features.py
│ │ ├── semantic_features.py
│ │ └── feature_utils.py
│ ├── analysis/ # 分析模块
│ │ ├── predictor.py
│ │ ├── report_generator.py
│ │ └── threat_assessment.py
│ ├── data_processing/ # 数据预处理
│ │ ├── dataset_loader.py
│ │ ├── sampler.py
│ │ └── splitter.py
│ ├── modeling/ # 模型训练与评估
│ │ ├── model_factory.py
│ │ ├── trainer.py
│ │ ├── evaluator.py
│ │ └── uncertainty.py
│ └── utils/ # 工具函数
│ ├── async_worker.py
│ ├── logger.py
│ ├── security.py
│ └── visualization.py
├── data/ # 数据存储
│ ├── raw/ # 原始样本
│ │ ├── benign/ # 良性样本
│ │ └── malware/ # 恶意样本
│ ├── processed/ # 预处理数据
│ └── quarantine/ # 可疑文件
├── models/ # 已保存的 ML 模型
│ ├── production/
│ ├── candidates/
│ └── legacy/
├── tests/ # 单元测试
├── docs/ # 文档
├── scripts/ # 脚本和工具
├── requirements.txt # Python 依赖
└── README.md # 项目概述
```


## 开发进度

- **项目初始化**：已完成，仓库结构已建立。
- **核心模块**：
  - 特征提取（PE 解析、静态与语义特征）已实现。
  - 数据处理管道（加载器、采样器、划分器）部分实现。
  - 建模模块（训练器、评估器）部分实现。
- **应用 GUI**：主窗口及基础 UI 组件已实现；进度对话框和报告视图可用。
- **集成**：特征提取与模型管道的初步集成正在进行中。
- **下一步计划**：
  - 完成模型训练与评估。
  - 实现完整的预测工作流及报告生成。
  - 优化 GUI 以提升可用性和可视化效果。
  - 在 VirusShare 数据集上进行测试。

---


## 总结
本项目提供了一个结构化的方法，用于利用机器学习检测恶意 PE 文件。
框架和部分核心功能已建立。
后续开发将实现完整的恶意软件分析、预测和报告功能。

---

## Flask Web 服务使用指南

桌面 GUI 中的恶意样本分析流程已经通过 Flask Web 服务对外暴露，方便远程用户直接调用。

### 1. 安装依赖

```bash
python -m venv .venv
source .venv/bin/activate  # Windows 下使用：.venv\Scripts\activate
pip install -r requirements.txt
```

### 2. 启动服务

直接运行模块即可启动服务，可通过命令行参数自定义监听地址、端口以及是否开启调试模式。

```bash
python -m Flask.app --host 0.0.0.0 --port 8000
```

启动后可访问的 HTTP 接口如下：

| 方法  | 路径        | 说明                     |
|-------|-------------|--------------------------|
| GET   | `/`         | 炫酷骇客风格的 Web 控制台（根据 Accept 头返回 JSON） |
| GET   | `/service-info` | 供脚本探测的 JSON 服务描述 |
| GET   | `/health`   | 健康检查接口              |
| POST  | `/predict`  | 执行恶意 PE 检测          |

### 3. 体验骇客风控制台

访问 [http://127.0.0.1:8000/](http://127.0.0.1:8000/) 即可进入焕新的 “Malicious PE Sentinel” 互动界面。页面延续赛博朋克风格，同时面向中文用户优化流程：

- 可在上传二进制文件与输入服务器已有路径之间自由切换。
- 服务固定使用项目自带的 `model.txt` 模型以及 `0.0385` 阈值，确保与桌面 GUI 判定一致。
- 页面展示精简的中文判定摘要与要点提示，并支持一键下载完整 Markdown 报告。
- 底部日志以时间顺序记录检测摘要与时间戳，方便追踪与审计。

### 4. 发起请求

直接上传待检测的 PE 文件：

```bash
curl -X POST http://127.0.0.1:8000/predict \
  -F "file=@/path/to/sample.exe"
```

分析服务器本地已有的文件：

```bash
curl -X POST http://127.0.0.1:8000/predict \
  -H "Content-Type: application/json" \
  -d '{
        "path": "C:/malware_samples/locked.exe"
      }'
```

返回的 JSON 数据与 GUI 中展示的内容一致，包括预测标签、置信度、特征摘要，并额外提供 `report_markdown` 与推荐的 `report_filename` 字段；若发生错误（如文件不存在）也会以 JSON 形式返回，方便与其他系统对接。

### 5. 反向代理部署提示

若在云服务器上通过 Nginx、Apache 等反向代理暴露服务，代理可能会改写 Host、协议或路径头信息，从而触发 Flask 的安全校验导致 `403 Forbidden`。Web 服务默认信任一层代理；若链路上存在多层（例如先经过负载均衡，再到反向代理），可在启动前设置环境变量指定可信跳数：

```bash
export PE_SENTINEL_TRUSTED_PROXY_HOPS=2
python -m Flask.app --host 0.0.0.0 --port 8000
```

服务会自动启用 Flask 的 `ProxyFix` 中间件，正确传递客户端的域名、协议以及路径前缀，确保骇客风界面与 API 能够从公网正常访问。
