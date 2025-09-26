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

### 在 GUI 中训练 LightGBM 模型

当你在应用的任务列表中选择 **“训练模型”** 时，需要按照以下顺序填写参数：

1. 训练向量 ``.npy`` 文件路径
2. 训练集标签 JSONL 路径
3. LightGBM 模型输出路径
4. *(可选)* 验证向量 ``.npy`` 文件路径
5. *(可选)* 验证集标签 JSONL 路径
6. *(可选)* 迭代轮数（整数，默认沿用 EMBER 的 4096）
7. *(可选)* LightGBM 参数覆盖值，使用 JSON 字符串，如 ``{"learning_rate": 0.05}``

提交后，任务会先打印一段“训练配置”摘要，方便核对路径和超参数，随后开始训练。
进度条和评估指标会实时输出到任务日志面板。
