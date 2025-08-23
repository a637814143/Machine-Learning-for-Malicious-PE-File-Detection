<<<<<<< HEAD
毕业设计_基于机器学习的恶意软件检测/
│
├── app/                      # 主应用程序 (新增)
│   ├── main.py               # 应用入口点
│   ├── ui/                   # UI模块
│   │   ├── main_window.py    # 主窗口实现
│   │   ├── report_view.py    # 报告展示组件
│   │   ├── progress_dialog.py # 进度对话框
│   │   └── resources.py      # 资源文件（图标等）
│   │
│   ├── controllers/          # 控制器
│   │   ├── analysis_controller.py # 分析流程控制
│   │   └── file_controller.py # 文件处理控制
│   │
│   └── models/               # UI数据模型
│       ├── analysis_model.py # 分析数据模型
│       └── report_model.py   # 报告数据模型
│
├── core/                     # 核心功能（原src/重命名）
│   ├── feature_engineering/  # 特征工程
│   │   ├── pe_parser.py      # PE文件解析器
│   │   ├── static_features.py # 静态特征提取
│   │   ├── semantic_features.py # 语义特征
│   │   └── feature_utils.py  # 特征工具
│   │
│   ├── analysis/             # 分析模块 (新增)
│   │   ├── predictor.py      # 模型预测
│   │   ├── report_generator.py # 报告生成器
│   │   └── threat_assessment.py # 威胁评估
│   │
│   ├── data_processing/      # 数据处理
│   │   ├── dataset_loader.py 
│   │   ├── sampler.py        
│   │   └── splitter.py       
│   │
│   ├── modeling/             # 建模核心
│   │   ├── model_factory.py  
│   │   ├── trainer.py        
│   │   ├── evaluator.py      
│   │   └── uncertainty.py    
│   │
│   └── utils/                # 实用工具
│       ├── async_worker.py   # 异步任务处理 (新增)
│       ├── logger.py         
│       ├── security.py       
│       └── visualization.py  
│
├── data/                     # 数据存储
│   ├── raw/ 
│       ├── benign	#良性样本
│       ├── malware     #恶意样本                      
│   ├── processed/            
│   └── quarantine/           
│
├── models/                   # 训练好的模型
│   ├── production/           
│   ├── candidates/           
│   └── legacy/               
│
├── tests/                    # 测试
├── docs/                     # 文档
├── scripts/                  # 脚本
├── requirements.txt          # Python依赖
└── README.md                 # 项目文档
=======
# Machine-Learning-for-Malicious-PE-File-Detection
I am a beginner in machine learning, here I will share my learning process, I will try to complete the project: machine learning-based malicious PE file detection; If you know a lot about machine learning or malicious PE file research, please give me advice, thank you. The dataset I used: VirusShare, language and version: Python 3.10.7
>>>>>>> a96c8e6689bd68b6a11f673b0ab9be390fde0757
