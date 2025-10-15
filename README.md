# Machine Learning for Malicious PE File Detection

## Project Overview
This project aims to build a machine learning-based system to detect malicious PE (Portable Executable) files.  
It integrates feature extraction, model training, prediction, and reporting, with a GUI for easy analysis and visualization.  
The goal is to provide a complete pipeline for malware detection and threat assessment.


---

## Project Structure

```
Graduation-Project-ML-Malicious-PE/
├── app/ # Main application
│ ├── main.py # Entry point
│ ├── ui/ # UI modules
│ │ ├── main_window.py
│ │ ├── report_view.py
│ │ ├── progress_dialog.py
│ │ └── resources.py # Icons and assets
│ ├── controllers/ # Application controllers
│ │ ├── analysis_controller.py
│ │ └── file_controller.py
│ └── models/ # UI data models
│ ├── analysis_model.py
│ └── report_model.py
├── core/ # Core functionality
│ ├── feature_engineering/ # Feature extraction
│ │ ├── pe_parser.py
│ │ ├── static_features.py
│ │ ├── semantic_features.py
│ │ └── feature_utils.py
│ ├── analysis/ # Analysis modules
│ │ ├── predictor.py
│ │ ├── report_generator.py
│ │ └── threat_assessment.py
│ ├── data_processing/ # Data preprocessing
│ │ ├── dataset_loader.py
│ │ ├── sampler.py
│ │ └── splitter.py
│ ├── modeling/ # Model training and evaluation
│ │ ├── model_factory.py
│ │ ├── trainer.py
│ │ ├── evaluator.py
│ │ └── uncertainty.py
│ └── utils/ # Utility functions
│ ├── async_worker.py
│ ├── logger.py
│ ├── security.py
│ └── visualization.py
├── data/ # Data storage
│ ├── raw/ # Raw samples
│ │ ├── benign/ # Benign samples
│ │ └── malware/ # Malicious samples
│ ├── processed/ # Preprocessed data
│ └── quarantine/ # Suspicious files
├── models/ # Saved ML models
│ ├── production/
│ ├── candidates/
│ └── legacy/
├── tests/ # Unit tests
├── docs/ # Documentation
├── scripts/ # Scripts and utilities
├── requirements.txt # Python dependencies
└── README.md # Project overview
```

## Development Progress

- **Project Initialization**: Completed, repository structure established.  
- **Core Modules**:  
  - Feature extraction (PE parsing, static and semantic features) implemented.  
  - Data processing pipeline (loader, sampler, splitter) partially implemented.  
  - Modeling modules (trainer, evaluator) partially implemented.  
- **Application GUI**: Main window and basic UI components implemented; progress dialogs and report view ready.  
- **Integration**: Preliminary integration of feature extraction and model pipeline underway.  
- **Next Steps**:  
  - Complete model training and evaluation.  
  - Implement full prediction workflow with report generation.  
  - Optimize GUI for usability and visualization.  
  - Perform testing on VirusShare dataset.

---

## Summary
This project provides a structured approach for detecting malicious PE files using machine learning.
The framework and partial core functionality have been established.
Further development will enable complete malware analysis, prediction, and reporting capabilities.

## Deploying the Flask service with BaoTa's WSGI mode

The repository ships with a lightweight Flask API inside the `Flask/` package. If
you manage your server with the BaoTa (宝塔) panel, you can deploy this service
through its Python project manager by pointing the form fields to the files in
this repository. The table below shows the recommended values; adapt the paths
and domain to match your own server layout.

| Field in BaoTa                          | Value / Description                                                    |
|----------------------------------------|------------------------------------------------------------------------|
| **项目名称** / Project name             | Any identifier you prefer, e.g. `machine`                              |
| **域名** / Domain                       | Your public domain or server IP, e.g. `ml-pe.example.com`               |
| **端口** / Port                         | A free TCP port, e.g. `6000` (ensure the security group/firewall allows it) |
| **Python版本** / Python version        | Python 3.10 or newer (matches `requirements.txt`)                      |
| **项目路径** / Project path             | Absolute path to this repository, e.g. `/www/wwwroot/machine`          |
| **运行目录** / Working directory        | Same as the project path                                               |
| **启动方式** / Start method             | Select `wsgi`                                                          |
| **执行文件** / Entry file               | `Flask/wsgi.py`                                                        |
| **启动用户** / Run as user              | `root` or a dedicated service account with read permission             |
| **是否安装依赖** / Install requirements | Enable automatic installation and point to `requirements.txt`          |

Once saved, BaoTa will create an isolated virtual environment, install the
dependencies, and start the WSGI service using the `application` object exposed
in `Flask/wsgi.py`. You can later manage (start/stop/restart) the service from
the BaoTa interface.