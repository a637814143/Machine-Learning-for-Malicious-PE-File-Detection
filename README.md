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