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

## Training with the Official EMBER Configuration

The project includes a LightGBM training pipeline that mirrors the official
EMBER setup. Once you have vectorised the JSONL features into ``.npy`` files,
train a model as follows:

```bash
python - <<'PY'
from pathlib import Path
from core.modeling.trainer import train_ember_model

train_vectors = Path("data/processed/npy/ember_train.npy")
train_jsonl = Path("data/raw/ember/train.jsonl")
valid_vectors = Path("data/processed/npy/ember_valid.npy")
valid_jsonl = Path("data/raw/ember/valid.jsonl")
model_path = Path("models/ember_lightgbm.txt")

train_ember_model(
    train_vectors=train_vectors,
    train_jsonl=train_jsonl,
    model_output=model_path,
    valid_vectors=valid_vectors,
    valid_jsonl=valid_jsonl,
)
PY
```

Progress updates and validation metrics are streamed through the GUI task
system. The resulting LightGBM model is saved in the standard text format and
can be loaded via ``lightgbm.Booster(model_file=...)`` for inference.

### Training from the GUI

The GUI task named **“训练模型”** accepts positional arguments. Provide them in
the following order when prompted:

1. Training vector file (``.npy``)
2. Training labels JSONL
3. Output path for the LightGBM model
4. *(Optional)* Validation vector file
5. *(Optional)* Validation labels JSONL
6. *(Optional)* Number of boosting rounds (integer; defaults to EMBER’s 4096)
7. *(Optional)* JSON string with LightGBM parameter overrides, e.g.
   ``{"learning_rate": 0.05, "num_leaves": 64}``

After the arguments are submitted, the task summary lists the resolved paths
and overrides before training starts. Progress updates and evaluation metrics
are streamed to the task log.

## Summary

This project provides a structured approach for detecting malicious PE files
using machine learning. The framework and core functionality have been
established, including an EMBER-compatible feature extraction and training
pipeline. Further development will enable complete malware analysis,
prediction, and reporting capabilities.
