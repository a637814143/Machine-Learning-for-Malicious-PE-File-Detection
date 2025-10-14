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

---

## Flask Web Service Usage

The desktop GUI's malware analysis pipeline is also exposed through a Flask web service so that it can be accessed remotely.

### 1. Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Start the service

Run the application module directly. Command line arguments let you customise the bind host, port, and debug mode.

```bash
python -m Flask.app --host 0.0.0.0 --port 8000
```

Once started the service exposes the following HTTP endpoints:

| Method | Path       | Description                               |
|--------|------------|-------------------------------------------|
| GET    | `/`        | Hacker-themed web console (responds with JSON when requested) |
| GET    | `/service-info` | JSON service description for programmatic discovery |
| GET    | `/health`  | Health check endpoint                     |
| POST   | `/predict` | Run the malicious PE detector             |

### 3. Explore the neon console

Visit [http://127.0.0.1:8000/](http://127.0.0.1:8000/) to enter the neon "Malicious PE Sentinel" console. The interface now focuses on a streamlined Chinese workflow while preserving the cyberpunk look and feel:

- Switch between uploading a binary or referencing a path already present on the server.
- Rely on the project’s bundled `model.txt` with a fixed decision threshold of `0.0385`, identical to the desktop GUI.
- View concise verdict summaries and reasoning bullets, then download the complete JSON report for archival or sharing.
- Review a chronological event log that records every request/response pair for traceability.

### 4. Send API requests directly

Upload a PE file directly:

```bash
curl -X POST http://127.0.0.1:8000/predict \
  -F "file=@/path/to/sample.exe"
```

Analyse a file that already exists on the server:

```bash
curl -X POST http://127.0.0.1:8000/predict \
  -H "Content-Type: application/json" \
  -d '{
        "path": "C:/malware_samples/locked.exe"
      }'
```

The JSON response mirrors what the GUI displays, including the predicted label, confidence scores, and extracted feature summary. Errors (for example missing files) are also returned as JSON to simplify integration with other systems.
