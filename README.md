# Network Traffic Intrusion Detection Analyzer

Python-based project analyzing network traffic data (NSL-KDD dataset) to detect anomalies using statistical and rule-based methods.

## Problem Statement
Manually detecting suspicious network connections is impractical at scale. This project automates anomaly detection using data analysis techniques.

## Tech Stack
- **Python** (OOP + Procedural)
- **Pandas & NumPy** — data processing and statistical analysis
- **MySQL** — data storage with triggers for automated alerts
- **Matplotlib** — visualization

## Architecture
- `models/` — Business logic (Detector classes, ConnectionRecord)
- `repository/` — Data access layer (CRUD operations)
- `database/` — MySQL schema and connection handling
- `utils/` — Data loading and cleaning utilities
- `visualization/` — Chart generation

## Key Features
- Abstract base class (`BaseDetector`) with polymorphic detection strategies
- MySQL triggers for automatic alert generation
- Encapsulated data models

## How to Run
```bash
pip install -r requirements.txt
python main.py
```

## Dataset
[NSL-KDD Dataset (Kaggle)](https://www.kaggle.com/datasets/hassan06/nslkdd)