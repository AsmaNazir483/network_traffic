# Network Traffic Intrusion Detection Analyzer

A Python-based project that analyzes network traffic data (NSL-KDD dataset) to detect anomalous/malicious connections using statistical, rule-based, and machine learning approaches — backed by a MySQL database with automated trigger-based alerting.

## Problem Statement

Manually inspecting network traffic to identify malicious connections is impractical at scale. This project automates anomaly detection using multiple approaches — from simple statistical rules to machine learning — and compares their effectiveness on real network intrusion data.

## Tech Stack

- **Python** — Core language (OOP + Procedural design)
- **Pandas & NumPy** — Data loading, cleaning, and statistical analysis
- **Scikit-learn** — Machine learning-based anomaly detection (Isolation Forest)
- **MySQL** — Relational data storage with triggers for automated alert generation
- **Matplotlib** — Data visualization
- **python-dotenv** — Secure credential management

## Architecture

The project follows a layered architecture (similar to BL/DL separation):
network_traffic/
├── database/ # MySQL schema, connection handling, and triggers
├── models/ # Business logic — Detector classes, ConnectionRecord (OOP)
├── repository/ # Data access layer — CRUD operations (Repository Pattern)
├── utils/ # Data loading and cleaning utilities (Procedural)
├── visualization/ # Chart generation
├── outputs/ # Generated charts (not tracked in git)
├── main.py # Entry point — integrates all components
└── requirements.txt # Project dependencies

## Key Features

- **Abstract base class** (`BaseDetector`) with polymorphic detection strategies (Statistical, Rule-Based)
- **MySQL Triggers** — automatically generate alerts when an anomalous connection is inserted, without application-level intervention
- **Encapsulated data models** — `ConnectionRecord` uses private attributes with property-based access
- **Repository Pattern** — separates database logic from business logic
- **Multi-method comparison** — evaluates Statistical, Rule-Based, and Machine Learning detectors side-by-side against ground-truth labels

## Detection Methods Compared

| Method | Description |
|---|---|
| **Statistical Detector** | Z-score based anomaly detection using multiple features (`count`, `srv_count`, `serror_rate`, `dst_host_serror_rate`) |
| **Rule-Based Detector** | Fixed threshold rules on `src_bytes` and `duration` |
| **ML Detector (Isolation Forest)** | Unsupervised machine learning model that learns complex, non-linear patterns across multiple features simultaneously |

## Key Findings

On a 500-record sample from the NSL-KDD training set:

| Detector | Accuracy |
|---|---|
| Statistical Detector | 50.40% |
| Rule-Based Detector | 52.00% |
| **ML (Isolation Forest)** | **77.80%** |

The statistical and rule-based detectors performed close to random-guessing baseline (50%), revealing that **simple threshold-based rules struggle to separate normal from malicious traffic** in high-dimensional network data, since individual features overlap significantly between the two classes.

Applying a **Machine Learning approach (Isolation Forest)** improved accuracy to **77.80%**, since it can learn non-linear combinations of multiple features simultaneously rather than relying on a single fixed threshold. This mirrors real-world practice — production Intrusion Detection Systems rely on ML/deep learning models rather than simple statistical rules.

## Database Design

3 normalized MySQL tables with a foreign-key relationship:
- `attack_categories` — reference table for attack severity classification
- `connections` — stores individual network connection records
- `alerts` — automatically populated via an `AFTER INSERT` trigger whenever a connection is flagged as anomalous

## How to Run

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set up the database (run in MySQL Workbench)
# Execute database/schema.sql

# 3. Configure environment variables
# Create a .env file in the project root:
#   DB_HOST=localhost
#   DB_USER=root
#   DB_PASSWORD=your_password
#   DB_NAME=network_traffic_db

# 4. Run the analyzer
python main.py
```

## Dataset

[NSL-KDD Dataset (Kaggle)](https://www.kaggle.com/datasets/hassan06/nslkdd)

## Future Improvements

- Train on the full dataset (125,000+ records) instead of a 500-record sample
- Add cross-validation for more robust accuracy measurement
- Experiment with additional ML models (Random Forest, Neural Networks)
- Feature engineering to identify the most discriminative attributes
- Real-time streaming detection instead of batch processing