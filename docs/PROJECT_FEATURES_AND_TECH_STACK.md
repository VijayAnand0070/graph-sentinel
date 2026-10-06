# GraphSentinel - Features & Technology Stack Overview

**GraphSentinel** is an enterprise-grade, real-time threat detection platform powered by **Temporal Graph Neural Networks (TGN)** and causal graph feature engineering. It detects insider threats, credential misuse, and lateral movement in high-velocity authentication log streams (e.g. LANL enterprise cyber telemetry).

---

## 1. Features Built So Far

### 🔹 A. Data Ingestion & Normalization Engine (`graphsentinel.ingestion`)
* **LANL Log Parser**: High-performance streaming parser for raw authentication logs (`auth.txt`).
* **Entity Dictionary Mapping (`AuthIdMaps`)**: Bi-directional mapping of raw user IDs (`U1234`) and host IDs (`C5678`) into contiguous integer node ID spaces.
* **Parquet Data Storage**: Native Parquet reader and writer for high-density, compressed event storage.
* **Ground-Truth Label Integrator**: Precise integration of red-team attack timestamps (`redteam.txt`).

### 🔹 B. Causal Feature Engineering Pipeline (`graphsentinel.features`)
* **27-Dimensional Feature Extractor**: Computes rolling temporal and graph features strictly in causal order (zero future data leakage).
* **Graph Fan-Out & Velocity Signals**: Tracks 1-hour and 24-hour source host fan-out, user fan-out over 5-minute and 1-hour windows.
* **Structural Novelty Detection**: Flagging first-time user-host authentication edges (`is_new_user_host_pair`) and destination host novelty.
* **Authentication Context Features**: Tracks failure-before-success patterns, auth orientation (TGT vs NTLM vs Kerberos), and target service types.
* **Cyclical Time Transformations**: Sine and Cosine encodings for hour-of-day and day-of-week temporal patterns.

### 🔹 C. Temporal Graph Network (TGN) Core (`graphsentinel.models.tgn`)
* **Dynamic Node Memory (`TGNState`)**: Maintains evolving memory states for users and hosts updated chronologically per authentication batch.
* **Fourier Time Encoding**: Continuous-time representation mapping timestamp deltas into dynamic frequency encodings.
* **Class-Weighted Binary Cross-Entropy Loss**: Balanced training on highly imbalanced security event streams (positive attack prevalence ~0.28%).
* **Memory Detachment & Truncation**: Memory state tracking with periodic BPTT truncation (`truncate_after_events=2048`) for GPU memory optimization.

### 🔹 D. Multi-Signal Risk Fusion Engine (`graphsentinel.detection`)
* **Composite Risk Scoring (`fuse_risk`)**: Fuses TGN deep graph embeddings with explicit domain signals (novelty, burst velocity, lateral movement pivot).
* **Threat Intelligence & Path Ranker**: Ranks lateral movement paths and prioritizes multi-stage attack chains.

### 🔹 E. Machine Learning Baseline Models (`graphsentinel.models.baselines`)
* **Tabular Logistic Regression**: Standardized L2-regularized linear model trained on all 27 rolling features.
* **Isolation Forest**: Unsupervised tree-based anomaly detection baseline.
* **Rule-Based & Rarity Baselines**: Heuristic rule triggers and structural edge rarity baselines for benchmarking.

### 🔹 F. Explainability & Analyst Triage Engine (`graphsentinel.explain`)
* **Automated Evidence Generation**: Generates human-readable evidence summaries explaining why an alert score exceeded risk thresholds.
* **Analyst Triage Reports**: Automated triage report creation for SOC security operations center workflows.

### 🔹 G. Real-Time REST API & Service (`graphsentinel.api`)
* **FastAPI Web Service**: Real-time event ingestion and risk scoring endpoints (`/api/v1/score`, `/api/v1/health`, `/api/v1/metrics`).
* **Phase 16 Live Pipeline**: Streaming inference service executing real-time threat scoring with sub-millisecond per-event latency.

### 🔹 H. SOC Analyst Interactive Dashboard (`graphsentinel.dashboard`)
* **Web Dashboard**: Interactive client/server dashboard for SOC analysts to view active risk streams, top alerts, and system health metrics.

### 🔹 I. Automated CLI Tooling & PowerShell Pipelines (`graphsentinel.cli` / `scripts/`)
* **Unified CLI Interface**: `graphsentinel` command line interface for data ingestion, feature extraction, training, and evaluation.
* **Automated GPU Scripts**: PowerShell automation scripts (`train_250k_cuda_only.ps1`, `run_bounded_lanl_tgn.ps1`) managing environment initialization, CUDA checks, transcript logging, and atomic asset publishing.

---

## 2. Technology Stack

| Layer / Category | Technology / Framework | Usage & Purpose |
| :--- | :--- | :--- |
| **Primary Language** | **Python 3.13** | Core application, data pipeline, and machine learning code |
| **Deep Learning Engine** | **PyTorch 2.11.0** | Neural network components, autograd engine, and GPU tensor math |
| **Hardware Acceleration** | **NVIDIA CUDA 12.8** | GPU acceleration (NVIDIA GeForce RTX 3050 6GB Laptop GPU) |
| **Machine Learning** | **Scikit-Learn** | Logistic Regression, Isolation Forest, feature scaling & metrics |
| **Scientific Computing** | **NumPy & SciPy** | Vectorized matrix operations, probability functions, interpolation |
| **Data Storage & Format** | **PyArrow & Pandas** | High-speed Parquet dataset storage, tabular data manipulation |
| **Web & REST API** | **FastAPI & Uvicorn** | Asynchronous REST service API and streaming endpoints |
| **Data Validation** | **Pydantic (v2)** | Request/response schema validation and type enforcement |
| **System & Memory** | **`psutil` & `hashlib`** | Process inspection, system resource tracking, SHA-256 asset hashing |
| **CLI & Automation** | **Python `argparse` & PowerShell** | CLI entrypoints, shell orchestration, transcript logging |
| **Testing & Quality** | **PyTest, Mypy, Ruff** | Unit testing, coverage reporting, static type checking, linting |

---

## 3. Current Performance Summary (250K LANL CUDA Run)

* **Top-10 Precision**: **60.0%** (6 of top 10 flagged events are true red-team attacks)
* **Top-100 Precision**: **36.0%** (36 of top 100 flagged events are true red-team attacks)
* **Top-100 Recall**: **76.6%** (36 out of 47 total test set attack events caught in top 100 alerts)
* **Test PR-AUC**: **55.16%**
* **Test ROC-AUC**: **85.85%**
* **False Positive Rate**: **16.54 / 10,000 events** (Budget: <= 25.0/10k)
