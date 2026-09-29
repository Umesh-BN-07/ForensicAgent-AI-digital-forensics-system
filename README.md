# ForensicAgent: AI Digital Forensics Investigation System

ForensicAgent is a Python-based digital forensics investigation tool that analyzes suspicious evidence folders and log files, detects risk patterns, applies NLP-based content analysis, correlates events into an investigation timeline, and generates PDF forensic reports.

The project combines:
- a Flask REST API backend,
- a desktop GUI built with CustomTkinter,
- rule-based forensic detection,
- a machine learning anomaly model,
- NLP keyword analysis,
- automated report generation.

---

## What the project does

ForensicAgent is designed to help investigate suspicious digital evidence by:

- collecting uploaded files and preserving evidence metadata,
- calculating SHA-256 hashes for integrity tracking,
- parsing log events such as login failures, file access, downloads, and deletions,
- identifying suspicious patterns like brute-force attacks and sensitive file access,
- analyzing text content for risky keywords and suspicious communication,
- correlating events into a timeline and summary,
- generating a PDF report for the case.

This is a prototype / research-oriented forensic workflow rather than a full enterprise forensic platform.

---

## Features

- Evidence upload and storage
- File integrity hashing with SHA-256
- Log parsing and event extraction
- Threat detection for:
  - brute-force login attempts,
  - multiple failed logins,
  - suspicious file access,
  - log deletion,
  - login-after-failure patterns
- NLP risk scoring on text content using spaCy
- Machine learning anomaly detection using Isolation Forest
- Correlation of attacker behavior across the timeline
- PDF report generation using ReportLab
- Desktop interface for evidence investigation workflows

---

## Project structure

```text
ForensicAgent-AI-digital-forensics-system-main/
├── README.md
├── backend/
│   ├── app.py                  # Flask app entry point
│   ├── config.py               # upload config and file restrictions
│   ├── requirements.txt        # Python dependencies
│   ├── agents/
│   │   ├── evidence_agent.py    # hashes and metadata collection
│   │   ├── log_agent.py         # log parsing and detection logic
│   │   ├── correlation_agent.py # timeline and summary correlation
│   │   ├── report_agent.py      # single-file PDF report generation
│   │   ├── folder_agent.py      # folder-level investigation orchestration
│   │   ├── folder_report_agent.py # consolidated PDF report for folders
│   │   ├── nlp_agent.py         # suspicious text score analysis
│   │   ├── orchestrator.py      # main investigation workflow
│   │   └── __init__.py
│   ├── ml/
│   │   ├── anomaly_detector.py  # model loader
│   │   └── train_model.py       # model training script
│   ├── routes/
│   │   ├── evidence.py          # evidence upload API
│   │   ├── investigation.py    # log analysis API
│   │   ├── folder_investigation.py # ZIP folder analysis API
│   │   ├── nlp.py              # NLP API
│   │   └── __init__.py
│   ├── uploads/
│   │   └── cases/               # sample evidence sets
│   └── reports/                 # generated PDF reports
├── gui/
│   ├── api.py                   # backend client for the GUI
│   ├── main.py                  # CustomTkinter desktop app
│   ├── theme.py                 # theme definitions
│   ├── assets/
│   ├── components/
│   └── pages/
├── models/
│   └── isolation_forest.pkl     # trained anomaly detection model
└── (optional training data can be added separately if retraining the model)
```

---

## How it works

### 1. Evidence collection
The backend accepts evidence files or complete evidence folders, saves them under the upload directory, and records metadata including:
- original filename,
- stored filename,
- path,
- size,
- SHA-256 hash,
- timestamp.

### 2. Log analysis
The log agent parses events in log-like strings and extracts relevant fields. It then checks for suspicious activity patterns such as:
- repeated failed logins,
- sensitive file access,
- log deletion,
- successful login after multiple failures.

### 3. NLP analysis
The NLP agent processes text files and scans for high-risk indicators such as:
- password,
- credential,
- confidential,
- secret,
- malware,
- ransomware,
- exploit,
- attack.

### 4. Correlation and risk scoring
The correlation agent creates a timeline of suspicious events and produces investigation conclusions based on the combined findings.

### 5. Report generation
The app produces a PDF report summarizing:
- evidence inventory,
- threat findings,
- ML prediction,
- NLP results,
- attack timeline,
- recommendations.

---

## Requirements

- Python 3.9+
- pip
- A working internet connection for installing dependencies and spaCy models

Required Python packages are listed in [backend/requirements.txt](backend/requirements.txt).

---

## Setup

### 1. Create a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install backend dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 3. Install the spaCy language model

The app uses:

```python
spacy.load("en_core_web_sm")
```

Install it with:

```bash
python -m spacy download en_core_web_sm
```

If the model is not installed, the NLP feature will fail at runtime.

---

## Running the app

### Start the backend API

From the project root:

```bash
cd backend
python app.py
```

The Flask app runs on:

```text
http://127.0.0.1:5000
```

### Start the GUI

From the project root:

```bash
cd gui
python main.py
```

The GUI is a custom desktop application that communicates with the backend API.

---

## API endpoints

### Health check

```http
GET /api/health
```
Returns backend health status.

### Evidence upload

```http
POST /api/evidence/upload
```
Uploads a single file and returns evidence metadata and SHA-256 hash.

### Log analysis

```http
POST /api/investigation/analyze-log
```
Analyzes a saved log file and returns threat findings, ML output, timeline, and report path.

### Folder analysis

```http
POST /api/investigation/analyze-folder
```
Uploads a ZIP archive of a case folder, extracts it safely, analyzes the full evidence set, and returns its findings.

### NLP analysis

```http
POST /api/nlp/analyze
```
Sends raw text to the NLP detector and returns risk score and keywords.

---

## Example data

Sample evidence directories are stored under:

```text
backend/uploads/cases/
```

Each case includes text and CSV files such as:
- login_activity.csv
- chat_log.txt
- suspicious_email.txt

These are used for demonstration and testing. A separate training dataset is not required to run the project because the pre-trained model is already included in the repository.

---

## Notes

- This project is a prototype for educational/demo digital forensics analysis.
- It is not a replacement for professional forensic tooling or chain-of-custody systems.
- Unsupported binary files are collected and hashed but not executed.
- The application generates reports in the backend reports folder.

---

## License

This project does not currently declare a specific license in the repository. If you are using it in a production environment, confirm the licensing terms before distribution or commercial use.

---

## Quick start summary

```bash
cd backend
pip install -r requirements.txt
python -m spacy download en_core_web_sm
python app.py
```

Then in another terminal:

```bash
cd gui
python main.py
```

---

## Troubleshooting

- If the GUI cannot reach the backend, make sure the Flask app is running first.
- If the NLP section fails, install the spaCy model again.
- If report generation fails, ensure the backend reports folder is writable.
- If a folder analysis fails, verify the archive contains a valid folder structure and no unsafe traversal paths.

