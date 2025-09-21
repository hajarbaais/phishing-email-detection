# Phishing Email Analyzer 


A multi-layered tool to analyze email files (`.eml`) and source code for phishing indicators. This analyzer provides a comprehensive risk score based on deep analysis of headers, URLs, and attachments, accessible via both a modern web interface and a powerful command-line tool.

---
##  Table of Contents

- [Key Features](#-key-features)
- [Tech Stack](#-tech-stack)
- [Installation & Setup](#-installation--setup)
- [Usage](#️-usage)
  - [Web Interface](#1-web-interface)
  - [Command-Line Interface (CLI)](#2-command-line-interface-cli)
- [Running Tests](#-running-tests)
- [Configuration](#️-Configuration)
- [Project Structure](#-Project-structure)
---


## ✨ Key Features

* **Deep Header Analysis:** Validates email authentication standards (**SPF, DKIM, DMARC**) and detects header anomalies and spoofing indicators.
* **Intelligent URL Scanning:** Extracts and scrutinizes all URLs, checking them against malicious TLDs, known URL shorteners, and identifying deceptive keywords.
* **Safe Attachment Inspection:** Analyzes attachment metadata for dangerous file types and inspects archive contents (`.zip`) without writing to disk.
* **Configurable Risk Scoring:** A flexible scoring engine defined in `config.yaml` allows for customized weighting of various risk factors.
* **Dual Interface:**
    * **Web Application (`app.py`):** A user-friendly interface powered by Flask for easy, on-the-fly analysis.
    * **Command-Line Tool (`main.py`):** A powerful CLI for batch processing, integration into other scripts, and detailed JSON report generation.
* **Thoroughly Tested:** The project includes a dedicated test suite to ensure reliability and accuracy.

---

## 🚀 Tech Stack

* **Backend:** Python 3.9+, Flask
* **Frontend:** HTML, CSS, JavaScript
* **Testing:** Pytest

---

## 🔧 Installation & Setup

Follow these steps to set up the project environment.

1.  **Clone the Repository**
    ```bash
    git clone [https://github.com/YourUsername/PhishingEmailDetection.git](https://github.com/YourUsername/PhishingEmailDetection.git)
    cd PhishingEmailDetection
    ```

2.  **Create and Activate a Virtual Environment**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

---

## 🛠️ Usage

This analyzer can be used in two ways: through the easy-to-use web interface or the powerful command-line tool.

### 1. Web Interface

The web interface is ideal for quick, interactive analysis.

1.  **Start the Flask Application:**
    ```bash
    python app.py
    ```
2.  Open your web browser and navigate to `http://127.0.0.1:5000`.
3.  In your email client, view the raw source of the suspicious email ("Show Original" in Gmail) and copy it.
4.  Paste the content into the text area on the web page and click "Analyze".



### 2. Command-Line Interface (CLI)

The CLI is perfect for power users and for integrating the analysis into automated workflows.

1.  Place the emails you want to analyze (as `.eml` files) in the `data/raw/` directory.
2.  Run the `main.py` script, providing the path to the email file as an argument.
    ```bash
    python main.py data/raw/suspicious-email.eml
    ```
3.  A detailed JSON report will be generated and saved in the `outputs/reports/` directory, timestamped for uniqueness.

---

## 🧪 Running Tests

A full suite of tests is included to ensure the reliability of the analysis modules. To run the tests, execute the following command from the project's root directory:

```bash
pytest
```

## ⚙️ Configuration

The analysis logic and scoring weights can be fully customized by editing the config/config.yaml file. Here you can define:

Points assigned to each risk factor.

Lists of suspicious keywords and TLDs.

Known safe senders.


## 📂 Project Structure

```bash
PhishingEmailDetection/
├── config/
│   └── config.yaml         # Main configuration for scoring and keywords
├── data/
│   ├── processed/          # Processed data (if any)
│   └── raw/                # Place raw .eml files here
├── outputs/
│   ├── artifacts/          # For generated models or other artifacts
│   └── reports/            # Output directory for JSON reports
├── src/
│   ├── utils/              # Utility functions
│   ├── __init__.py
│   ├── attachments.py      # Attachment analysis module
│   ├── headers.py          # Header analysis module
│   ├── ingest.py           # Data ingestion and parsing
│   ├── report.py           # Report generation logic
│   ├── scoring.py          # Risk scoring engine
│   └── urls.py             # URL analysis module
├── tests/                  # Test suite for all modules
├── app.py                  # Flask application for the web UI
├── index.html              # Frontend for the web UI
├── main.py                 # CLI entry point
├── requirements.txt        # Project dependencies
└── README.md               # This file
```
