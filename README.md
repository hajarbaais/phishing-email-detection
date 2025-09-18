Phishing Email Analyzer
A comprehensive tool to analyze email files (.eml) for signs of phishing. This project uses a multi-layered approach, examining email headers, URLs, and attachments to calculate a risk score. It includes both a command-line interface (CLI) for detailed analysis and a user-friendly web interface for quick checks.

<!-- You can replace this with a screenshot of your GUI -->

Features
Header Analysis: Checks for email authentication standards like DKIM, SPF, and DMARC, and flags mismatches between the From and Return-Path headers.

URL Analysis: Extracts all URLs from the email body, checks them against lists of known URL shorteners and suspicious Top-Level Domains (TLDs), and scans for deceptive keywords.

Attachment Scanning: Safely inspects email attachments, flagging dangerous file types and checking inside .zip files for executables without writing to disk.

Risk Scoring: A configurable weighting system aggregates findings from all analyses to produce a final risk score (0-100).

Dual Interfaces:

Command-Line Tool (main.py): For power users and integration, providing detailed logs and generating JSON reports.

Web GUI (index.html): An easy-to-use, single-file interface for users to paste email source code and get an instant analysis in their browser.

Project Structure
phish-detection/
│
├─ config/
│  └─ config.yaml        # Scoring weights and analysis keywords
├─ data/
│  └─ raw/               # Directory for test .eml files
├─ outputs/
│  └─ reports/           # Generated JSON reports from the CLI
├─ src/
│  ├─ ingest.py
│  ├─ headers.py
│  ├─ urls.py
│  ├─ attachments.py
│  ├─ scoring.py
│  └─ report.py
│
├─ index.html            # User-friendly Web Interface
├─ main.py               # Main script for the Command-Line Interface
├─ requirements.txt      # Python dependencies
└─ README.md             # This file

Getting Started
Prerequisites
Python 3.8+

Git

Installation
Clone the repository:

git clone [https://github.com/YourUsername/phishing-email-analyzer.git](https://github.com/YourUsername/phishing-email-analyzer.git)
cd phishing-email-analyzer

Create a virtual environment (recommended):

python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`

Install the required dependencies:

pip install -r requirements.txt

How to Use
This project offers two ways to analyze emails.

Option 1: Web Interface (Easy)
Open the index.html file in your web browser (e.g., Chrome, Firefox).

In your email client (like Gmail or Outlook), find the email you want to analyze and select the "Show Original" or "View Source" option.

Copy the entire raw email source.

Paste the source code into the text box on the webpage and click Analyze Email.

View the instant report.

Option 2: Command-Line Tool (Advanced)
Save the email you want to analyze as a .eml file.

Run the main.py script from your terminal, providing the path to the .eml file.

python main.py /path/to/your/email.eml

On Windows, remember to use quotes if your path contains spaces:

python main.py "C:\Path With Spaces\email.eml"

A detailed JSON report will be generated and saved in the outputs/reports/ directory.

Configuration
All analysis parameters and scoring weights can be adjusted in the config/config.yaml file. You can add new keywords, dangerous file extensions, and change the points assigned for each risk factor.