<div align="center">

# 🛡️ SURAKSHA
### Intelligent Rule-Based Vulnerability Scanner & Risk Prediction Engine

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat-square&logo=python&logoColor=white)](#)
[![Flask](https://img.shields.io/badge/Flask-Web%20Framework-000000?style=flat-square&logo=flask&logoColor=white)](#)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-Machine%20Learning-F7931E?style=flat-square&logo=scikit-learn&logoColor=white)](#)
[![Nmap](https://img.shields.io/badge/Network-Nmap%20Engine-blue?style=flat-square)](#)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](#)

<p align="center">
  <em>A unified cybersecurity assessment platform bridging active reconnaissance, automated CVE correlation, and machine learning risk classification.</em>
</p>

</div>

---

## 📌 Overview

**SURAKSHA** (सुरक्षा / സുരക്ഷ) is an integrated vulnerability assessment framework built using Python and Flask. It consolidates network host discovery, web application vulnerability scanning, and SSL/TLS cryptographic auditing into a single interface. 

Rather than relying purely on static heuristics, SURAKSHA employs a **Random Forest Classifier** trained on port, service, version, and host attributes to predict multi-tier risk levels (`Low`, `Medium`, `High`, `Critical`), delivering prioritized remediation guidance.

---

## 🌟 Key Capabilities

### 🌐 Web Application Security
- **Injection Detection:** Heuristic- and payload-based discovery for SQL Injection (SQLi) and Reflected/Stored Cross-Site Scripting (XSS).
- **Hardening Checks:** Automated inspection of modern HTTP security headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`).
- **Surface Discovery:** Sensitive directory brute-forcing, server version disclosure, and technology stack fingerprinting.

### 🔌 Network Reconnaissance
- **Host & Service Profiling:** Active host discovery, deep TCP/UDP port mapping, and live banner grabbing powered by Nmap integration.
- **OS & Version Fingerprinting:** Precision operating system detection and version mapping across exposed network services.

### 🔒 SSL / TLS Assessment
- **Certificate Verification:** Chain validation, hostname verification, and proactive certificate expiry warnings.
- **Protocol & Cipher Auditing:** Identifies legacy protocols (TLS 1.0/1.1) and evaluates cryptographic cipher suite strength.

### 🧠 Predictive Risk Scoring & CVE Intelligence
- **Machine Learning Classifier:** Employs a trained Random Forest model that ingests multi-dimensional host parameters (`Port`, `Protocol`, `Service`, `Version`, `OS`, `Open Port Count`) to classify risk profiles.
- **CVE Mapping:** Dynamically links discovered services and versions against known CVE indexes for contextual threat reporting.

---

## ⚙️ Architecture & Modules

| Module | Core Methodology | Primary Objective |
| :--- | :--- | :--- |
| **Web Scanner** | Signature & Payload Response Analysis | Identify client-side & server-side web flaws |
| **Network Engine** | Nmap Scripting Engine & Version Scanning | Enumerate open attack vectors and services |
| **SSL/TLS Inspector**| Socket & OpenSSL Handshake Inspection | Expose weak cryptography & expired certs |
| **Risk Classifier** | Random Forest + Feature Encoders (TF-IDF/Joblib) | Quantify threat level into actionable tiers |
| **CVE Correlator** | Service-to-Vulnerability Mapping | Provide contextual intelligence & remediation steps |

---

## 🛠️ Technology Stack

```
Frontend            HTML5 • CSS3 • Modern JavaScript • Bootstrap 5
Backend Core        Python 3.9+ • Flask • SQLAlchemy • Jinja2
Database            SQLite (Development / Default)
Machine Learning    Scikit-learn • Random Forest • TF-IDF • Joblib
Networking & Tools  Nmap Core • Requests • BeautifulSoup4 • Socket • SSL
```

---

## 📁 Repository Structure

```text
SURAKSHA/
├── app.py                 # Flask server initialization and routing logic
├── database/              # SQLite instances and database migration schemas
├── datasets/              # Vulnerability datasets and ML training corpora
├── models/                # Serialized model pipelines (.pkl / Joblib)
├── scanner/               # Detection modules (web, network, ssl, nmap)
├── static/                # Stylesheets, JavaScript plugins, and static assets
├── templates/             # Responsive Bootstrap dashboard templates
├── requirements.txt       # Environment dependencies
└── README.md              # Project documentation
```

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.9+** installed on your system.
- **Nmap** binary installed and added to your system environment variable path:
  ```bash
  # Linux (Ubuntu/Debian)
  sudo apt install nmap

  # macOS (Homebrew)
  brew install nmap
  ```

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/SURAKSHA.git
   cd SURAKSHA
   ```

2. **Create and activate a virtual environment:**
   ```bash
   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate

   # Windows
   python -m venv venv
   venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Launch the platform:**
   ```bash
   python app.py
   ```

5. **Access the web console:**
   Navigate to `http://127.0.0.1:5000` in your web browser.

---

## 📊 Sample Output & Dashboard

The web interface compiles comprehensive vulnerability statistics, including:
- **Scan History & Trends:** Visual breakdown of scans conducted across subnets.
- **Risk Severity Breakdown:** Color-coded threat categorizations (`Low`, `Medium`, `High`, `Critical`).
- **Exportable Reports:** Detailed audit summaries with timestamped CVE associations and recommended mitigations.

---

## ⚖️ Disclaimer

> **Notice:** SURAKSHA is developed exclusively for educational, authorized penetration testing, and system auditing purposes. Executing vulnerability scans against target networks or hosts without explicit prior authorization is illegal. Use responsibly.