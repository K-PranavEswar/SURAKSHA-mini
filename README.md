# SURAKSHA – A Rule Based Vulnerability Scanner with Risk Prediction

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&height=220&color=DC2626&text=SURAKSHA&fontColor=FFFFFF&fontSize=48&fontAlign=50&fontAlignY=38&desc=Advanced%20Web%20Application%20and%20Network%20Vulnerability%20Scanner&descAlign=50&descAlignY=60&descSize=18&descColor=FFF5F5" width="100%" />

<br>

<p align="center">
<img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white"/>
<img src="https://img.shields.io/badge/SQLite-07405E?style=for-the-badge&logo=sqlite&logoColor=white"/>
<img src="https://img.shields.io/badge/Bootstrap-7952B3?style=for-the-badge&logo=bootstrap&logoColor=white"/>
<img src="https://img.shields.io/badge/Nmap-217346?style=for-the-badge"/>
<img src="https://img.shields.io/badge/Scapy-CC0000?style=for-the-badge"/>
<img src="https://img.shields.io/badge/Machine%20Learning-Random%20Forest-orange?style=for-the-badge"/>
</p>

> **An intelligent cybersecurity platform for authorized web vulnerability assessment, network reconnaissance, AI-assisted risk prediction, SSL analysis, traffic monitoring, and professional security reporting.**

</div>

---

# 📖 Overview

**SURAKSHA** is an intelligent cybersecurity platform developed using **Python** and **Flask** to perform comprehensive web application and network security assessments. It combines automated vulnerability detection, network reconnaissance, SSL security analysis, AI-powered risk prediction, protocol analysis, and professional reporting within a single platform.

The system enables administrators and security analysts to identify vulnerabilities such as SQL Injection (SQLi), Cross-Site Scripting (XSS), missing HTTP security headers, exposed services, insecure SSL configurations, and vulnerable network ports. It also integrates machine learning using a **Random Forest Classifier** to predict network risk levels based on service characteristics and scan results.

SURAKSHA provides a centralized dashboard that allows users to perform scans, monitor results, analyze vulnerabilities, classify security risks, and generate detailed reports for remediation.

---

# ✨ Features

## 🌐 Web Vulnerability Scanner

* SQL Injection Detection
* Cross-Site Scripting (XSS) Detection
* HTTP Security Header Analysis
* Sensitive Directory Discovery
* Technology Detection
* Server Fingerprinting
* Risk Classification

---

## 📡 Network Scanner

* Host Discovery
* TCP SYN Port Scanning
* Banner Grabbing
* Service Enumeration
* Version Detection
* Operating System Detection
* Open Port Analysis
* Intelligent Risk Classification

---

## 🤖 AI Risk Prediction

SURAKSHA integrates a Machine Learning model trained using a **Random Forest Classifier**.

### AI Features

* AI-Based Network Risk Prediction
* Confidence Score Generation
* Service Behaviour Analysis
* Version-Based Risk Assessment
* Operating System Correlation
* Overall Risk Classification

### Prediction Parameters

* Port Number
* Protocol
* Service
* Version
* Operating System
* Number of Open Ports

---

## 🔍 Vulnerability Intelligence

The platform correlates detected services with a built-in vulnerability knowledge base.

Features include

* CVE Mapping
* Port-Based Vulnerability Identification
* Severity Classification
* Recommended Mitigation
* Security Best Practices

Supported Risk Levels

* Critical
* High
* Medium
* Low

---

## 🔒 SSL Security Analysis

* SSL Certificate Validation
* Certificate Expiry Detection
* Hostname Verification
* TLS Version Analysis
* Encryption Strength Assessment

---

## 📈 Traffic Monitoring

Using **Scapy**, SURAKSHA provides

* Live Packet Capture
* Protocol Identification
* Source/Destination Analysis
* Website Resolution
* Traffic Classification
* Risk Assessment

---

## 📊 Dashboard

Interactive dashboard displaying

* Total Scans
* Risk Distribution
* Open Ports
* Vulnerability Statistics
* Scan History
* AI Confidence
* CVE Count

---

## 📄 Security Reports

Generate professional reports including

* Executive Summary
* Vulnerability Details
* Risk Assessment
* AI Prediction
* Security Recommendations
* Scan Timestamp

---

# 🧠 Core Algorithms

| Module            | Algorithm / Technique                  |
| ----------------- | -------------------------------------- |
| Web Scanner       | Signature-Based Detection              |
| SQL Injection     | Payload Analysis & Response Comparison |
| XSS Detection     | Reflected Payload Detection            |
| Security Headers  | Rule-Based Analysis                    |
| Network Scanner   | TCP SYN Scan (Nmap)                    |
| Banner Detection  | Service Fingerprinting                 |
| Version Detection | Nmap Version Enumeration               |
| OS Detection      | Nmap OS Fingerprinting                 |
| AI Prediction     | Random Forest Classifier               |
| Risk Engine       | Rule-Based Risk Scoring                |
| CVE Mapper        | Port & Service Correlation             |
| Traffic Monitor   | Live Packet Inspection (Scapy)         |

---

# 💻 Technology Stack

## Frontend

* HTML5
* CSS3
* JavaScript
* Bootstrap 5

## Backend

* Python
* Flask

## Database

* SQLite

## Machine Learning

* Scikit-learn
* Joblib
* Random Forest

## Cybersecurity Libraries

* python-nmap
* Scapy
* Requests
* Socket
* SSL
* BeautifulSoup4
* urllib3
* WHOIS

---

# 📁 Project Structure

```text
SURAKSHA
│
├── ai/
├── database/
├── datasets/
├── ml/
├── models/
├── scanner/
├── templates/
├── static/
├── app.py
├── requirements.txt
└── README.md
```

---

# 📂 Major Modules

```
Dashboard

Authentication

Web Scanner

Network Scanner

SSL Checker

Traffic Monitor

SQL Analyzer

AI Risk Predictor

Protocol Analyzer

CVE Mapper

Report Generator

Admin Panel
```

---

# 📊 AI Prediction Engine

Input Features

* Port
* Protocol
* Service
* Version
* Operating System
* Open Ports

Output

* Low
* Medium
* High
* Critical

Also provides

* AI Confidence (%)
* Risk Classification
* Security Recommendation

---

# 🛡 Supported Vulnerability Detection

### Web

* SQL Injection
* Cross Site Scripting
* Missing Security Headers
* Sensitive Directories
* Server Disclosure

### Network

* Open Ports
* Insecure Services
* Banner Information
* Operating System
* CVE Mapping

### SSL

* Invalid Certificates
* Expired Certificates
* Weak TLS
* Hostname Mismatch

---

# 🚀 Installation

## Clone Repository

```bash
git clone https://github.com/yourusername/SURAKSHA.git
cd SURAKSHA
```

---

## Create Virtual Environment

Windows

```bash
python -m venv venv
venv\Scripts\activate
```

Linux

```bash
python3 -m venv venv
source venv/bin/activate
```

---

## Install Requirements

```bash
pip install -r requirements.txt
```

---

## Install Nmap

Download

https://nmap.org/download.html

Verify

```bash
nmap --version
```

---

## Run Application

```bash
python app.py
```

Open

```
http://127.0.0.1:5000
```

---

# 🎯 Recommended Test Targets

## Web

* http://testphp.vulnweb.com
* https://demo.testfire.net
* https://demo.owasp-juice.shop

## Network

* scanme.nmap.org
* localhost
* 127.0.0.1

## SSL

* https://badssl.com

---

# 📸 Screenshots

Include screenshots of

* Login
* Dashboard
* Web Scanner
* Network Scanner
* SSL Checker
* Traffic Monitor
* Reports
* Admin Dashboard

---

# 🚀 Future Enhancements

* AI-Based Vulnerability Detection using Deep Learning
* Automated CVE Database Updates
* Real-Time Threat Intelligence Integration
* Cloud Asset Discovery
* Distributed Network Scanning
* Scheduled Security Assessments
* Email Alert System
* PDF Report Enhancements
* Multi-user Collaboration
* SIEM Integration

---

# ⚠ Legal Disclaimer

SURAKSHA is developed strictly for **educational, research, and authorized cybersecurity assessment purposes only**.

Users must obtain proper authorization before scanning any website, server, or network. Unauthorized vulnerability assessment or penetration testing may violate applicable laws and regulations.

The developer assumes no responsibility for misuse of this software.

---

# 👨‍💻 Developer

**K Pranav Eswar**

MCA Student

Python • Flask • Cybersecurity • Machine Learning

---

<div align="center">

### ⭐ If you like this project, consider giving it a Star ⭐

**Made with ❤️ using Python & Flask**

</div>
