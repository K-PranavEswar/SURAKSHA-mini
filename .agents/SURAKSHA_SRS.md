# SOFTWARE REQUIREMENTS SPECIFICATION (SRS)

# SURAKSHA -- An Intelligent Rule-Based Vulnerability Scanner

**Project Type:** MCA Mini Project\
**Application Type:** Web-Based Cybersecurity Vulnerability Assessment
Platform\
**Backend:** Python + Flask\
**Database:** SQLite

------------------------------------------------------------------------

## 1. Introduction

### 1.1 Project Overview

SURAKSHA is a web-based cybersecurity vulnerability assessment platform
that integrates web vulnerability scanning, network reconnaissance,
SSL/TLS security analysis, protocol analysis, CVE mapping, and
machine-learning-assisted risk prediction into a unified workflow.

The system follows a hybrid approach:

-   Rule-based and signature-based vulnerability detection.
-   Payload-based web security testing and response analysis.
-   Nmap-based network reconnaissance.
-   SSL/TLS certificate and configuration analysis.
-   CVE mapping using detected service/version information.
-   Random Forest-based machine-learning assistance.
-   Centralized storage of users, scans, and vulnerability findings.
-   Security reporting with severity, priority, risk score, evidence,
    and recommendations.

------------------------------------------------------------------------

## 2. Problem Statement

Modern web applications and networked systems expose multiple attack
surfaces. SQL Injection, Cross-Site Scripting (XSS), exposed services,
insecure configurations, and weak transport-security configurations
require different detection and analysis techniques.

Recent research demonstrates machine-learning approaches for web attack
detection and cybersecurity risk assessment. UniEmbed investigates XSS
and SQL Injection detection using Word2Vec, Universal Sentence Encoder
(USE), FastText, and machine-learning classifiers. FRAPE investigates
machine-learning-based vulnerability risk classification,
prioritization, and explainability. A 2026 study combines automated
vulnerability scanning, CVSS-based assessment, and Random Forest
classification for cyber-threat and risk assessment.

The literature also identifies challenges including limited dataset
diversity, limited real-world generalization, unseen attacks,
explainability, robustness, and evaluation standardization.

**SURAKSHA addresses this problem by integrating web vulnerability
testing, network reconnaissance, SSL/TLS analysis, protocol analysis,
CVE mapping, and ML-assisted risk prediction in a single modular
Flask-based platform.**

------------------------------------------------------------------------

## 3. Proposed System

SURAKSHA provides a centralized workflow:

``` text
Target Input
     ↓
Authentication & Scan Configuration
     ↓
Scan Selection
     ↓
Web Scan / Network Scan / SSL-TLS Check
     ↓
Result & Evidence Analysis
     ↓
Protocol Analysis + CVE Mapping
     ↓
ML-Based Risk Prediction
     ↓
Risk Assessment
     ↓
SQLite Database
     ↓
Security Reports
     ↓
Dashboard
```

The ML component supports the security assessment; ML output alone is
not treated as proof of a vulnerability.

------------------------------------------------------------------------

## 4. Objectives

1.  Develop a centralized web-based vulnerability assessment platform.
2.  Detect common web application security weaknesses.
3.  Perform network reconnaissance and service discovery.
4.  Analyze SSL/TLS configurations.
5.  Analyze protocols and exposed services.
6.  Map detected vulnerabilities/services to CVE references.
7.  Apply machine learning to assist risk prediction.
8.  Store scan and vulnerability information systematically.
9.  Generate consolidated security reports.
10. Present severity, priority, risk score, evidence, and
    recommendations.

------------------------------------------------------------------------

## 5. Scope

### In Scope

-   User authentication.
-   Web vulnerability assessment.
-   SQL Injection testing.
-   XSS testing.
-   Security-header analysis.
-   Sensitive-path detection.
-   Network port/service/version detection.
-   Banner and protocol analysis.
-   SSL/TLS analysis.
-   CVE mapping.
-   ML-assisted risk prediction.
-   Scan history and vulnerability storage.
-   Security reports.
-   Admin dashboard, user management, and report monitoring.

### Out of Scope

-   Unauthorized scanning.
-   Destructive exploitation.
-   Automatic patch deployment.
-   Guaranteed vulnerability discovery.
-   Enterprise SIEM functionality.
-   Replacement for professional penetration testing.

All active scanning must be performed only against authorized targets.

------------------------------------------------------------------------

## 6. Core Modules

### 6.1 Web Vulnerability Scanning

Detects common web security weaknesses.

**Functions:**

-   URL and parameter assessment.
-   SQL Injection testing.
-   XSS testing.
-   Security-header analysis.
-   Sensitive-path detection.
-   Technology detection.
-   Response analysis.
-   Evidence collection.

#### SQL Injection

SURAKSHA assesses:

-   Error-Based SQL Injection.
-   Boolean-Based SQL Injection.
-   UNION-Based SQL Injection.
-   Time-Based SQL Injection.
-   SQL response/error analysis.
-   ML-assisted payload classification.

Flow:

``` text
Target Parameter
      ↓
Controlled SQLi Payloads
      ↓
Error / Boolean / UNION / Time Tests
      ↓
Response Analysis
      ↓
SQLi Evidence
      ↓
TF-IDF + Random Forest Payload Classification
      ↓
Risk Assessment
```

#### XSS

XSS assessment uses controlled payload testing and response/content
analysis to identify indicators of script injection.

------------------------------------------------------------------------

### 6.2 Network Reconnaissance

Collects information about authorized network targets.

**Functions:**

-   Port scanning.
-   Service detection.
-   Version detection.
-   OS detection where supported.
-   Banner grabbing.
-   Service/protocol identification.

**Primary tool:** Nmap.

------------------------------------------------------------------------

### 6.3 SSL/TLS Security Analysis

Evaluates HTTPS/TLS configuration.

**Functions:**

-   Certificate inspection.
-   Certificate validity.
-   Issuer information.
-   Expiry information.
-   TLS version identification.
-   Transport-security analysis.
-   Security issue identification.
-   Recommendations.

SSL/TLS results are associated with scan records and presented through
reports.

------------------------------------------------------------------------

### 6.4 Protocol Analysis

Analyzes discovered network services and protocols.

**Functions:**

-   Protocol/service identification.
-   Banner analysis.
-   Version analysis.
-   Service exposure assessment.
-   Protocol-related security observations.

------------------------------------------------------------------------

### 6.5 CVE Mapping

Maps detected service/version information to known CVE references where
applicable.

**Functions:**

-   Service/version matching.
-   CVE identification.
-   CVE reference storage.
-   Vulnerability description.
-   Severity information.
-   Remediation recommendation.

Flow:

``` text
Port → Service → Version → CVE Mapping → Severity → Recommendation
```

------------------------------------------------------------------------

### 6.6 Machine-Learning-Based Risk Prediction

ML assists classification and risk assessment.

#### Network ML

-   Algorithm: Random Forest.
-   Dataset: `datasets/network_risk_dataset.csv`.
-   Model: `models/network_risk_model.pkl`.

Attributes:

``` text
port
protocol
service
version
os
open_ports
risk
category
```

#### SQL Injection ML

-   Dataset: `datasets/sqli.csv`.
-   Records: 4,200.
-   Attributes: `Sentence`, `Label`.
-   Label 0: benign/normal text.
-   Label 1: SQL Injection.
-   Representation: TF-IDF.
-   Algorithm: Random Forest.
-   Model: `models/sqli_model.pkl`.

The SQLi model is a supporting payload classifier and should not be
interpreted as a universal live-vulnerability detector.

------------------------------------------------------------------------

## 7. Risk and Priority Mapping

  Severity          Priority   Risk Score
  --------------- ---------- ------------
  Critical                P1      100/100
  High                    P2       80/100
  Medium                  P3       60/100
  Low                     P4       40/100
  Informational           P5       20/100
  None                    P6       10/100

Priority and risk score are calculated dynamically from the actual
severity/risk value.

------------------------------------------------------------------------

## 8. Users and Functionalities

### 8.1 User

-   Register.
-   Secure login/logout.
-   Access dashboard.
-   Configure scans.
-   Perform web scanning.
-   Perform network reconnaissance.
-   Perform SSL/TLS checks.
-   Analyze protocols/services.
-   View CVE information.
-   View scan history.
-   View security reports.
-   Review vulnerability evidence.
-   View remediation recommendations.

### 8.2 Administrator

-   Secure admin login.
-   View dashboard statistics.
-   Manage registered users.
-   View user information.
-   View reports.
-   Monitor scan activity.
-   Review severity and priority.
-   Monitor risk scores.
-   Access historical scan information.
-   Logout.

The separate Admin Vulnerabilities navigation page is not part of the
final Admin workflow, while the underlying vulnerability database
remains required for scanning and reporting.

------------------------------------------------------------------------

## 9. System Workflow

### User Workflow

``` text
User
 ↓
Registration / Login
 ↓
Dashboard
 ↓
Select Scan Type
 ↓
Enter Authorized Target
 ↓
Start Scan
 ↓
Scanner Execution
 ↓
Result Collection
 ↓
Evidence Analysis
 ↓
CVE Mapping
 ↓
ML Risk Prediction
 ↓
Severity & Priority
 ↓
Database Storage
 ↓
Security Report
 ↓
User
```

### Network Workflow

``` text
Target
 ↓
Nmap
 ↓
Port Detection
 ↓
Service Detection
 ↓
Version Detection
 ↓
OS Detection
 ↓
Banner / Protocol Analysis
 ↓
CVE Mapping
 ↓
Random Forest Risk Prediction
 ↓
Risk Assessment
 ↓
Report
```

### SSL/TLS Workflow

``` text
Target Domain
 ↓
TLS Connection
 ↓
Certificate Inspection
 ↓
Issuer / Expiry Analysis
 ↓
TLS Version Analysis
 ↓
Security Configuration Analysis
 ↓
Severity Assessment
 ↓
Store Result
 ↓
Report
```

------------------------------------------------------------------------

## 10. System Architecture

``` text
┌─────────────────────────────────────┐
│          Presentation Layer         │
│ HTML / CSS / JavaScript / Jinja2    │
└──────────────────┬──────────────────┘
                   ↓
┌─────────────────────────────────────┐
│          Flask Application           │
│ Authentication / Routes / Reports   │
└──────────────────┬──────────────────┘
                   ↓
┌─────────────────────────────────────┐
│            Scanner Layer             │
│ Web | Network | SSL/TLS | Protocol  │
└──────────────────┬──────────────────┘
                   ↓
┌─────────────────────────────────────┐
│           Analysis Layer             │
│ Response Analysis | CVE | Risk | ML │
└──────────────────┬──────────────────┘
                   ↓
┌─────────────────────────────────────┐
│             SQLite DB                │
│ User | Scans | Vulnerability        │
└─────────────────────────────────────┘
```

------------------------------------------------------------------------

## 11. Database Design

**Database:** SQLite\
**File:** `database/scanner.db`

### `user`

  Field      Type           Constraint
  ---------- -------------- -----------------------
  id         INTEGER        Primary Key, NOT NULL
  username   VARCHAR(100)   NOT NULL
  email      VARCHAR(120)   NOT NULL, UNIQUE
  password   VARCHAR(255)   NOT NULL

### `scans`

  Field        Type           Constraint
  ------------ -------------- -----------------------
  id           INTEGER        Primary Key, NOT NULL
  target       VARCHAR(255)   NOT NULL
  scan_type    VARCHAR(100)   NOT NULL
  severity     VARCHAR(50)    NOT NULL
  status       VARCHAR(50)    Nullable
  open_ports   INTEGER        Nullable
  details      TEXT           Nullable
  user_id      INTEGER        NOT NULL, Foreign Key
  created_at   DATETIME       Nullable

Relationship:

``` text
scans.user_id → user.id
```

### `vulnerability`

  Field                Type           Constraint
  -------------------- -------------- -----------------------
  id                   INTEGER        Primary Key, NOT NULL
  port                 INTEGER        NOT NULL
  service              VARCHAR(100)   NOT NULL
  protocol             VARCHAR(50)    Nullable
  vulnerability_name   VARCHAR(255)   NOT NULL
  cve_id               VARCHAR(100)   Nullable
  severity             VARCHAR(50)    NOT NULL
  attack_type          VARCHAR(255)   Nullable
  description          TEXT           Nullable
  recommendation       TEXT           Nullable
  scan_id              INTEGER        Foreign Key

Relationship:

``` text
vulnerability.scan_id → scans.id
```

### Database Relationship

``` text
USER
 │
 │ 1
 └────────< SCANS
             │
             │ 1
             └────────< VULNERABILITY
```

------------------------------------------------------------------------

## 12. Dataset Description

### SQL Injection Dataset

**File:** `datasets/sqli.csv`

**Records:** 4,200

**Attributes:**

-   Sentence
-   Label

**Distribution:**

-   Label 0: 3,072
-   Label 1: 1,128

The dataset is used for SQL Injection payload classification.

### Network Risk Dataset

**File:** `datasets/network_risk_dataset.csv`

**Attributes:**

-   port
-   protocol
-   service
-   version
-   os
-   open_ports
-   risk
-   category

The dataset supports Random Forest-based network risk prediction.

------------------------------------------------------------------------

## 13. Functional Requirements

### Authentication

-   User registration.
-   User login.
-   Secure logout.
-   Administrator authentication.
-   Access control for protected pages.

### Web Scanning

-   Accept authorized URL.
-   Perform SQL Injection assessment.
-   Perform XSS assessment.
-   Analyze security headers.
-   Detect selected sensitive paths.
-   Store findings.

### Network Scanning

-   Accept authorized target.
-   Detect ports.
-   Detect services.
-   Detect versions.
-   Detect OS where supported.
-   Collect banners.

### SSL/TLS

-   Inspect certificates.
-   Analyze TLS versions.
-   Identify security issues.
-   Store scan results.

### CVE Mapping

-   Match service/version information.
-   Identify applicable CVEs.
-   Display descriptions and severity.

### ML

-   Load trained models.
-   Generate supported predictions.
-   Provide classification information.
-   Use ML as supporting evidence.

### Reporting

-   Store scan history.
-   Display severity.
-   Calculate priority/risk score.
-   Display evidence.
-   Display CVE information.
-   Display recommendations.

------------------------------------------------------------------------

## 14. Non-Functional Requirements

### Security

-   Passwords must not be stored in plain text.
-   Protected routes require authentication.
-   Scanner should be used only against authorized targets.
-   Input validation should be applied.

### Performance

-   Scanner operations should complete within reasonable limits.
-   ML models should be loaded efficiently.
-   Database access should avoid unnecessary repeated queries.

### Reliability

-   Network timeouts should be handled gracefully.
-   Scanner failures should not crash the application.
-   Missing CVE information should not stop report generation.

### Usability

-   Clear scan status.
-   Readable reports.
-   Severity-based visual indicators.
-   Clear findings and recommendations.

### Maintainability

-   Modular scanner components.
-   Separation of detection, analysis, ML, and presentation logic.
-   Separate model files and datasets.

------------------------------------------------------------------------

## 15. Technology Stack

### Frontend

-   HTML5
-   CSS3
-   JavaScript
-   Jinja2

### Backend

-   Python
-   Flask
-   SQLAlchemy / Flask-SQLAlchemy where configured

### Database

-   SQLite

### Security Tools/Libraries

-   Nmap
-   Requests
-   BeautifulSoup
-   SSL/TLS libraries

### Machine Learning

-   Scikit-learn
-   Random Forest
-   TF-IDF
-   Joblib

### Data Processing

-   Pandas
-   NumPy
-   Matplotlib where applicable

### Development

-   Visual Studio Code
-   Git
-   GitHub
-   Python virtual environment

------------------------------------------------------------------------

## 16. Current Results

### SQL Injection ML Model

Current evaluation:

-   Accuracy: 97.06%
-   Precision: 97.35%
-   Recall: 97.06%
-   F1-score: 97.10%

Confusion matrix:

``` text
[[882, 37],
 [  0, 338]]
```

These are evaluation metrics for the dataset and are not a 97.06%
guarantee that a live target is vulnerable.

### Network Risk Model

Current evaluation:

-   Accuracy: 76.40%
-   Precision: 77.18%
-   Recall: 76.40%
-   F1-score: 76.42%
-   Cross-validation average: 76.40%

------------------------------------------------------------------------

## 17. Project Structure

``` text
SURAKSHA/
├── ai/
├── database/
│   └── scanner.db
├── datasets/
│   ├── sqli.csv
│   └── network_risk_dataset.csv
├── ml/
│   └── train_network_model.py
├── models/
│   ├── network_risk_model.pkl
│   └── sqli_model.pkl
├── scanner/
│   ├── ai_risk_predictor.py
│   ├── banner_grabber.py
│   ├── cve_mapper.py
│   ├── network_scan.py
│   ├── protocol_analyzer.py
│   ├── result_parser.py
│   ├── risk_engine.py
│   ├── scan_builder.py
│   ├── sql_analyzer.py
│   ├── sql_detector.py
│   ├── sql_payloads.py
│   ├── sql_risk.py
│   ├── ssl_checker.py
│   ├── tech_detector.py
│   ├── waf_detector.py
│   └── web_scan.py
├── templates/
├── app.py
└── requirements.txt
```

------------------------------------------------------------------------

## 18. Research Gap

The selected literature demonstrates strong approaches for individual
cybersecurity problems:

-   ML-based SQL Injection detection.
-   ML-based XSS detection.
-   Feature-fusion approaches.
-   ML-based vulnerability risk classification.
-   Automated vulnerability scanning.
-   CVSS/risk-based assessment.
-   Explainable vulnerability prioritization.

SURAKSHA focuses on integrating these assessment stages into a single
modular workflow:

``` text
Web Assessment
       +
Network Reconnaissance
       +
SSL/TLS Analysis
       +
Protocol Analysis
       +
CVE Mapping
       +
ML-Assisted Risk Prediction
       ↓
Integrated Vulnerability Assessment
```

The project therefore emphasizes integration, modularity, practical
assessment workflow, and a clear separation between vulnerability
evidence and ML-assisted prediction.

------------------------------------------------------------------------

## 19. Current Limitations

1.  Dataset size and diversity are limited compared with large
    production datasets.
2.  The SQL Injection dataset primarily represents benign text versus
    SQLi payload classification.
3.  ML models may not generalize to all real-world attack variants.
4.  Obfuscated and unseen attacks need additional evaluation.
5.  CVE mapping depends on accurate service/version information.
6.  Network scanning depends on scanner availability and target
    accessibility.
7.  SSL/TLS findings depend on information available from the target.
8.  Current ML models require broader cross-dataset validation.
9.  The system is not a replacement for professional penetration
    testing.

------------------------------------------------------------------------

## 20. Future Enhancements

-   Expand datasets and attack types.
-   Detect obfuscated and unseen attacks.
-   Use advanced feature extraction methods.
-   Apply ensemble machine-learning models.
-   Improve CVE updates and security recommendations.
-   Add explainable AI.
-   Improve cross-dataset evaluation.
-   Add robustness/adversarial testing.
-   Support continuous security monitoring.
-   Evaluate using authorized laboratory applications.
-   Improve real-time vulnerability assessment.
-   Explore scalable cloud deployment.

------------------------------------------------------------------------

## 21. Testing Strategy

### Functional Testing

-   Registration.
-   Login/logout.
-   Web scan.
-   Network scan.
-   SSL/TLS check.
-   CVE mapping.
-   ML prediction.
-   Report generation.
-   Search and filtering.
-   Admin user management.

### Security Testing

-   Authentication.
-   Access control.
-   Input validation.
-   Session handling.
-   SQL Injection resistance.
-   XSS resistance.
-   Sensitive-data exposure.

### ML Testing

-   Accuracy.
-   Precision.
-   Recall.
-   F1-score.
-   Confusion matrix.
-   Cross-validation.
-   Class imbalance.
-   Data leakage.
-   Unseen-attack testing.
-   Cross-dataset generalization.

------------------------------------------------------------------------

## 22. Ethical Requirements

SURAKSHA is intended for authorized security assessment.

The system should:

-   Scan only authorized targets.
-   Avoid destructive payloads.
-   Avoid unauthorized exploitation.
-   Preserve evidence.
-   Distinguish ML predictions from confirmed vulnerability evidence.
-   Protect stored user and scan information.
-   Clearly communicate uncertainty.

------------------------------------------------------------------------

## 23. Expected Benefits

-   Centralized vulnerability assessment.
-   Reduced need to switch between multiple basic tools.
-   Automated initial security analysis.
-   Structured vulnerability evidence.
-   CVE-oriented information.
-   ML-assisted risk assessment.
-   Centralized scan history.
-   Easier report interpretation.
-   Modular foundation for future research.

------------------------------------------------------------------------

## 24. Conclusion

SURAKSHA provides an integrated approach to web and network
vulnerability assessment by combining rule-based security testing,
automated network reconnaissance, SSL/TLS analysis, protocol analysis,
CVE mapping, and machine-learning-assisted risk prediction.

The system separates vulnerability detection from risk interpretation
and stores results in a structured SQLite database. Web and network
scanners provide security evidence, CVE mapping adds known-vulnerability
context, and machine-learning components assist classification and risk
prediction.

The current implementation demonstrates the feasibility of combining
these components in a Flask-based academic cybersecurity platform.
Future work will focus on larger and more diverse datasets, unseen and
obfuscated attack detection, richer feature representations, ensemble
learning, explainability, stronger evaluation methodology, and
authorized real-world testing.

------------------------------------------------------------------------

## 25. Literature References

1.  R. Bakır, **"UniEmbed: A Novel Approach to Detect XSS and SQL
    Injection Attacks Leveraging Multiple Feature Fusion with Machine
    Learning Techniques,"** Arabian Journal for Science and
    Engineering, 2025. DOI: `10.1007/s13369-024-09916-4`.

2.  F. R. Parente, E. B. Rodrigues, and C. L. C. Mattos, **"FRAPE: A
    Framework for Risk Assessment, Prioritization and Explainability of
    Vulnerabilities in Cybersecurity,"** Journal of Information Security
    and Applications, 2025. DOI: `10.1016/j.jisa.2025.103971`.

3.  K. Prasanna, J. Prajapati, and U. Patel, **"AI Driven Cyber Threat
    Classification and Risk Assessment for IoT Ecosystem Security,"**
    Discover Artificial Intelligence, 2026. DOI:
    `10.1007/s44163-026-01748-5`.

4.  **"Cybersecurity in the Age of Generative AI: A Systematic Taxonomy
    of AI-Powered Vulnerability Assessment and Risk Management,"**
    Future Generation Computer Systems, 2026. DOI:
    `10.1016/j.future.2025.108107`.

5.  **"Vulnerabilities in Machine Learning for Cybersecurity: Current
    Trends and Future Research Directions,"** Journal of Information
    Security and Applications, 2026. DOI: `10.1016/j.jisa.2025.104269`.

6.  Nmap Documentation.

7.  Flask Documentation.

8.  Scikit-learn Documentation.

9.  SQLite Documentation.

------------------------------------------------------------------------

# 26. Quick Project Summary

  -----------------------------------------------------------------------
  Category                            SURAKSHA
  ----------------------------------- -----------------------------------
  Project                             Intelligent Rule-Based
                                      Vulnerability Scanner

  Type                                Web-based cybersecurity assessment
                                      platform

  Backend                             Python + Flask

  Database                            SQLite

  Web Assessment                      SQLi, XSS, headers, sensitive paths

  Network Assessment                  Ports, services, versions, OS,
                                      banners

  SSL/TLS                             Certificate and TLS analysis

  Protocol                            Service/protocol analysis

  Vulnerability Intelligence          CVE mapping

  ML                                  Random Forest

  SQLi ML                             TF-IDF + Random Forest

  Network ML                          Random Forest

  Reports                             Findings, severity, priority, risk
                                      score, CVE, recommendations

  Users                               User + Administrator

  Main Goal                           Integrated vulnerability assessment
                                      and risk analysis
  -----------------------------------------------------------------------

------------------------------------------------------------------------

**End of SRS**
