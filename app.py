import os, json, re
import urllib.parse
import warnings
from dotenv import load_dotenv
load_dotenv()
warnings.filterwarnings("ignore")
from datetime import datetime
from sqlalchemy import or_
from flask import (
    Flask, render_template, redirect, url_for,
    request, flash, jsonify, send_file
)
from flask_cors import CORS
from flask_login import (
    LoginManager, login_user, login_required,
    logout_user, current_user
)
from flask_bcrypt import Bcrypt
from reportlab.platypus import (
    SimpleDocTemplate, Table,
    TableStyle, Paragraph, Spacer
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

from models import db
from models.user_model import User
from models.scan_model import Scan
from models.vulnerability_model import Vulnerability
from models.shareable_report_model import ShareableReport
from scanner.network_scan import run_network_scan
from scanner.web_scan import run_web_scan
from scanner.ssl_checker import run_ssl_check, build_ssl_report_email, discover_contact_email
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded
from flask import abort
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(BASE_DIR, "database", "scanner.db")
app = Flask(__name__)
CORS(app)
blocked_ips = set()
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per minute"],
    storage_uri="memory://"
)

@app.context_processor
def inject_emailjs_config():
    return {
        "emailjs_service_id": os.environ.get("EMAILJS_SERVICE_ID", "service_gma17jk"),
        "emailjs_template_id": os.environ.get("EMAILJS_TEMPLATE_ID", ""),
        "emailjs_public_key": os.environ.get("EMAILJS_PUBLIC_KEY", ""),
    }

@app.errorhandler(429)
def ratelimit_handler(error):

    return render_template(
        "rate_limit.html",
        retry_after=30
    ), 429  
from flask import jsonify, request
from ai.helpdesk_ai import HELPDESK
@app.route("/helpdesk", methods=["GET", "POST"])
def helpdesk():

    if request.method == "GET":
        return jsonify(
            HELPDESK["main"]
        )
    data = request.get_json()
    topic = data.get(
        "topic",
        "main"
    )
    if topic == "Back":
        topic = "main"
    return jsonify(
        HELPDESK.get(
            topic,
            HELPDESK["main"]
        )
    )

#-----------------App Configuration-----------------
#         
@app.template_filter("from_json")
def from_json(value):
    return json.loads(value) if value else {}
app.config["SECRET_KEY"] = "vulnerability_scanner_secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
@login_manager.user_loader
def load_user(user_id):
        return db.session.get(
            User,
            int(user_id)
        )

#-----------------Vulnerability Synchronization-----------------
def extract_and_store_vulnerabilities(scan):
    try:
        details = json.loads(scan.details) if scan.details else {}
    except (json.JSONDecodeError, TypeError):
        return

    vulns_to_add = []

    # =========================================================
    # NETWORK SCAN
    # =========================================================
    if scan.scan_type == "Network":

        for v in details.get("vulnerabilities", []):
            if not v.get("vulnerability"):
                continue

            new_vuln = Vulnerability(
                port=int(v.get("port") or 0),
                service=v.get("service") or "N/A",
                protocol=v.get("protocol") or "TCP",
                vulnerability_name=v.get("vulnerability"),
                cve_id=v.get("cve"),
                severity=v.get("risk_level") or "Informational",
                attack_type=v.get("attack_type"),
                description=(
                    f"Exposed service on port {v.get('port')}"
                ),
                recommendation=v.get("recommendation"),
                scan_id=scan.id
            )

            vulns_to_add.append(new_vuln)

    # =========================================================
    # WEB SCAN
    # =========================================================
    elif scan.scan_type == "Web":

        scan_data = details.get("scan_data", {})

        # ---------------- SQL Injection ----------------
        sql_issues = scan_data.get("sql_issues")

        if sql_issues and sql_issues.get("issue"):

            parameters = sql_issues.get("parameters", [])

            new_vuln = Vulnerability(
                port=443 if details.get("https") else 80,
                service="HTTP/HTTPS",
                protocol="TCP",
                vulnerability_name="SQL Injection",
                cve_id=None,
                severity=sql_issues.get("severity") or "Critical",
                attack_type="Injection",
                description=(
                    "The application may be processing user input "
                    "in a way that allows unintended SQL commands "
                    "to be executed.\n"
                    "Parameters: "
                    + ", ".join(parameters)
                ),
                recommendation=(
                    "Use parameterized queries, validate input, "
                    "and review database access controls."
                ),
                scan_id=scan.id
            )

            vulns_to_add.append(new_vuln)

        # ---------------- XSS ----------------
        xss_issues = scan_data.get("xss_issues", [])

        if xss_issues:
            for xss in xss_issues:

                new_vuln = Vulnerability(
                    port=443 if details.get("https") else 80,
                    service="HTTP/HTTPS",
                    protocol="TCP",
                    vulnerability_name=(
                        "Cross-Site Scripting (XSS)"
                    ),
                    cve_id=None,
                    severity=(
                        xss.get("severity")
                        or "High"
                    ),
                    attack_type="XSS",
                    description=(
                        "XSS Vulnerability detected. "
                        f"Details: {xss.get('issue', '')}. "
                        f"Tested URL: "
                        f"{xss.get('test_url', 'Not available')}"
                    ),
                    recommendation=(
                        "Implement strict input validation "
                        "and context-aware output encoding."
                    ),
                    scan_id=scan.id
                )

                vulns_to_add.append(new_vuln)

        # ---------------- Security Headers ----------------
        headers = (
            scan_data.get("security_headers")
            or {}
        )

        missing_headers = [
            header
            for header, status in headers.items()
            if status == "Missing"
        ]

        if missing_headers:

            new_vuln = Vulnerability(
                port=443 if details.get("https") else 80,
                service="HTTP/HTTPS",
                protocol="TCP",
                vulnerability_name="Missing Security Headers",
                cve_id=None,
                severity="Low",
                attack_type="Misconfiguration",
                description=(
                    "The following security headers are missing: "
                    + ", ".join(missing_headers)
                ),
                recommendation=(
                    "Configure the web server to include missing "
                    "security headers such as Content-Security-Policy, "
                    "X-Frame-Options, X-Content-Type-Options, "
                    "Strict-Transport-Security, and Referrer-Policy."
                ),
                scan_id=scan.id
            )

            vulns_to_add.append(new_vuln)

    # =========================================================
    # FULL ASSESSMENT
    # =========================================================
    elif scan.scan_type == "Full Assessment":

        findings = details.get("findings", [])

        for finding in findings:

            new_vuln = Vulnerability(
                port=int(finding.get("port") or 0),
                service=finding.get("service") or "Multiple",
                protocol=finding.get("protocol") or "TCP",
                vulnerability_name=(
                    finding.get("title")
                    or "Unknown Vulnerability"
                ),
                cve_id=finding.get("cve"),
                severity=(
                    finding.get("severity")
                    or "Informational"
                ),
                attack_type=finding.get("module"),
                description=(
                    finding.get("explanation", "")
                    + "\n\nTechnical details: "
                    + finding.get("technical", "")
                ),
                recommendation=(
                    finding.get("recommendation")
                    or "Please review the full report "
                       "for specific recommendations."
                ),
                scan_id=scan.id
            )

            vulns_to_add.append(new_vuln)

    # =========================================================
    # SSL / TLS SCAN
    # =========================================================
    elif scan.scan_type == "SSL":

        risk = details.get("risk")

        ssl_valid = details.get(
            "ssl_valid"
        )

        certificate_trusted = details.get(
            "certificate_trusted"
        )

        hostname_valid = details.get(
            "hostname_valid"
        )

        trust_status = details.get(
            "trust_status"
        )

        verification_error = details.get(
            "verification_error"
        )

        days_remaining = details.get(
            "days_remaining"
        )

        # -----------------------------------------------------
        # Determine whether SSL has an actual finding
        # -----------------------------------------------------

        has_finding = False

        if risk and risk != "Low":
            has_finding = True

        if certificate_trusted is False:
            has_finding = True

        if hostname_valid is False:
            has_finding = True

        if (
            days_remaining is not None
            and days_remaining < 0
        ):
            has_finding = True

        if not ssl_valid:
            has_finding = True

        if has_finding:

            # -------------------------------------------------
            # Certificate hostname mismatch
            # -------------------------------------------------
            if trust_status == "hostname_mismatch":

                vulnerability_name = (
                    "SSL/TLS Certificate Hostname Mismatch"
                )

                attack_type = "Misconfiguration"

                description = (
                    "The SSL/TLS certificate presented by the "
                    "target does not match the requested hostname.\n\n"
                    f"Issued To: {details.get('issued_to', 'Unknown')}\n"
                    f"Verification Error: "
                    f"{verification_error or 'Not available'}"
                )

                recommendation = (
                    "Install and configure an SSL/TLS certificate "
                    "whose Subject Alternative Name (SAN) or "
                    "Common Name matches the requested hostname."
                )

            # -------------------------------------------------
            # Expired certificate
            # -------------------------------------------------
            elif (
                days_remaining is not None
                and days_remaining < 0
            ):

                vulnerability_name = (
                    "Expired SSL/TLS Certificate"
                )

                attack_type = "Certificate Management"

                description = (
                    "The SSL/TLS certificate has expired.\n\n"
                    f"Expiry Date: "
                    f"{details.get('expiry_date', 'Unknown')}\n"
                    f"Days Expired: "
                    f"{abs(days_remaining)}"
                )

                recommendation = (
                    "Renew the SSL/TLS certificate and install "
                    "the renewed certificate on the target server."
                )

            # -------------------------------------------------
            # Local trust-store problem
            # -------------------------------------------------
            elif trust_status == "local_trust_store_error":

                vulnerability_name = (
                    "Certificate Trust Verification Issue"
                )

                attack_type = "Certificate Validation"

                description = (
                    "The TLS connection and certificate were "
                    "successfully inspected, but the local "
                    "certificate trust store could not verify "
                    "the certificate chain.\n\n"
                    f"Issuer: "
                    f"{details.get('issuer', 'Unknown')}\n"
                    f"Verification Error: "
                    f"{verification_error or 'Not available'}"
                )

                recommendation = (
                    "Review the certificate chain and the "
                    "certificate authority trust configuration "
                    "of the scanner environment. A local trust "
                    "store failure should not by itself be treated "
                    "as proof that the target certificate is invalid."
                )

            # -------------------------------------------------
            # Generic SSL/TLS finding
            # -------------------------------------------------
            else:

                vulnerability_name = (
                    "Weak SSL/TLS Configuration"
                )

                attack_type = "Misconfiguration"

                description = (
                    "SSL/TLS security issues were detected.\n\n"
                    f"Valid: {ssl_valid}\n"
                    f"Certificate Trusted: "
                    f"{certificate_trusted}\n"
                    f"Hostname Valid: "
                    f"{hostname_valid}\n"
                    f"Issuer: "
                    f"{details.get('issuer', 'Unknown')}\n"
                    f"Issued To: "
                    f"{details.get('issued_to', 'Unknown')}\n"
                    f"TLS Version: "
                    f"{details.get('tls_version', 'Unknown')}\n"
                    f"Cipher: "
                    f"{details.get('cipher', 'Unknown')}\n"
                    f"Expiry: "
                    f"{details.get('expiry_date', 'Unknown')}"
                )

                recommendation = (
                    "Review the SSL/TLS certificate, certificate "
                    "chain, TLS protocol version, cipher suite, "
                    "hostname configuration, and certificate expiry."
                )

            # -------------------------------------------------
            # Store SSL vulnerability
            # -------------------------------------------------

            new_vuln = Vulnerability(
                port=443,
                service="HTTPS",
                protocol="TCP",
                vulnerability_name=vulnerability_name,
                cve_id=None,
                severity=risk or "Informational",
                attack_type=attack_type,
                description=description,
                recommendation=recommendation,
                scan_id=scan.id
            )

            vulns_to_add.append(new_vuln)

    # =========================================================
    # SAVE VULNERABILITIES
    # =========================================================

    if vulns_to_add:
        for vulnerability in vulns_to_add:
            db.session.add(vulnerability)

        db.session.commit()

#-----------------Home-----------------
@app.route("/")
def home():
        return render_template(
            "home.html"
        )
#-----------------Web Scan-----------------
@app.route(
    "/web-scan",
    methods=[
        "GET",
        "POST"
    ]
)
@login_required
def web_scan():
    scan_data = None
    scan_time = None
    if request.method == "POST":
        target = (request.form.get("target","").strip())
        scan_options = (request.form.getlist("web_scan_options"))
        print(f"\n[DEBUG] Scan started")
        print(f"[DEBUG] Target = {target}")
        print(f"[DEBUG] Web scan options = {scan_options}")
        
        if not target:
            flash("Please enter a target URL or IP address.","warning")
            return redirect(url_for("web_scan"))
        if not scan_options:
            flash("Please select at least one web scan type.","warning")
            return redirect(url_for("web_scan"))
        try:
            print("[DEBUG] Web scanner called")
            scan_data = (run_web_scan(target,scan_options))
            print(f"[DEBUG] Web scanner returned = {list(scan_data.keys()) if scan_data else None}")
            
            scan_time = (datetime.now().strftime("%d %B %Y %I:%M %p"))
            new_scan = Scan(
                user_id=current_user.id,
                target=target,
                scan_type="Web",
                severity=scan_data["risk"],
                status="Completed",
                open_ports=0,
                details=json.dumps({"scan_data":scan_data,"scan_time":scan_time})
            )
            print(f"[DEBUG] Final risk = {scan_data['risk']}")
            db.session.add(new_scan)
            db.session.commit()
            
            extract_and_store_vulnerabilities(new_scan)
            
            flash("Web Scan Completed Successfully","success")
        except Exception as error:
            print(f"[DEBUG] Web Scan Error: {error}")
            flash(f"Scan Failed: {str(error)}","danger")
    
    return render_template("web_scan.html",scan_data=scan_data,scan_time=scan_time)


#-----------------Nmap Check-----------------

import shutil
import subprocess
@app.route("/check-nmap")
def check_nmap():
    nmap_path = shutil.which("nmap")
    try:
        version = subprocess.check_output(["nmap", "--version"]).decode()
    except Exception as e:
        version = str(e)
    return jsonify({"nmap_path": nmap_path,"version": version})

#-----------------Web Scan-----------------

@app.route("/block-ip", methods=["POST"])
def block_ip_route():
    data = request.get_json()
    ip = data.get("ip")
    return jsonify({
        "message": f"{ip} blocked successfully"
    })

#-----------------Profile-----------------
@app.route("/profile")
@login_required
def profile():
    user_scans = Scan.query.filter_by(user_id=current_user.id)
    total_scans = user_scans.count()
    critical_count = user_scans.filter_by(severity="Critical").count()
    medium_count = user_scans.filter_by(severity="Medium").count()
    low_count = user_scans.filter_by(severity="Low").count()
    recent_scans = (user_scans.order_by(Scan.created_at.desc()).limit(5).all())
    return render_template(
        "profile.html",
        user=current_user,
        total_scans=total_scans,
        critical_count=critical_count,
        medium_count=medium_count,
        low_count=low_count,
        recent_scans=recent_scans
    )

#-----------------Update Profile-----------------

@app.route("/update-profile", methods=["POST"])
@login_required
def update_profile():
    username = request.form.get("username")
    password = request.form.get("password")
    if username:
        current_user.username = username
    if password:
        current_user.password = (bcrypt.generate_password_hash(password).decode("utf-8"))

    db.session.commit()
    flash("Profile Updated Successfully", "success")
    return redirect(url_for("profile"))

# -----------------Register---------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        if User.query.filter_by(email=email).first():
            flash("Email already exists", "danger")
            return redirect(url_for("register"))
        new_user = User(
            username=username,
            email=email,
            password=bcrypt.generate_password_hash(password).decode("utf-8")
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

#-----------------Login-----------------

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    client_ip = request.remote_addr
    if client_ip in blocked_ips:
        flash("Access blocked due to suspicious activity","danger")
        return render_template("login.html")
    
    if request.method == "POST":
        email = request.form.get("email","").strip()
        password = request.form.get(
            "password",
            ""
        ).strip()

        suspicious_patterns = ["<script>","drop table","union select","' or '1'='1","' or 1=1","../","cmd="]
        input_data = (email.lower() + password.lower())
        for pattern in suspicious_patterns:
            if pattern.lower() in input_data:
                blocked_ips.add(client_ip)
                flash("Suspicious activity detected. IP blocked.","danger")
                return render_template("login.html")
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("Login Successful","success")
            return redirect(url_for("admin") if user.email == "suraksha@admin.in" else url_for("dashboard"))
        flash("Invalid credentials","danger")
    return render_template("login.html")

#-----------------Reports-----------------

@app.route("/reports")
@login_required
def reports():
    search = request.args.get("search", "")
    scan_type = request.args.get("scan_type", "")
    query = Scan.query.filter_by(user_id=current_user.id)
    if search:
        query = query.filter(Scan.target.ilike(f"%{search}%"))
    if scan_type:
        query = query.filter_by(scan_type=scan_type)
    scans = query.order_by(Scan.created_at.desc()).all()
    return render_template("reports.html",scans=scans)

#-----------------Report Details-----------------

@app.route("/report/<int:scan_id>")
@login_required
def report_details(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    return render_template("report_details.html",scan=scan)

from threading import Thread
capture_thread = None

#-----------------Dashboard-----------------

@app.route("/dashboard")
@login_required
def dashboard():
    user_scans = Scan.query.filter_by(user_id=current_user.id)
    total_scans = user_scans.count()
    critical_count = user_scans.filter_by(severity="Critical").count()
    high_count = user_scans.filter_by(severity="High").count()
    medium_count = user_scans.filter_by(severity="Medium").count()
    low_count = user_scans.filter_by(severity="Low").count()
    recent_scans = user_scans.order_by(Scan.created_at.desc()).limit(10).all()
    return render_template(
        "dashboard.html",
        user=current_user,
        total_scans=total_scans,
        critical_vulnerabilities=critical_count,
        reports_generated=total_scans,
        recent_scans=recent_scans,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count
    )
#-----------------Unified Assessment-----------------

@app.route("/assessment", methods=["GET"])
@login_required
def assessment():
    return render_template("assessment.html")

@app.route("/assessment-result/<int:scan_id>")
@login_required
def assessment_result(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    return render_template("assessment_result.html", scan=scan)

@app.route("/api/run-assessment", methods=["POST"])
@login_required
def run_assessment():
    data = request.get_json()
    target = data.get("target", "").strip()
    scans = data.get("scans", [])

    if not target or not scans:
        return jsonify({"success": False, "error": "Target and at least one scan type required."}), 400

    results = {
        "web": None,
        "network": None,
        "ssl": None,
        "stats": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "findings": [],
        "recommendations": []
    }
    total_risk_score = 0
    highest_severity = "Not Evaluated"

    try:
        if "web" in scans:
            web_opts = ["headers", "paths", "sql", "xss", "https"]
            web_data = run_web_scan(target, web_opts)
            results["web"] = web_data
            
            # Process Web Findings
            if web_data.get("risk") == "Critical":
                highest_severity = "Critical"
                total_risk_score += 35
                results["stats"]["critical"] += 1
            elif web_data.get("risk") == "High":
                if highest_severity not in ["Critical"]: highest_severity = "High"
                total_risk_score += 25
                results["stats"]["high"] += 1
            elif web_data.get("risk") == "Medium":
                if highest_severity not in ["Critical", "High"]: highest_severity = "Medium"
                total_risk_score += 15
                results["stats"]["medium"] += 1
            elif web_data.get("risk") == "Low":
                if highest_severity == "Not Evaluated": highest_severity = "Low"

            if web_data.get("sql_issues") and web_data["sql_issues"].get("issue"):
                results["findings"].append({
                    "title": "SQL Injection Vulnerability",
                    "severity": web_data["sql_issues"]["severity"],
                    "explanation": "Attackers can manipulate database queries to access or modify unauthorized information.",
                    "module": "Web Layer - " + ", ".join(web_data["sql_issues"].get("parameters", [])),
                    "technical": str(web_data["sql_issues"].get("findings", [])),
                })
                results["recommendations"].extend([{"text": rec, "priority": "Critical"} for rec in web_data["sql_issues"].get("recommendation", [])])
                results["stats"]["critical"] += 1

            if web_data.get("xss_issues"):
                for issue in web_data["xss_issues"]:
                    results["findings"].append({
                        "title": "Cross-Site Scripting (XSS)",
                        "severity": issue.get("severity") or "High",
                        "explanation": "Attackers can inject malicious scripts into webpages viewed by other users.",
                        "module": f"Web Layer - {issue.get('parameter', 'unknown parameter')}",
                        "technical": issue.get("test_url") or issue.get("issue", ""),
                    })
                    results["recommendations"].append({"text": "Implement strict input validation and context-aware output encoding.", "priority": "High"})
                    results["stats"]["high"] += 1

        if "network" in scans:
            net_opts = ["port", "banner", "service", "version", "os", "vuln"]
            net_data = run_network_scan(target, net_opts)
            results["network"] = net_data
            
            risk = net_data.get("risk", "Low")
            if risk == "Critical":
                highest_severity = "Critical"
                total_risk_score += 35
            elif risk == "High":
                if highest_severity not in ["Critical"]: highest_severity = "High"
                total_risk_score += 25
            elif risk == "Medium":
                if highest_severity not in ["Critical", "High"]: highest_severity = "Medium"
                total_risk_score += 15
            elif risk == "Low":
                if highest_severity == "Not Evaluated": highest_severity = "Low"
            
            for res in net_data.get("results", []):
                ai_risk = res.get("ai_risk", "Low")
                results["stats"][ai_risk.lower()] = results["stats"].get(ai_risk.lower(), 0) + 1
                if ai_risk in ["Critical", "High", "Medium"]:
                    results["findings"].append({
                        "title": f"Exposed Service: {res.get('service', 'Unknown').upper()} on Port {res.get('port')}",
                        "severity": ai_risk,
                        "explanation": "An open port running this service may expose the system to unauthorized access or known exploits.",
                        "module": "Network Layer",
                        "cve": ", ".join([c.get("id") for c in res.get("cves", [])]) if res.get("cves") else None,
                        "technical": f"State: {res.get('state')} | Product: {res.get('product', '')} {res.get('version', '')}"
                    })
                    results["recommendations"].append({"text": f"Review necessity of port {res.get('port')}. Restrict access via firewall or upgrade service.", "priority": ai_risk})

        if "ssl" in scans:
            ssl_data = run_ssl_check(target)
            results["ssl"] = ssl_data
            
            if ssl_data.get("risk") == "Critical":
                highest_severity = "Critical"
                total_risk_score += 30
                results["stats"]["critical"] += 1
            elif ssl_data.get("risk") == "High":
                if highest_severity not in ["Critical"]: highest_severity = "High"
                total_risk_score += 20
                results["stats"]["high"] += 1
            elif ssl_data.get("risk") == "Medium":
                if highest_severity not in ["Critical", "High"]: highest_severity = "Medium"
                total_risk_score += 10
                results["stats"]["medium"] += 1
            elif ssl_data.get("risk") == "Low":
                if highest_severity == "Not Evaluated": highest_severity = "Low"
            
            if ssl_data.get("risk") != "Low" and not ssl_data.get("error"):
                results["findings"].append({
                    "title": "Weak SSL/TLS Configuration",
                    "severity": ssl_data.get("risk"),
                    "explanation": "The SSL certificate has issues, such as being expired or using weak protocols, which compromises transport encryption.",
                    "module": "Transport Layer (SSL/TLS)",
                    "technical": f"Valid: {ssl_data.get('ssl_valid')} | Issuer: {ssl_data.get('issuer')} | Expiry: {ssl_data.get('expiry_date')}"
                })
                results["recommendations"].append({"text": "Renew SSL certificate or upgrade to secure TLS protocols (TLS 1.2/1.3).", "priority": ssl_data.get("risk")})

        results["risk_score"] = min(total_risk_score, 100)
        
        # Deduplicate recommendations
        unique_recs = []
        seen_texts = set()
        for rec in results["recommendations"]:
            if rec["text"] not in seen_texts:
                unique_recs.append(rec)
                seen_texts.add(rec["text"])
        results["recommendations"] = unique_recs

        new_scan = Scan(
            user_id=current_user.id,
            target=target,
            scan_type="Full Assessment",
            severity=highest_severity,
            status="Completed",
            open_ports=results["network"]["open_port_count"] if results["network"] else 0,
            details=json.dumps(results)
        )
        db.session.add(new_scan)
        db.session.commit()
        
        extract_and_store_vulnerabilities(new_scan)
        
        return jsonify({"success": True, "scan_id": new_scan.id})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

#-----------------SSL Check-----------------

@app.route("/ssl-check", methods=["GET", "POST"])
@login_required
def ssl_check():
    ssl_data = None
    scan_time = None
    email_report = None

    if request.method == "POST":
        target = request.form.get("target", "").strip()

        if not target:
            flash("Please enter a target domain.", "warning")
            return render_template(
                "ssl_check.html",
                ssl_data=None,
                scan_time=None,
                email_report=None
            )

        try:
            ssl_data = run_ssl_check(target)

            scan_time = datetime.now().strftime(
                "%d %B %Y %I:%M %p"
            )

            new_scan = Scan(
                user_id=current_user.id,
                target=ssl_data.get("target", target),
                scan_type="SSL",
                severity=ssl_data.get("risk", "Critical"),
                status="Completed",
                open_ports=1,
                details=json.dumps({
                    "ssl_valid": ssl_data.get("ssl_valid"),
                    "certificate_trusted": ssl_data.get(
                        "certificate_trusted"
                    ),
                    "hostname_valid": ssl_data.get(
                        "hostname_valid"
                    ),
                    "tls_connected": ssl_data.get(
                        "tls_connected"
                    ),
                    "trust_status": ssl_data.get(
                        "trust_status"
                    ),
                    "issuer": ssl_data.get("issuer"),
                    "issued_to": ssl_data.get("issued_to"),
                    "tls_version": ssl_data.get(
                        "tls_version"
                    ),
                    "cipher": ssl_data.get("cipher"),
                    "hash_algorithm": ssl_data.get(
                        "hash_algorithm"
                    ),
                    "expiry_date": ssl_data.get(
                        "expiry_date"
                    ),
                    "days_remaining": ssl_data.get(
                        "days_remaining"
                    ),
                    "risk": ssl_data.get("risk"),
                    "error": ssl_data.get("error"),
                    "verification_error": ssl_data.get(
                        "verification_error"
                    ),
                    "verification_type": ssl_data.get(
                        "verification_type"
                    ),
                    "scan_time": scan_time
                })
            )

            db.session.add(new_scan)
            db.session.commit()

            extract_and_store_vulnerabilities(
                new_scan
            )

            # Build report dynamically from the actual scan result
            try:
                email_report = build_ssl_report_email(
                    ssl_data,
                    current_user
                )
            except Exception as report_error:
                app.logger.error(
                    "SSL report generation failed: %s",
                    report_error
                )
                email_report = None

            flash(
                "SSL Check Completed Successfully",
                "success"
            )

        except Exception as error:
            app.logger.exception(
                "SSL Check failed"
            )

            flash(
                f"SSL Check Failed: {str(error)}",
                "danger"
            )

    return render_template(
        "ssl_check.html",
        ssl_data=ssl_data,
        scan_time=scan_time,
        email_report=email_report
    )

#-----------------Report SSL & Send Advisory-----------------
import smtplib
from email.message import EmailMessage

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def handle_send_ssl_advisory(data):
    """Common helper to validate and record SSL security advisory.
    Direct SMTP dispatch is bypassed in favor of frontend EmailJS integration (service_gma17jk)
    to prevent duplicate email transmission.
    """
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"success": False, "message": "Domain is required."}), 400

    recipient = data.get("recipient", "").strip()
    if not recipient:
        return jsonify({"success": False, "message": "Recipient email address is required."}), 400

    if not EMAIL_REGEX.match(recipient):
        return jsonify({"success": False, "message": "Invalid recipient email address format."}), 400

    subject = data.get("subject", "").strip()
    if not subject:
        return jsonify({"success": False, "message": "Advisory subject cannot be empty."}), 400

    body = data.get("body", "").strip()
    if not body:
        return jsonify({"success": False, "message": "Advisory body cannot be empty."}), 400

    safe_user_name = current_user.username if (current_user and current_user.is_authenticated and current_user.username) else "Security Analyst"
    safe_recipient = re.sub(r'[\r\n]', '', recipient).strip()
    safe_subject = re.sub(r'[\r\n]', '', subject).strip()
    sender_addr = "surakshav1@gmail.com"

    # Record advisory in database
    try:
        from datetime import timedelta
        new_report = ShareableReport(
            reporter_name=safe_user_name,
            reporter_email=sender_addr,
            recipient=safe_recipient,
            target=domain,
            ssl_status=data.get("ssl_status", "At Risk"),
            risk_level=data.get("risk_level", "Medium"),
            subject=safe_subject,
            email_body=body,
            expires_at=datetime.utcnow() + timedelta(days=7)
        )
        db.session.add(new_report)
        db.session.commit()
    except Exception as db_err:
        app.logger.warning(f"Could not record ShareableReport entry: {db_err}")

    return jsonify({
        "success": True,
        "message": f"Security advisory recorded successfully for {safe_recipient}."
    }), 200

@app.route("/report-ssl", methods=["POST"])
@login_required
@limiter.limit("20 per minute")
def report_ssl():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "Invalid request data."}), 400
        
    action = data.get("action", "prepare")
    if action in ("send", "record"):
        return handle_send_ssl_advisory(data)

    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"success": False, "message": "Domain is required."}), 400

    # Build standardized SSL report dynamically from scan result and current_user session
    scan_payload = {
        "target": domain,
        "ssl_valid": data.get("ssl_valid", data.get("status") == "Valid"),
        "issuer": data.get("issuer"),
        "issued_to": data.get("issued_to"),
        "tls_version": data.get("tls_version"),
        "cipher": data.get("cipher"),
        "hash_algorithm": data.get("hash_algorithm"),
        "expiry_date": data.get("expiry_date"),
        "days_remaining": data.get("days_remaining"),
        "risk": data.get("risk", "Medium"),
        "certificate_trusted": data.get("certificate_trusted"),
        "trust_status": data.get("trust_status"),
        "error": data.get("error") or (data.get("status") if data.get("status") != "Valid" else None)
    }
    
    report_info = build_ssl_report_email(scan_payload, current_user)
    
    if "recipient" in data and data.get("recipient", "").strip():
        report_info["recipient"] = data.get("recipient", "").strip()

    return jsonify({
        "success": True,
        "message": "Security advisory prepared successfully.",
        "report": report_info
    }), 200

@app.route("/send-ssl-advisory", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def send_ssl_advisory():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "Invalid request data."}), 400
    return handle_send_ssl_advisory(data)

#-----------------Report API for CPEMAIL-----------------

from datetime import timedelta

@app.route("/api/reports", methods=["POST"])
@limiter.limit("10 per minute")
def create_report():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "Invalid data."}), 400

    cp_email_base_url = os.environ.get("CP_EMAIL_BASE_URL", "http://localhost:5173")
    
    # Calculate expiration
    expires_at = datetime.utcnow() + timedelta(days=7) # Reports expire in 7 days by default
    
    new_report = ShareableReport(
        reporter_name=data.get("reporter_name", ""),
        reporter_email=data.get("reporter_email", ""),
        recipient=data.get("recipient", ""),
        target=data.get("target", ""),
        ssl_status=data.get("ssl_status", ""),
        risk_level=data.get("risk_level", ""),
        subject=data.get("subject", ""),
        email_body=data.get("email_body", ""),
        expires_at=expires_at
    )
    
    db.session.add(new_report)
    db.session.commit()
    
    share_url = f"{cp_email_base_url}/report/{new_report.report_token}"
    
    return jsonify({
        "success": True,
        "report_token": new_report.report_token,
        "share_url": share_url
    }), 201

@app.route("/api/reports/<report_token>", methods=["GET"])
@limiter.limit("30 per minute")
def get_report(report_token):
    report = ShareableReport.query.filter_by(report_token=report_token).first()
    
    if not report:
        return jsonify({"success": False, "message": "Report not found."}), 404
        
    if report.expires_at and report.expires_at < datetime.utcnow():
        return jsonify({"success": False, "message": "This report link has expired."}), 410
        
    return jsonify({
        "success": True,
        "report": report.to_dict()
    }), 200

@app.route("/api/send-report-email", methods=["POST"])
@limiter.limit("10 per minute")
def api_send_report_email():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "Invalid request."}), 400
        
    report_token = data.get("report_token")
    if not report_token:
        return jsonify({"success": False, "message": "Missing report token."}), 400
        
    report = ShareableReport.query.filter_by(report_token=report_token).first()
    if not report:
        return jsonify({"success": False, "message": "Report not found."}), 404
        
    if report.expires_at and report.expires_at < datetime.utcnow():
        return jsonify({"success": False, "message": "This report link has expired."}), 410
        
    # Same SMTP logic as /report-ssl
    mail_username = os.environ.get("MAIL_USERNAME")
    mail_password = os.environ.get("MAIL_PASSWORD")
    
    if not mail_username or not mail_password:
        return jsonify({"success": False, "message": "Backend email service is not configured."}), 500

    mail_server = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    mail_port = int(os.environ.get("MAIL_PORT", 587))
    mail_use_tls = os.environ.get("MAIL_USE_TLS", "True").lower() == "true"
    
    safe_subject = re.sub(r'[\r\n]', '', report.subject).strip()
    safe_user_email = re.sub(r'[\r\n]', '', report.reporter_email).strip() if report.reporter_email else mail_username
    safe_user_name = re.sub(r'[\r\n]', '', report.reporter_name).strip() if report.reporter_name else "Security Analyst"
    safe_recipient = re.sub(r'[\r\n]', '', report.recipient).strip()
    
    msg = EmailMessage()
    msg['Subject'] = safe_subject
    if safe_user_email.lower() == mail_username.lower():
        msg['From'] = f"{safe_user_name} <{safe_user_email}>"
    else:
        msg['From'] = f"{safe_user_name} via SURAKSHA <{mail_username}>"
    msg['To'] = safe_recipient
    msg['Reply-To'] = f"{safe_user_name} <{safe_user_email}>"
    msg.set_content(report.email_body)
    
    try:
        with smtplib.SMTP(mail_server, mail_port, timeout=10) as server:
            server.ehlo()
            if mail_use_tls:
                server.starttls()
            server.login(mail_username, mail_password)
            server.send_message(msg)
    except Exception as e:
        app.logger.error(f"SMTP send failed in API: {e}")
        return jsonify({"success": False, "message": "Unable to send email from backend."}), 500
        
    return jsonify({"success": True, "message": f"Email sent successfully to {safe_recipient}."}), 200


#-----------------Admin Panel-----------------

RISK_MAPPING = {
    "critical": {"priority": "P1", "score": 100},
    "high": {"priority": "P2", "score": 80},
    "medium": {"priority": "P3", "score": 60},
    "low": {"priority": "P4", "score": 40},
    "informational": {"priority": "P5", "score": 20},
    "none": {"priority": "P6", "score": 10}
}

@app.route("/admin")
@login_required
def admin():

    total_users = User.query.count()
    total_scans = Scan.query.count()
    critical_scans = Scan.query.filter_by(severity="Critical").count()

    # Recent Scans
    recent_scans = Scan.query.order_by(
        Scan.created_at.desc()
    ).limit(10).all()

    # Calculate Risk Score and Assign Priority dynamically
    for scan in recent_scans:
        # Safely extract and normalize the severity value
        safe_severity = str(scan.severity).strip().lower() if scan.severity else "none"
        
        # Get mapped values or fallback to default
        mapped_values = RISK_MAPPING.get(safe_severity, RISK_MAPPING["none"])
        
        scan.risk_score = mapped_values["score"]
        scan.priority = mapped_values["priority"]

    # Sort by Highest Risk Score
    recent_scans = sorted(
        recent_scans,
        key=lambda x: x.risk_score,
        reverse=True
    )

    return render_template(
        "admin.html",
        total_users=total_users,
        total_scans=total_scans,
        critical_scans=critical_scans,
        total_reports=total_scans,
        recent_scans=recent_scans
    )

#-----------------Admin Profile-----------------

@app.route("/admin/profile", methods=["GET", "POST"])
@login_required
def admin_profile():
    if current_user.email != "suraksha@admin.in":
        flash("Unauthorized Access", "danger")
        return redirect(url_for("dashboard"))

    # Direct query to the 'users' table
    admin_user = User.query.get(current_user.id)
    if not admin_user:
        flash("Admin user record not found in users database.", "danger")
        return redirect(url_for("admin"))

    if request.method == "POST":
        new_username = request.form.get("username", "").strip()
        new_password = request.form.get("password", "").strip()

        updated = False
        if new_username and new_username != admin_user.username:
            admin_user.username = new_username
            updated = True
        if new_password:
            admin_user.password = bcrypt.generate_password_hash(new_password).decode("utf-8")
            updated = True

        if updated:
            db.session.commit()
            flash("Superadmin profile updated successfully.", "success")
        else:
            flash("No changes were made.", "info")

        return redirect(url_for("admin_profile"))

    total_users_count = User.query.count()
    total_scans_count = Scan.query.count()
    critical_scans_count = Scan.query.filter_by(severity="Critical").count()

    return render_template(
        "admin_profile.html",
        admin_user=admin_user,
        total_users=total_users_count,
        total_scans=total_scans_count,
        critical_scans=critical_scans_count
    )

#-----------------Admin Users-----------------

@app.route("/admin/users")
@login_required
def admin_users():
    if current_user.email != "suraksha@admin.in":
        flash("Unauthorized Access", "danger")
        return redirect(url_for("dashboard"))
    search = request.args.get("search", "")
    query = User.query
    if search:
        query = query.filter(User.username.ilike(f"%{search}%") | User.email.ilike(f"%{search}%"))
    users = query.order_by(User.id.desc()).all()
    return render_template("users.html", users=users)

#-----------------API User Details (For Popup)-----------------

@app.route("/api/user/<int:user_id>")
@login_required
def api_get_user(user_id):
    if current_user.email != "suraksha@admin.in":
        return jsonify({"error": "Unauthorized Access"}), 403
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    created_date = user.created_at.strftime("%d %B %Y, %I:%M %p") if hasattr(user, "created_at") and user.created_at else "Date not available"
    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "created_at": created_date
    })

#-----------------Delete User via admin-----------------

@app.route("/admin/delete-user/<int:user_id>")
@login_required
def delete_user(user_id):
    if current_user.email != "suraksha@admin.in":
        return redirect(url_for("dashboard"))
    user = User.query.get_or_404(user_id)
    if user.email == "suraksha@admin.in":
        flash("Admin account cannot be deleted", "danger")
        return redirect(url_for("admin_users"))
    Scan.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    flash("User Deleted", "success")
    return redirect(url_for("admin_users"))

#-----------------View User via admin-----------------

@app.route("/admin/user/<int:user_id>")
@login_required
def view_user(user_id):
    if current_user.email != "suraksha@admin.in":
        return redirect(url_for("dashboard"))
    user = User.query.get_or_404(user_id)
    scans = Scan.query.filter_by(user_id=user.id).order_by(Scan.created_at.desc()).all()
    return render_template("view_user.html", user=user, scans=scans)

#-----------------Admin Reports-----------------
@app.route("/admin/reports")
@login_required
def admin_reports():
    if current_user.email != "suraksha@admin.in":
        return redirect(url_for("dashboard"))
        
    search = request.args.get("search", "")
    scan_type = request.args.get("scan_type", "")
    severity = request.args.get("severity", "")
    start_date = request.args.get("start_date", "")
    end_date = request.args.get("end_date", "")
    
    query = Scan.query
    if search:
        query = query.join(User).filter(Scan.target.ilike(f"%{search}%") | User.username.ilike(f"%{search}%"))
    if scan_type:
        query = query.filter_by(scan_type=scan_type)
    if severity:
        query = query.filter_by(severity=severity)
        
    if start_date:
        try:
            sd = datetime.strptime(start_date, "%Y-%m-%d")
            query = query.filter(Scan.created_at >= sd)
        except ValueError:
            pass
            
    if end_date:
        try:
            ed = datetime.strptime(end_date + " 23:59:59", "%Y-%m-%d %H:%M:%S")
            query = query.filter(Scan.created_at <= ed)
        except ValueError:
            pass
            
    scans = query.order_by(Scan.created_at.desc()).all()
    
    # Calculate summary statistics based on filtered data
    total_scans = len(scans)
    critical_scans = sum(1 for s in scans if s.severity and s.severity.lower() == "critical")
    high_scans = sum(1 for s in scans if s.severity and s.severity.lower() == "high")
    network_scans = sum(1 for s in scans if s.scan_type == "Network")
    web_scans = sum(1 for s in scans if s.scan_type == "Web")
    ssl_scans = sum(1 for s in scans if s.scan_type == "SSL")
    
    summary_stats = {
        "total": total_scans,
        "critical": critical_scans,
        "high": high_scans,
        "network": network_scans,
        "web": web_scans,
        "ssl": ssl_scans
    }
    
    # 1. Gather all scan IDs to avoid N+1 queries
    scan_ids = [scan.id for scan in scans]
    
    # 2. Fetch related vulnerabilities in one go
    vuln_map = {}
    if scan_ids:
        vulns = Vulnerability.query.filter(Vulnerability.scan_id.in_(scan_ids)).all()
        # Create a mapping of scan_id to its most relevant vulnerability (prioritize critical)
        for v in vulns:
            if v.scan_id not in vuln_map:
                vuln_map[v.scan_id] = v
            else:
                if v.severity and v.severity.lower() == "critical" and (not vuln_map[v.scan_id].severity or vuln_map[v.scan_id].severity.lower() != "critical"):
                    vuln_map[v.scan_id] = v
                    
    # Priority Mapping Constants
    RISK_MAPPING = {
        "critical": "P1",
        "high": "P2",
        "medium": "P3",
        "low": "P4",
        "informational": "P5",
        "none": "P6"
    }
    
    # 3. Enrich scans with priority and vulnerability explanations
    for scan in scans:
        safe_severity = str(scan.severity).strip().lower() if scan.severity else "none"
        scan.priority = RISK_MAPPING.get(safe_severity, "P6")
        
        rel_vuln = vuln_map.get(scan.id)
        if rel_vuln:
            scan.vulnerability_name = rel_vuln.vulnerability_name
            scan.attack_type = rel_vuln.attack_type
            scan.cve_id = rel_vuln.cve_id
            scan.description = rel_vuln.description
        else:
            scan.vulnerability_name = None
            scan.attack_type = None
            scan.cve_id = None
            scan.description = None
            
    return render_template("statement.html", scans=scans, stats=summary_stats)

#-----------------API Report Details-----------------

@app.route("/admin/api/reports/<int:scan_id>")
@login_required
def api_get_report_details(scan_id):
    if current_user.email != "suraksha@admin.in":
        return jsonify({"error": "Unauthorized Access"}), 403
        
    scan = Scan.query.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
        
    RISK_MAPPING = {
        "critical": {"priority": "P1", "score": 100},
        "high": {"priority": "P2", "score": 80},
        "medium": {"priority": "P3", "score": 60},
        "low": {"priority": "P4", "score": 40},
        "informational": {"priority": "P5", "score": 20},
        "none": {"priority": "P6", "score": 10}
    }
    
    safe_severity = str(scan.severity).strip().lower() if scan.severity else "none"
    mapped_values = RISK_MAPPING.get(safe_severity, RISK_MAPPING["none"])
    
    parsed_details = scan.details
    if scan.details:
        try:
            parsed_details = json.loads(scan.details)
        except Exception:
            pass

    scan_data = {
        "id": scan.id,
        "username": scan.user.username if scan.user else "Unknown",
        "target": scan.target,
        "scan_type": scan.scan_type,
        "created_at": scan.created_at.strftime("%Y-%m-%d %H:%M") if scan.created_at else "Unknown",
        "status": scan.status,
        "severity": scan.severity or "None",
        "priority": mapped_values["priority"],
        "risk_score": mapped_values["score"],
        "open_ports": scan.open_ports,
        "details": parsed_details
    }
    
    vulns = Vulnerability.query.filter_by(scan_id=scan.id).all()
    vulns_data = []
    for v in vulns:
        vulns_data.append({
            "id": v.id,
            "vulnerability_name": v.vulnerability_name,
            "cve_id": v.cve_id,
            "severity": v.severity,
            "attack_type": v.attack_type,
            "description": v.description,
            "recommendation": v.recommendation,
            "port": v.port,
            "service": v.service
        })
        
    return jsonify({
        "scan": scan_data,
        "vulnerabilities": vulns_data
    })

#-----------------Export Statement as PDF-----------------

@app.route("/admin/export-statement")
@login_required
def export_statement():
    if current_user.email != "suraksha@admin.in":
        return redirect(url_for("dashboard"))
    reports = Scan.query.order_by(Scan.created_at.desc()).all()
    pdf_path = "admin_statement.pdf"
    doc = SimpleDocTemplate(pdf_path)
    styles = getSampleStyleSheet()
    elements = []
    elements.append(Paragraph("SURAKSHA Security Scan Statement Report", styles["Title"]))
    elements.append(Spacer(1, 15))
    generated_time = datetime.now().strftime("%d %B %Y %I:%M %p")
    RISK_MAPPING = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "informational": "P5", "none": "P6"}
    table_data = [["ID", "User", "Target", "Type", "Severity", "Priority", "Date"]]
    for report in reports:
        safe_sev = str(report.severity).strip().lower() if report.severity else "none"
        prio = RISK_MAPPING.get(safe_sev, "P6")
        table_data.append([
            str(report.id),
            report.user.username if report.user else "Unknown",
            report.target,
            report.scan_type,
            report.severity or "None",
            prio,
            report.created_at.strftime("%Y-%m-%d %H:%M") if report.created_at else ""
        ])
    table = Table(table_data)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke)
    ]))
    elements.append(table)
    doc.build(elements)
    return send_file(pdf_path, as_attachment=True)

#/ Calculate Risk Score

import json

def calculate_risk_score(scan):

    score = 0

    # ----------------------------
    # Severity Weight
    # ----------------------------

    severity = {
        "Critical": 60,
        "High": 45,
        "Medium": 30,
        "Low": 15
    }

    score += severity.get(scan.severity, 10)

    # ----------------------------
    # Open Ports
    # ----------------------------

    if scan.open_ports >= 10:
        score += 25
    elif scan.open_ports >= 5:
        score += 15
    elif scan.open_ports >= 1:
        score += 8

    # ----------------------------
    # Read JSON Details
    # ----------------------------

    try:
        details = json.loads(scan.details)

        vulnerabilities = details.get("vulnerabilities", [])

        for vuln in vulnerabilities:

            risk = vuln.get("risk_level", "Low")

            if risk == "Critical":
                score += 25

            elif risk == "High":
                score += 18

            elif risk == "Medium":
                score += 12

            else:
                score += 5

            # Bonus if CVE exists
            if vuln.get("cve"):
                score += 5

    except Exception:
        pass

    return min(score, 100)


#-----------------API Vulnerability Details-----------------

@app.route("/admin/api/vulnerabilities/<int:vuln_id>")
@login_required
def api_get_vuln_details(vuln_id):
    if current_user.email != "suraksha@admin.in":
        return jsonify({"error": "Unauthorized Access"}), 403
        
    vuln = Vulnerability.query.get(vuln_id)
    if not vuln:
        return jsonify({"error": "Vulnerability not found"}), 404
        
    scan = Scan.query.get(vuln.scan_id)
    if not scan:
        return jsonify({"error": "Associated scan not found"}), 404
        
    RISK_MAPPING = {
        "critical": {"priority": "P1", "score": 100},
        "high": {"priority": "P2", "score": 80},
        "medium": {"priority": "P3", "score": 60},
        "low": {"priority": "P4", "score": 40},
        "informational": {"priority": "P5", "score": 20},
        "none": {"priority": "P6", "score": 10}
    }
    
    safe_severity = str(vuln.severity).strip().lower() if vuln.severity else "none"
    mapped_values = RISK_MAPPING.get(safe_severity, RISK_MAPPING["none"])

    parsed_details = scan.details
    if scan.details:
        try:
            parsed_details = json.loads(scan.details)
        except Exception:
            pass

    return jsonify({
        "vulnerability": {
            "id": vuln.id,
            "vulnerability_name": vuln.vulnerability_name,
            "severity": vuln.severity,
            "priority": mapped_values["priority"],
            "risk_score": mapped_values["score"],
            "attack_type": vuln.attack_type,
            "cve_id": vuln.cve_id,
            "description": vuln.description,
            "recommendation": vuln.recommendation,
            "port": vuln.port,
            "service": vuln.service,
            "protocol": vuln.protocol
        },
        "target": {
            "username": scan.user.username if scan.user else "Unknown",
            "target": scan.target,
            "scan_type": scan.scan_type,
            "created_at": scan.created_at.strftime("%Y-%m-%d %H:%M") if scan.created_at else "Unknown"
        },
        "raw_evidence": parsed_details
    })

#-----------------Admin Deep Report-----------------

@app.route("/admin/report/<int:scan_id>")
@login_required
def deep_report(scan_id):
    if current_user.email != "suraksha@admin.in":
        return redirect(url_for("dashboard"))
    scan = Scan.query.get_or_404(scan_id)
    return render_template("deep_reports.html", scan=scan)

##-----------------Network Scan-----------------

@app.route("/network-scan", methods=["GET", "POST"])
@login_required
def network_scan():
    data = {
        "scan_results": [],
        "banner_results": [],
        "risk_level": None,
        "server_ecosystem": "Unknown",
        "target": None,
        "scan_time": None,
        "os_details": [],
        "host_status": None,
        "resolved_ip": None,
        "metrics": {
            "total_ports": 0,
            "unique_services": 0,
            "unique_products": 0,
            "critical_issues": 0,
            "known_cves": 0,
            "avg_confidence": 0
        }
    }
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        scan_options = request.form.getlist("scan_options")
        if not target:
            flash("Please enter target IP or domain", "warning")
            return redirect(url_for("network_scan"))
        if not scan_options:
            flash("Please select at least one scan type", "warning")
            return redirect(url_for("network_scan"))
        try:
            scan_data = run_network_scan(target, scan_options)
            scan_time = datetime.now().strftime("%d %B %Y %I:%M %p")
            data.update({
                "scan_results": scan_data["results"],
                "banner_results": scan_data["banner_results"],
                "risk_level": scan_data["risk"],
                "server_ecosystem": scan_data.get("server_ecosystem", "Unknown"),
                "os_details": scan_data.get("os_details", []),
                "host_status": scan_data.get("host_status", "unknown"),
                "resolved_ip": scan_data.get("resolved_ip"),
                "target": target,
                "scan_time": scan_time
            })
            new_scan = Scan(
                user_id=current_user.id,
                target=target,
                scan_type="Network",
                severity=data["risk_level"],
                status="Completed",
                open_ports=scan_data["open_port_count"],
                details=json.dumps({
                    "results": data["scan_results"],
                    "banner_results": data["banner_results"],
                    "risk": data["risk_level"],
                    "server_ecosystem": data["server_ecosystem"],
                    "open_ports": scan_data["open_port_count"],
                    "vulnerabilities": [{
                        "port": r.get("port"),
                        "service": r.get("service"),
                        "risk_level": r.get("risk_level"),
                        "vulnerability": r.get("vulnerability"),
                        "cve": r.get("cve"),
                        "attack_type": r.get("attack_type"),
                        "recommendation": r.get("recommendation")
                    } for r in data["scan_results"]],
                    "scan_time": scan_time
                })
            )
            db.session.add(new_scan)
            db.session.commit()
            
            extract_and_store_vulnerabilities(new_scan)
            
            # ---- Compute metrics from real scan results ----
            _scan_results = data["scan_results"]
            _cves_count = 0
            _critical_count = 0
            _conf_total = 0.0
            _services_set = set()
            _products_set = set()
            for _r in _scan_results:
                if _r.get("service"):
                    _services_set.add(_r["service"])
                if _r.get("product"):
                    _products_set.add(_r["product"])
                if _r.get("confidence"):
                    _conf_total += float(_r["confidence"])
                if _r.get("cves"):
                    _cves_count += len(_r["cves"])
                    for _cve in _r["cves"]:
                        if _cve.get("severity", "").lower() in ("critical", "high"):
                            _critical_count += 1
            _total_ports = len(_scan_results)
            data["metrics"] = {
                "total_ports": _total_ports,
                "unique_services": len(_services_set),
                "unique_products": len(_products_set),
                "critical_issues": _critical_count,
                "known_cves": _cves_count,
                "avg_confidence": round(_conf_total / _total_ports, 1) if _total_ports > 0 else 0
            }

            flash("Scan Completed Successfully", "success")
        except Exception as error:
            flash(f"Scan Failed: {error}", "danger")
    return render_template("scan.html", **data)
    
#------------------Logout-----------------

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

with app.app_context():
    db.create_all()
    admin_email = "suraksha@admin.in"
    existing_admin = User.query.filter_by(email=admin_email).first()
    if not existing_admin:
        admin_user = User(
            username="admin",
            email=admin_email,
            password=bcrypt.generate_password_hash("admin123").decode("utf-8")
        )
        db.session.add(admin_user)
        db.session.commit()
        print("Default Admin Created Successfully")

if __name__ == "__main__":
    app.run(
        debug=True
    )
