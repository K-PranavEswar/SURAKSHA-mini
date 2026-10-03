import json
import joblib
import warnings
warnings.filterwarnings("ignore")
import re
import requests
import secrets
from collections import deque
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urldefrag, urljoin, urlparse, urlunparse
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from scanner.sql_detector import detect_sql_injection
from scanner.tech_detector import detect_technology
from scanner.ssl_checker import run_ssl_check
from scanner.network_scan import run_network_scan
init(autoreset=True)
requests.packages.urllib3.disable_warnings()
BASE_DIR = Path(__file__).resolve().parent.parent
SIGNATURE_FILE = BASE_DIR / "scanner" / "signatures.json"
MODEL_FILE = BASE_DIR / "models" / "web_scan_model.pkl"
HEADERS = {
    "User-Agent":
    "Mozilla/5.0 SURAKSHA Vulnerability Scanner"
}
with open(SIGNATURE_FILE, "r") as f:
    SIGNATURES = json.load(f)
SECURITY_HEADERS = SIGNATURES["security_headers"]
SENSITIVE_PATHS = SIGNATURES["sensitive_paths"]
try:
    MODEL = joblib.load(MODEL_FILE)
except:
    MODEL = None
def request(url, timeout=5):
    try:
        return requests.get(url, timeout=timeout, verify=False, allow_redirects=True, headers=HEADERS)
    except requests.RequestException:
        return None

def get_live_url(target):
    host = target.strip().replace("https://", "").replace("http://", "").split("/")[0]
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        response = request(url, 15)
        print(f"{Fore.CYAN}[+] Trying:{Style.RESET_ALL} {url}")
        if response and (response.ok or response.status_code in (301, 302, 403)):
            return response.url, response
    raise Exception("No active web service detected.")

def check_security_headers(headers):
    return {header: "Present" if header in headers else "Missing" for header in SECURITY_HEADERS}

def check_server_with_nmap(target):
    print("[SERVER DEBUG] Function entered")
    print(f"[SERVER DEBUG] Target = {target}")
    import shutil
    nmap_path = shutil.which("nmap")
    print(f"[SERVER DEBUG] Scanner/tool detected = {nmap_path}")
    print("[SERVER DEBUG] Scan started")
    try:
        host = target.strip().replace("https://", "").replace("http://", "").split("/")[0]
        result = run_network_scan(host, ["os", "version"])
        status = result.get("status", "failed")
        final_res = {
            "status": status.lower(),
            "data": result,
            "error": result.get("error")
        }
        print(f"[SERVER DEBUG] Scan result = {result.get('server_ecosystem')}")
        print(f"[SERVER DEBUG] Returning result = {final_res}")
        return final_res
    except Exception as e:
        final_res = {
            "status": "unavailable" if not nmap_path else "failed",
            "data": {},
            "error": str(e) if nmap_path else "Nmap is not installed or not available in PATH"
        }
        print(f"[SERVER DEBUG] Returning result = {final_res}")
        return final_res

def check_https_with_tls(url):
    print("[HTTPS DEBUG] Function entered")
    print(f"[HTTPS DEBUG] Target = {url}")
    print("[HTTPS DEBUG] Connection attempt started")
    try:
        result = run_ssl_check(url)
        print(f"[HTTPS DEBUG] TLS connection result = {result.get('ssl_valid')}")
        print(f"[HTTPS DEBUG] Certificate result = {result.get('issuer')}")
        status = "scanned" if result.get("ssl_valid") else "failed"
        final_res = {
            "status": status,
            "data": result,
            "error": result.get("error")
        }
        print(f"[HTTPS DEBUG] Returning result = {final_res}")
        return final_res
    except Exception as e:
        print(f"[HTTPS DEBUG] Exception: {e}")
        final_res = {
            "status": "failed",
            "data": {},
            "error": str(e)
        }
        print(f"[HTTPS DEBUG] Returning result = {final_res}")
        return final_res

def check_sensitive_paths(base_url):
    found = []
    for path in SENSITIVE_PATHS:
        response = request(urljoin(base_url, path))
        if not response:
            continue
        if response.status_code in (200, 301, 302):
            found.append(path)
    return found

XSS_MAX_CRAWL_PAGES = 12
XSS_MAX_CRAWL_DEPTH = 2
XSS_MAX_TESTS = 35
XSS_TIMEOUT = 7
XSS_SEARCH_PARAM_HINTS = {"q", "query", "search", "s", "keyword", "keywords", "term", "text", "name"}

def _normalize_url(url):
    try:
        cleaned, _fragment = urldefrag(url)
        parsed = urlparse(cleaned)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return None
        path = parsed.path or "/"
        return urlunparse((parsed.scheme, parsed.netloc, path, "", parsed.query, ""))
    except Exception:
        return None


def _origin(url):
    parsed = urlparse(url)
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return parsed.scheme, (parsed.hostname or "").lower(), port

def _same_origin(base_url, candidate_url):
    try:
        return _origin(base_url) == _origin(candidate_url)
    except Exception:
        return False


def _url_without_query(url):
    parsed = urlparse(url)
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def _build_url_with_parameter(url, parameter, value):
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    updated = []
    replaced = False
    for key, existing_value in pairs:
        if key == parameter:
            if not replaced:
                updated.append((key, value))
                replaced = True
            continue
        updated.append((key, existing_value))
    if not replaced:
        updated.append((parameter, value))
    query = urlencode(updated, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", query, ""))

def _is_html_response(response):
    content_type = response.headers.get("Content-Type", "").lower()
    return "text/html" in content_type or "application/xhtml" in content_type or not content_type


def _candidate_priority(candidate):
    path = urlparse(candidate["url"]).path.lower()
    params = candidate["parameters"]
    if any(param.lower() in XSS_SEARCH_PARAM_HINTS for param in params):
        return 0
    if "search" in path:
        return 1
    return 2


def _add_url_parameter_candidates(candidates, seen, url):
    parsed = urlparse(url)
    params = [key for key, _value in parse_qsl(parsed.query, keep_blank_values=True)]
    for parameter in params:
        key = ("GET", _url_without_query(url), parameter)
        if key in seen:
            continue
        seen.add(key)
        candidates.append({"method": "GET", "url": url, "parameters": [parameter], "source": "url"})

def _extract_get_form_candidate(form, page_url, base_url):
    method = (form.get("method") or "get").lower()
    if method != "get":
        return None

    action = form.get("action") or page_url
    action_url = _normalize_url(urljoin(page_url, action))
    if not action_url or not _same_origin(base_url, action_url):
        return None

    parsed = urlparse(action_url)
    values = parse_qsl(parsed.query, keep_blank_values=True)
    testable_parameters = []

    for field in form.find_all(["input", "textarea", "select"]):
        name = field.get("name")
        if not name:
            continue

        tag_name = field.name.lower()
        input_type = (field.get("type") or "text").lower()
        if input_type in ("submit", "button", "reset", "image", "file", "password"):
            continue

        value = field.get("value") or ""
        if tag_name == "select":
            selected = field.find("option", selected=True) or field.find("option")
            value = selected.get("value") if selected else ""
        values.append((name, value))

        if input_type != "hidden":
            testable_parameters.append(name)

    if not testable_parameters:
        return None

    query = urlencode(values, doseq=True)
    form_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", query, ""))
    return {"method": "GET", "url": form_url, "parameters": testable_parameters, "source": "form"}


def _discover_xss_inputs(start_url, start_response=None):
    base_url = _normalize_url(start_url)
    if not base_url:
        return []
    candidates = []
    seen_candidates = set()
    visited = set()
    queued = {base_url}
    queue = deque([(base_url, 0, start_response)])

    while queue and len(visited) < XSS_MAX_CRAWL_PAGES:
        current_url, depth, provided_response = queue.popleft()
        if current_url in visited:
            continue
        visited.add(current_url)

        _add_url_parameter_candidates(candidates, seen_candidates, current_url)

        response = provided_response if provided_response is not None else request(current_url, XSS_TIMEOUT)
        if not response or not _is_html_response(response):
            continue

        # Parameter discovery stays same-origin and shallow: URL parameters, safe GET
        # forms, and crawlable links that may expose more GET inputs.
        soup = BeautifulSoup(response.text or "", "html.parser")
        for form in soup.find_all("form"):
            candidate = _extract_get_form_candidate(form, response.url or current_url, base_url)
            if not candidate:
                continue
            for parameter in candidate["parameters"]:
                key = ("GET", _url_without_query(candidate["url"]), parameter)
                if key in seen_candidates:
                    continue
                seen_candidates.add(key)
                candidates.append({"method": "GET", "url": candidate["url"], "parameters": [parameter], "source": candidate["source"]})
        if depth >= XSS_MAX_CRAWL_DEPTH:
            continue

        for link in soup.find_all("a", href=True):
            next_url = _normalize_url(urljoin(response.url or current_url, link["href"]))
            if not next_url or not _same_origin(base_url, next_url):
                continue
            if next_url in visited or next_url in queued:
                continue
            queued.add(next_url)
            queue.append((next_url, depth + 1, None))

    return sorted(candidates, key=_candidate_priority)


def _reflection_snippets(body, marker, radius=90):
    snippets = []
    start = 0
    while True:
        index = body.find(marker, start)
        if index == -1:
            break
        snippets.append(body[max(0, index - radius):index + len(marker) + radius])
        start = index + len(marker)
    return snippets


def _reflection_contexts(body, marker):
    contexts = set()
    for snippet in _reflection_snippets(body, marker):
        lower_snippet = snippet.lower()
        if "<script" in lower_snippet and "</script" in lower_snippet:
            contexts.add("script")
        elif "<" in snippet and ">" in snippet:
            contexts.add("html-tag-or-attribute")
        else:
            contexts.add("text")
    return sorted(contexts)


def _inside_non_executable_container(body, index):
    lower_body = body.lower()
    comment_open = lower_body.rfind("<!--", 0, index)
    comment_close = lower_body.rfind("-->", 0, index)
    if comment_open != -1 and comment_open > comment_close:
        return True

    for tag_name in ("textarea", "title", "style", "xmp", "plaintext"):
        open_index = lower_body.rfind(f"<{tag_name}", 0, index)
        close_index = lower_body.rfind(f"</{tag_name}", 0, index)
        if open_index != -1 and open_index > close_index:
            return True
    return False


def _confirm_executable_context(body, marker):
    escaped_marker = re.escape(marker)
    checks = [
        (
            "event-handler HTML context",
            rf"(?is)<[^>]+\bon[a-z0-9_-]+\s*=\s*['\"]?[^>]*alert\s*\([^>]*{escaped_marker}[^>]*>"
        ),
        (
            "script HTML context",
            rf"(?is)<script\b[^>]*>.*?alert\s*\([^<]*{escaped_marker}.*?</script\s*>"
        ),
        (
            "javascript URL context",
            rf"(?is)<[^>]+\b(?:href|src|xlink:href)\s*=\s*['\"]?\s*javascript:[^>]*{escaped_marker}[^>]*>"
        ),
    ]
    for context, pattern in checks:
        for match in re.finditer(pattern, body):
            marker_index = body.find(marker, match.start(), match.end())
            if marker_index != -1 and not _inside_non_executable_container(body, marker_index):
                return context
    return None


def _make_xss_finding(candidate, parameter, payload, payload_url, marker, response, context):
    endpoint = _url_without_query(response.url or candidate["url"])
    test_query = f"{parameter}={payload}"
    return {
        "issue": f"Reflected Cross-Site Scripting (XSS) in parameter '{parameter}' at {endpoint}",
        "vulnerability": "Reflected Cross-Site Scripting (XSS)",
        "type": "Reflected Cross-Site Scripting (XSS)",
        "endpoint": endpoint,
        "parameter": parameter,
        "method": candidate["method"],
        "payload": payload,
        "test_marker": marker,
        "test_query": test_query,
        "test_url": payload_url,
        "evidence": "The scanner-controlled test value was reflected into an executable HTML context.",
        "detection_reason": "Scanner-controlled input was reflected into an executable HTML context.",
        "context": context,
        "severity": "High"
    }


def detect_xss_indicators(url):
    findings = []
    tested = set()

    initial_response = request(url, XSS_TIMEOUT)
    candidates = _discover_xss_inputs(url, initial_response)

    for candidate in candidates:
        for parameter in candidate["parameters"]:
            if len(tested) >= XSS_MAX_TESTS:
                return findings

            test_key = (candidate["method"], _url_without_query(candidate["url"]), parameter)
            if test_key in tested:
                continue
            tested.add(test_key)

            marker = f"SURAKSHA_XSS_{secrets.token_hex(5)}"
            marker_url = _build_url_with_parameter(candidate["url"], parameter, marker)
            marker_response = request(marker_url, XSS_TIMEOUT)
            if not marker_response or marker not in (marker_response.text or ""):
                continue

            # Reflection detection first ties the response to scanner-controlled input.
            # Payload probes are then checked only around that unique marker, which avoids
            # treating unrelated <script>, onerror, or javascript: strings as XSS.
            reflection_contexts = _reflection_contexts(marker_response.text or "", marker)
            payloads = [f"<svg onload=alert('{marker}')>", f"\"><svg onload=alert('{marker}')>", f"'><svg onload=alert('{marker}')>", f"';alert('{marker}');//", f"javascript:alert('{marker}')"]

            for payload in payloads:
                payload_url = _build_url_with_parameter(candidate["url"], parameter, payload)
                payload_response = request(payload_url, XSS_TIMEOUT)
                if not payload_response:
                    continue

                body = payload_response.text or ""
                if marker not in body:
                    continue

                # Confirmation requires raw executable HTML/JS created from the injected
                # value. Plain text-node reflection remains unreported.
                executable_context = _confirm_executable_context(body, marker)
                if not executable_context:
                    continue

                finding = _make_xss_finding(candidate, parameter, payload, payload_url, marker, payload_response, executable_context)
                finding["reflection_contexts"] = reflection_contexts
                findings.append(finding)
                break
    return findings

RISK_PRIORITY = {"Low": 0,"Medium": 1,"High": 2,"Critical": 3}

def _highest_risk(*levels):
    known_levels = [level for level in levels if level in RISK_PRIORITY]
    if not known_levels:
        return "Low"
    return max(known_levels, key=lambda level: RISK_PRIORITY[level])

def _xss_issue_severity(issue):
    if isinstance(issue, dict):
        severity = issue.get("severity") or issue.get("risk") or issue.get("risk_level")
        if severity in RISK_PRIORITY:
            return severity
    return "High"

def predict_risk(headers, paths, sql, xss, https_enabled, server):
    # Check if there was any successful data collected
    has_successful_scan = False
    if headers is not None: has_successful_scan = True
    if paths is not None: has_successful_scan = True
    if sql is not None: has_successful_scan = True
    if xss is not None: has_successful_scan = True
    if https_enabled is not None: has_successful_scan = True
    if server is not None: has_successful_scan = True

    if not has_successful_scan:
        return "Not Evaluated"

    sql_payload_count = len(sql["payloads"]) if sql else 0
    https_penalty = 1 if (https_enabled and https_enabled.get("status") == "scanned" and not https_enabled.get("data", {}).get("ssl_valid")) else 0
    server_known = 1 if (server and server.get("status") == "scanned" and server.get("data", {}).get("server_ecosystem", "Protected / Hidden") not in ["Unknown", "Protected / Hidden"]) else 0
    missing_headers = sum(value == "Missing" for value in headers.values()) if headers else 0
    paths_count = len(paths) if paths is not None else 0
    xss_count = len(xss) if xss else 0

    if missing_headers == 0 and paths_count == 0 and sql_payload_count == 0 and xss_count == 0 and https_penalty == 0:
        return "Low"

    features = [[missing_headers, paths_count, 0, 0, https_penalty, server_known]]
    
    sql_risk = sql.get("severity", "Low") if sql else "Low"
    
    if MODEL:
        prediction = MODEL.predict(features)[0]
        model_risk = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}.get(prediction, "Unknown")
        xss_risk = _highest_risk(*[_xss_issue_severity(issue) for issue in xss]) if xss else "Low"
        return _highest_risk(model_risk, sql_risk, xss_risk)
        
    score = missing_headers + (paths_count * 2)
    if score >= 15:
        base_risk = "Critical"
    elif score >= 10:
        base_risk = "High"
    elif score >= 5:
        base_risk = "Medium"
    else:
        base_risk = "Low"
        
    xss_risk = _highest_risk(*[_xss_issue_severity(issue) for issue in xss]) if xss else "Low"
    return _highest_risk(base_risk, sql_risk, xss_risk)

def run_web_scan(target, scan_options=None):
    scan_options = scan_options or ["headers", "paths", "sql", "xss", "https", "tech"]
    url, response = get_live_url(target)
    headers = response.headers
    
    print(f"[DEBUG] Executing modules for: {scan_options}")
    
    security_headers = check_security_headers(headers) if "headers" in scan_options else None
    print(f"[DEBUG] Security Headers scanner returned = {'Scanned' if security_headers else 'Not Scanned'}")
    
    sensitive_paths = check_sensitive_paths(url) if "paths" in scan_options else None
    print(f"[DEBUG] Sensitive Paths scanner returned = {len(sensitive_paths) if sensitive_paths else 0} paths found")
    
    sql_issues = detect_sql_injection(url) if "sql" in scan_options else None
    print(f"[DEBUG] SQL Injection scanner returned = {len(sql_issues['payloads']) if sql_issues else 0} payloads found")
    
    xss_issues = detect_xss_indicators(url) if "xss" in scan_options else None
    print(f"[DEBUG] XSS scanner returned = {len(xss_issues) if xss_issues else 0} issues found")
    
    # None = not scanned; True/False = scanned result.
    print("[DEBUG] HTTPS scanner called")
    https_enabled = check_https_with_tls(url) if "https" in scan_options else None
    print(f"[DEBUG] HTTPS scanner returned = {https_enabled}")
    if https_enabled is None:
        print("[DEBUG] HTTPS scan status = Not Scanned")
    elif https_enabled.get("status") == "failed":
        print("[DEBUG] HTTPS scan status = Scan Failed")
    else:
        print("[DEBUG] HTTPS scan status = Scanned")
        
    tech_issues = detect_technology(url, detailed=True) if "tech" in scan_options else None
    
    print("[DEBUG] Server scanner called")
    server = check_server_with_nmap(target) if ("tech" in scan_options or "headers" in scan_options) else None
    print(f"[DEBUG] Server scanner returned = {server}")
    if server is None:
        print("[DEBUG] Server scan status = Not Scanned")
    else:
        print("[DEBUG] Server scan status = Scanned")
        
    risk_value = predict_risk(
        security_headers or {},
        sensitive_paths,
        sql_issues,
        xss_issues or [],
        https_enabled,
        server
    )
    print(f"[DEBUG] Risk input (missing headers) = {sum(v == 'Missing' for v in security_headers.values()) if security_headers else 0}")
    print(f"[DEBUG] Risk input (paths) = {len(sensitive_paths) if sensitive_paths else 0}")
    print(f"[DEBUG] Risk input (sql) = {len(sql_issues['payloads']) if sql_issues else 0}")
    print(f"[DEBUG] Risk input (xss) = {len(xss_issues) if xss_issues else 0}")
    print(f"[DEBUG] Final risk calculated = {risk_value}")
    
    return {
        "url": url,
        "server": server,
        "https_enabled": https_enabled,
        "security_headers": security_headers,
        "sensitive_paths": sensitive_paths,
        "sql_issues": sql_issues,
        "xss_issues": xss_issues,
        "tech_issues": tech_issues,
        "scan_options": list(scan_options),
        "risk": risk_value,
        "scan_time": __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

if __name__ == "__main__":
    target = input("\nEnter Target URL: ").strip()
    result = run_web_scan(target)
    print(json.dumps(result, indent=4))
