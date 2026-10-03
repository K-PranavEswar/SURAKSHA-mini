import time
import requests
import os
import joblib
from urllib.parse import urlparse, parse_qsl
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanner.sql_payloads import ERROR_BASED, BOOLEAN_BASED, UNION_BASED, TIME_BASED
from scanner.sql_analyzer import analyze_sql_response, compare_boolean_response
from scanner.sql_risk import generate_risk_report

try:
    _model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models', 'sqli_model.pkl')
    SQLI_MODEL = joblib.load(_model_path)
except Exception:
    SQLI_MODEL = None

HEADERS = {
    "User-Agent": "SURAKSHA Vulnerability Scanner"
}
FALLBACK_PARAMETERS = [
    "id", "uid", "user", "userid", "page", "cat", "category",
    "search", "q", "query", "item", "product"
]

def build_url(url, parameter, payload):
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{parameter}={payload}"

def check_ml_payload(payload):
    if not SQLI_MODEL:
        return False, 0.0
    try:
        if SQLI_MODEL.predict([payload])[0] == 1:
            proba = 0.0
            if hasattr(SQLI_MODEL, "predict_proba"):
                proba = SQLI_MODEL.predict_proba([payload])[0][1]
            return True, proba
    except Exception:
        pass
    return False, 0.0

def test_payload_stage(session, url, parameter, payload, normal_response):
    try:
        target = build_url(url, parameter, payload)
        start = time.time()
        injected = session.get(target, headers=HEADERS, timeout=7, verify=False, allow_redirects=True)
        elapsed = time.time() - start
        findings = analyze_sql_response(normal_response, injected, payload, elapsed)
        return findings if findings else None
    except requests.exceptions.Timeout:
        elapsed = time.time() - start
        if any(t in payload.upper() for t in ['SLEEP', 'WAITFOR']):
            return [f"Response Delayed (Timeout after {elapsed:.1f}s)"]
        return None
    except Exception:
        return None

def boolean_test(session, url, parameter):
    try:
        true_payload = "' AND 1=1--"
        false_payload = "' AND 1=2--"
        true_req = session.get(build_url(url, parameter, true_payload), headers=HEADERS, timeout=5, verify=False)
        false_req = session.get(build_url(url, parameter, false_payload), headers=HEADERS, timeout=5, verify=False)
        findings = compare_boolean_response(true_req.text, false_req.text)
        if findings:
            return true_payload, findings
        return None
    except Exception:
        return None

def is_strong_evidence(findings):
    if not findings:
        return False
    weak = ["Response Length Changed", "HTTP Status Changed"]
    for f in findings:
        if not any(f.startswith(w) for w in weak):
            return True
    return False

def detect_sql_injection(url):
    start_time = time.time()
    session = requests.Session()
    
    try:
        normal_response = session.get(url, headers=HEADERS, timeout=10, verify=False, allow_redirects=True)
    except Exception:
        return None

    parsed = urlparse(url)
    discovered_params = [k for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
    
    parameters_to_test = []
    if discovered_params:
        parameters_to_test.extend(discovered_params)
        print(f"[SQLi] Parameters discovered: {len(discovered_params)}")
    else:
        parameters_to_test.extend(FALLBACK_PARAMETERS)
        print(f"[SQLi] No parameters in URL, using {len(FALLBACK_PARAMETERS)} fallback parameters.")

    vulnerable_params = set()
    successful_payloads = set()
    all_findings = set()
    
    ml_detected = False
    max_ml_prob = 0.0
    fast_tests_run = 0
    
    def process_parameter(parameter):
        local_findings = set()
        local_payloads = set()
        strong_evidence = False
        weak_evidence = False
        local_ml_detected = False
        local_max_prob = 0.0
        tests_count = 0

        stage1_payloads = ERROR_BASED + BOOLEAN_BASED + UNION_BASED
        for payload in stage1_payloads:
            if strong_evidence:
                break
                
            tests_count += 1
            findings = test_payload_stage(session, url, parameter, payload, normal_response)
            
            is_sqli, proba = check_ml_payload(payload)
            if is_sqli:
                local_ml_detected = True
                local_max_prob = max(local_max_prob, proba)

            if findings:
                local_payloads.add(payload)
                local_findings.update(findings)
                if is_strong_evidence(findings):
                    strong_evidence = True
                else:
                    weak_evidence = True

        if not strong_evidence:
            tests_count += 2
            bool_result = boolean_test(session, url, parameter)
            for b_payload in ["' AND 1=1--", "' AND 1=2--"]:
                is_sqli, proba = check_ml_payload(b_payload)
                if is_sqli:
                    local_ml_detected = True
                    local_max_prob = max(local_max_prob, proba)

            if bool_result:
                used_payload, bool_findings = bool_result
                local_payloads.add(used_payload)
                local_findings.update(bool_findings)
                if is_strong_evidence(bool_findings):
                    strong_evidence = True

        if not strong_evidence and weak_evidence:
            print(f"[SQLi] Running confirmation for {parameter}...")
            for payload in TIME_BASED:
                tests_count += 1
                findings = test_payload_stage(session, url, parameter, payload, normal_response)
                
                is_sqli, proba = check_ml_payload(payload)
                if is_sqli:
                    local_ml_detected = True
                    local_max_prob = max(local_max_prob, proba)

                if findings:
                    local_payloads.add(payload)
                    local_findings.update(findings)
                    if is_strong_evidence(findings):
                        strong_evidence = True
                        break

        return parameter, local_findings, local_payloads, local_ml_detected, local_max_prob, tests_count

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(process_parameter, p): p for p in parameters_to_test}
        for future in as_completed(futures):
            p = futures[future]
            try:
                param, findings, payloads, l_ml_detected, l_max_prob, t_count = future.result()
                fast_tests_run += t_count
                if findings:
                    vulnerable_params.add(param)
                    successful_payloads.update(payloads)
                    all_findings.update(findings)
                    print(f"[SQLi] Suspicious parameter: {param}")
                if l_ml_detected:
                    ml_detected = True
                    max_ml_prob = max(max_ml_prob, l_max_prob)
            except Exception as e:
                pass

    elapsed_time = time.time() - start_time
    print(f"[SQLi] Fast tests: {fast_tests_run}")
    print(f"[SQLi] Completed in {elapsed_time:.1f}s")

    if all_findings:
        final_findings = list(all_findings)
        if ml_detected:
            if max_ml_prob > 0:
                final_findings.append(f"ML Model Detected SQL Injection (Confidence: {max_ml_prob*100:.1f}%)")
            else:
                final_findings.append("ML Model Detected SQL Injection")
                
        final_findings.append(f"SQL Injection Scan: {elapsed_time:.1f} seconds")
                
        risk = generate_risk_report(final_findings)
        return {
            "issue": "SQL Injection Detected",
            "severity": risk["severity"],
            "confidence": risk["confidence"],
            "score": risk["score"],
            "parameters": list(vulnerable_params),
            "payloads": list(successful_payloads),
            "findings": final_findings,
            "recommendation": risk["recommendation"]
        }
    return None