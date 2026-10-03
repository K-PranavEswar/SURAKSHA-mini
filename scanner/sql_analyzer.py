import re
SQL_ERRORS = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql error",
    "mysqli",

    # PostgreSQL
    "postgresql",
    "pg_query",
    "postgres error",

    # SQLite
    "sqlite",
    "sqlite error",

    # Oracle
    "ora-",
    "oracle",

    # SQL Server
    "sql server",
    "microsoft ole db provider",
    "odbc sql server driver",
    "native client",

    # Generic
    "database error",
    "sql syntax",
    "syntax error",
    "sqlstate",
    "sql exception",
    "unclosed quotation mark"
]

def detect_sql_errors(response_text):
    """
    Detect SQL error messages.
    """
    findings = []
    page = response_text.lower()

    for error in SQL_ERRORS:
        if error in page:
            findings.append(f"SQL Error: {error}")
    return findings

def detect_reflection(response_text, payload):
    """
    Detect reflected payload.
    """
    if payload.lower() in response_text.lower():
        return ["Payload Reflection"]
    return []

def compare_status(normal_status, injected_status):
    """
    Detect HTTP status changes.
    """
    if normal_status != injected_status:
        return [f"HTTP Status Changed ({normal_status} → {injected_status})"]
    return []

def compare_response_length(normal_text, injected_text, threshold=300):
    """
    Compare page sizes.
    """
    difference = abs(len(normal_text) - len(injected_text))
    if difference > threshold:
        return [f"Response Length Changed ({difference} bytes)"]
    return []

def compare_boolean_response(true_response, false_response):
    """
    Boolean SQLi comparison.
    """
    if true_response != false_response:
        return ["Boolean Response Difference"]
    return []

def detect_time_delay(elapsed, threshold=4):
    """
    Detect possible time-based SQLi.
    """
    if elapsed >= threshold:
        return [f"Response Delayed ({elapsed:.2f}s)"]
    return []

def analyze_sql_response(normal_response, injected_response, payload, elapsed):
    """
    Combine all SQL analysis.
    """
    findings = []
    findings.extend(detect_sql_errors(injected_response.text))
    findings.extend(detect_reflection(injected_response.text, payload))
    findings.extend(compare_status(normal_response.status_code, injected_response.status_code))
    findings.extend(compare_response_length(normal_response.text, injected_response.text))
    findings.extend(detect_time_delay(elapsed))
    return list(set(findings))