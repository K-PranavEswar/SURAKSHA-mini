RISK_WEIGHTS = {
    "SQL Error": 5,
    "Payload Reflection": 3,
    "HTTP Status Changed": 2,
    "Response Length Changed": 4,
    "Boolean Response Difference": 5,
    "Response Delayed": 6
}
RECOMMENDATIONS = {
    "Critical": [
        "Use Prepared Statements (Parameterized Queries).",
        "Validate and sanitize all user inputs.",
        "Disable SQL error messages in production.",
        "Review database permissions immediately."
    ],
    "High": [
        "Use parameterized queries.",
        "Validate input data.",
        "Hide database error messages.",
        "Enable server-side input filtering."
    ],
    "Medium": [
        "Validate user inputs.",
        "Implement allow-list input validation.",
        "Review SQL query construction."
    ],
    "Low": [
        "Continue security monitoring.",
        "Review application logs periodically."
    ]
}
def calculate_score(findings):
    score = 0
    for finding in findings:
        for key, value in RISK_WEIGHTS.items():
            if finding.startswith(key):
                score += value
    return score

def calculate_severity(score):
    if score >= 15:
        return "Critical"
    if score >= 10:
        return "High"
    if score >= 5:
        return "Medium"
    return "Low"

def calculate_confidence(score):
    return min(score * 10, 100)
def get_recommendation(severity):
    return RECOMMENDATIONS.get(severity, [])
def generate_risk_report(findings):
    score = calculate_score(findings)
    severity = calculate_severity(score)
    confidence = calculate_confidence(score)
    recommendation = get_recommendation(severity)
    return {
        "score": score,
        "severity": severity,
        "confidence": confidence,
        "recommendation": recommendation
    }