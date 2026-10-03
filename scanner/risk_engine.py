CRITICAL_PORTS = {
    21, 22, 23, 25,
    445, 1433, 3306,
    3389, 5432,
    6379, 27017
}
def calculate_risk(open_ports):
    score = sum(2 if port in CRITICAL_PORTS else 1 for port in open_ports)
    if score >= 8:
        return "Critical"
    if score >= 4:
        return "Medium"
    return "Low"