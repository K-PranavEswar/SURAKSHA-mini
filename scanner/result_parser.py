def build_result(port, protocol, data, vuln, target):
    """
    Build a structured result dictionary from a single Nmap port record.
    
    Uses actual Nmap data as the source of truth.
    Does NOT fabricate product/version information.
    """
    service = data.get("name") or (vuln.service if vuln else "Unknown")
    product = data.get("product") or "Unknown"
    version = data.get("version") or "Not Detected"
    extra_info = data.get("extrainfo") or ""
    cpe_list = data.get("cpe", "")
    tunnel = data.get("tunnel", "")

    result = {
        "port": port,
        "state": data.get("state", "Unknown"),
        "protocol": protocol.upper(),
        "service": service,
        "product": product,
        "version": version,
        "extra_info": extra_info,
        "tunnel": tunnel,
        "cpe": cpe_list,
        "version_detection": "Successful" if version != "Not Detected" else "Failed",
        "risk_level": vuln.severity if vuln else "Low",
        "vulnerability": vuln.vulnerability_name if vuln else "No Known Vulnerability",
        "cve": vuln.cve_id if vuln else "N/A",
        "attack_type": vuln.attack_type if vuln else "Not Identified",
        "recommendation": vuln.recommendation if vuln else "No Action Required",
        "scripts": data.get("script", {})
    }
    return result