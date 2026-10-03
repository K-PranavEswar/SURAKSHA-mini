CVE_DATABASE = {
    "Apache Tomcat": [{"cve": "CVE-2020-1938", "severity": "Critical", "description": "Ghostcat AJP File Read / Inclusion Vulnerability"}, {"cve": "CVE-2017-12617", "severity": "High", "description": "Remote Code Execution via JSP Upload"}],
    "Apache": [{"cve": "CVE-2021-41773", "severity": "Critical", "description": "Path Traversal and Remote Code Execution"}],
    "nginx": [{"cve": "CVE-2021-23017", "severity": "High", "description": "Resolver Off-by-One Heap Write"}],
    "OpenSSH": [{"cve": "CVE-2018-15473", "severity": "Medium", "description": "Username Enumeration"}],
    "Microsoft IIS": [{"cve": "CVE-2021-31166", "severity": "Critical", "description": "HTTP Protocol Stack Remote Code Execution"}],
    "vsftpd": [{"cve": "CVE-2011-2523", "severity": "Critical", "description": "Backdoor Command Execution"}],
    "ProFTPD": [{"cve": "CVE-2015-3306", "severity": "Critical", "description": "Remote Code Execution"}],
    "MySQL": [{"cve": "CVE-2016-6662", "severity": "Critical", "description": "Privilege Escalation"}],
    "PostgreSQL": [{"cve": "CVE-2018-1058", "severity": "High", "description": "Search Path Privilege Escalation"}],
    "Samba": [{"cve": "CVE-2017-7494", "severity": "Critical", "description": "Remote Code Execution"}],
    "Redis": [{"cve": "CVE-2022-0543", "severity": "Critical", "description": "Lua Sandbox Escape"}],
    "MongoDB": [{"cve": "CVE-2019-2391", "severity": "High", "description": "Authentication Bypass"}],
    "AkamaiGHost": [{"cve": "None", "severity": "Low", "description": "No publicly known critical CVEs detected."}]
}

def map_cves(service_name):
    if not service_name:
        return []
    service = service_name.lower()
    findings = []
    for product, cves in CVE_DATABASE.items():
        if product.lower() in service:
            findings.extend(cves)
    return findings

def highest_cve_severity(cves):
    if not cves:
        return "None"
    priority = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1
    }
    highest = max(cves, key=lambda x: priority.get(x["severity"], 0))
    return highest["severity"]

if __name__ == "__main__":
    service = input("Service Name : ")
    cves = map_cves(service)
    print("\nDetected CVEs\n")
    if not cves:
        print("No CVEs Found")
    else:
        for cve in cves:
            print(cve)