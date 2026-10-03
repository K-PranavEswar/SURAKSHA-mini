PROTOCOL_DATABASE = {
    "http": {
        "risk": "Medium",
        "description": "HTTP traffic is unencrypted.",
        "recommendation": "Use HTTPS wherever possible."
    },
    "https": {
        "risk": "Low",
        "description": "Secure encrypted communication.",
        "recommendation": "Keep TLS configuration updated."
    },
    "ftp": {
        "risk": "High",
        "description": "FTP transmits credentials in plaintext.",
        "recommendation": "Use SFTP or FTPS."
    },
    "ssh": {
        "risk": "Low",
        "description": "Secure remote administration.",
        "recommendation": "Disable password login and use SSH keys."
    },
    "telnet": {
        "risk": "Critical",
        "description": "Telnet transmits credentials without encryption.",
        "recommendation": "Disable Telnet and migrate to SSH."
    },
    "smtp": {
        "risk": "Medium",
        "description": "Mail service detected.",
        "recommendation": "Enable TLS and configure anti-spam protection."
    },
    "pop3": {
        "risk": "Medium",
        "description": "POP3 detected.",
        "recommendation": "Use POP3S."
    },
    "imap": {
        "risk": "Medium",
        "description": "IMAP service detected.",
        "recommendation": "Enable IMAPS."
    },
    "dns": {
        "risk": "Medium",
        "description": "DNS service detected.",
        "recommendation": "Disable recursion for public DNS servers."
    },
    "snmp": {
        "risk": "High",
        "description": "SNMP may expose device information.",
        "recommendation": "Use SNMPv3."
    },
    "ldap": {
        "risk": "Medium",
        "description": "Directory service detected.",
        "recommendation": "Use LDAPS."
    },
    "rdp": {
        "risk": "High",
        "description": "Remote Desktop is exposed.",
        "recommendation": "Restrict RDP access using VPN or firewall."
    },
    "ms-wbt-server": {
        "risk": "High",
        "description": "Remote Desktop service detected.",
        "recommendation": "Restrict external RDP access."
    },
    "netbios": {
        "risk": "High",
        "description": "NetBIOS information exposure.",
        "recommendation": "Disable NetBIOS if not required."
    },
    "microsoft-ds": {
        "risk": "High",
        "description": "SMB file sharing exposed.",
        "recommendation": "Disable SMBv1 and restrict access."
    },
    "smb": {
        "risk": "High",
        "description": "SMB service detected.",
        "recommendation": "Use SMBv3 and firewall restrictions."
    },
    "mysql": {
        "risk": "High",
        "description": "Database service exposed.",
        "recommendation": "Restrict remote database access."
    },
    "postgresql": {
        "risk": "High",
        "description": "PostgreSQL service detected.",
        "recommendation": "Restrict access using firewall rules."
    },
    "redis": {
        "risk": "Critical",
        "description": "Redis should never be publicly exposed.",
        "recommendation": "Bind Redis to localhost and enable authentication."
    },
    "mongodb": {
        "risk": "Critical",
        "description": "MongoDB service exposed.",
        "recommendation": "Enable authentication and firewall protection."
    }
}

def analyze_protocol(service):
    if not service:
        service = "unknown"
    service = service.lower()
    for protocol, details in PROTOCOL_DATABASE.items():
        if protocol in service:
            return {
                "protocol": protocol.upper(),
                "risk": details["risk"],
                "description": details["description"],
                "recommendation": details["recommendation"]
            }
    return {
        "protocol": service.upper(),
        "risk": "Unknown",
        "description": "No protocol profile available.",
        "recommendation": "Manual verification recommended."
    }

def overall_protocol_risk(results):
    priority = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
        "Unknown": 0
    }
    if not results:
        return "Low"
    score = max(priority.get(item["risk"], 0) for item in results)
    for level, value in priority.items():
        if value == score:
            return level
    return "Low"

if __name__ == "__main__":
    while True:
        protocol = input("Service : ")
        print(analyze_protocol(protocol))