import socket
COMMON_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
                 80: "HTTP",110: "POP3", 143: "IMAP", 443: "HTTPS",
                 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt"}

def grab_banner(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((target, port))
        try:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        except:
            pass
        banner = sock.recv(4096).decode(errors="ignore").strip()
        sock.close()
        if not banner:
            banner = "No banner received"
        return {
            "port": port,
            "service": COMMON_PORTS.get(port, "Unknown"),
            "banner": banner[:300]
        }
    except Exception:
        return {
            "port": port,
            "service": COMMON_PORTS.get(port, "Unknown"),
            "banner": "Unavailable"
        }

def run_banner_scan(target, open_ports):
    results = []
    for port in open_ports:
        data = grab_banner(target, port)
        results.append(data)
    return results