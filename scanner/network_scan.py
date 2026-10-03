import shutil
import nmap
from scanner.banner_grabber import run_banner_scan
from scanner.scan_builder import build_scan_arguments
from scanner.result_parser import build_result
from scanner.risk_engine import calculate_risk
from scanner.ai_risk_predictor import predict_ai_risk
from models.vulnerability_model import Vulnerability
from scanner.cve_mapper import map_cves
from scanner.protocol_analyzer import analyze_protocol
from scanner.web_service_detector import detect_web_service

from urllib.parse import urlparse


def normalize_target(target):
    """Strip scheme, path, query, fragment — return bare hostname/IP for Nmap."""
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target
    parsed = urlparse(target)
    return parsed.hostname or target


def run_network_scan(target, scan_options):
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        return {
            "status": "Scan Unavailable",
            "error": "Nmap is not installed or not available in PATH.",
            "results": [],
            "banner_results": [],
            "risk": "Not Evaluated",
            "open_port_count": 0,
            "server_ecosystem": "Scan Unavailable"
        }

    normalized_target = normalize_target(target)
    nmap_args = build_scan_arguments(scan_options)

    try:
        scanner = nmap.PortScanner(nmap_search_path=(nmap_path,))
        scanner.scan(hosts=normalized_target, arguments=nmap_args)

        # ---- Concise debug logging ----
        print("=" * 60)
        print(f"[NMAP] Target   : {target}")
        print(f"[NMAP] Normalized: {normalized_target}")
        print(f"[NMAP] Command  : {scanner.command_line()}")
        print(f"[NMAP] Hosts    : {scanner.all_hosts()}")
        stats = scanner.scanstats()
        print(f"[NMAP] Stats    : up={stats.get('uphosts')}, down={stats.get('downhosts')}, elapsed={stats.get('elapsed')}s")
        print("=" * 60)

        vuln_cache = {vuln.port: vuln for vuln in Vulnerability.query.all()}
        results = []
        open_ports = []
        ecosystem = "Protected / Hidden"
        os_details = []
        host_status = "unknown"
        resolved_ip = None

        # ---- No hosts found at all ----
        if not scanner.all_hosts():
            print(f"[NMAP] No hosts found for {normalized_target}")
            return {
                "status": "Scan Failed",
                "error": f"No host was found/reachable by Nmap for '{normalized_target}'.",
                "results": [],
                "banner_results": [],
                "risk": "Not Evaluated",
                "open_port_count": 0,
                "server_ecosystem": "Scan Failed",
                "os_details": [],
                "host_status": "down",
                "resolved_ip": None
            }

        # ---- Process the first host ----
        for host in scanner.all_hosts():
            host_data = scanner[host]
            host_status = host_data.get("status", {}).get("state", "unknown")
            resolved_ip = host

            print(f"[NMAP] Host {host} status: {host_status}")

            # ---- OS Detection ----
            if "os" in scan_options:
                try:
                    os_matches = host_data.get("osmatch", [])
                    if os_matches:
                        ecosystem = os_matches[0].get("name", ecosystem)
                        for match in os_matches:
                            os_details.append({
                                "name": match.get("name", "Unknown"),
                                "accuracy": match.get("accuracy", "0")
                            })
                except Exception as e:
                    print(f"[NMAP] OS Detection Error: {e}")

            # ---- TCP Port Data ----
            # Safely access the TCP dictionary. If Nmap returned no TCP data
            # (e.g. all ports filtered, or firewall blocking), this is an
            # empty dict — NOT a scan failure.
            tcp_data = host_data.get("tcp", {})

            if not tcp_data:
                print(f"[VERSION] No open TCP ports returned for {host}")
            else:
                print(f"[VERSION] Open ports found: {len(tcp_data)}")

            for port, data in tcp_data.items():
                state = data.get("state", "")
                if state not in ["open", "open|filtered"]:
                    continue

                open_ports.append(port)

                service = data.get("name", "unknown")
                product = data.get("product", "")
                version = data.get("version", "")
                service_version = f"{product} {version}".strip()

                # Debug: per-port version detection status
                if product:
                    print(f"[VERSION] {port}/tcp → {service} → {product} → {'version detected' if version else 'version not detected'}")
                else:
                    print(f"[VERSION] {port}/tcp → {service} → product unknown → version not detected")

                result = build_result(
                    port,
                    "tcp",
                    data,
                    vuln_cache.get(port),
                    target
                )

                result["protocol_analysis"] = analyze_protocol(service)
                result["cves"] = map_cves(service_version)
                result["web_service"] = detect_web_service(target, port)

                try:
                    ai_prediction = predict_ai_risk(
                        port=port,
                        protocol="tcp",
                        service=service,
                        version=service_version,
                        os_name=ecosystem,
                        open_ports=len(open_ports)
                    )
                    result["ai_risk"] = ai_prediction.get("risk")
                    result["confidence"] = ai_prediction.get("confidence", 0)
                    result["algorithm"] = ai_prediction.get("algorithm")
                    result["rf_result"] = ai_prediction.get("random_forest")
                except Exception as e:
                    print(f"[NMAP] AI Prediction Error for port {port}: {e}")
                    result["ai_risk"] = "Unknown"
                    result["confidence"] = 0
                    result["algorithm"] = "None"

                results.append(result)

        # ---- Banner Grabbing ----
        banner_results = []
        if "banner" in scan_options and open_ports:
            banner_results = run_banner_scan(target, open_ports)

        return {
            "status": "Scanned",
            "results": results,
            "banner_results": banner_results,
            "risk": calculate_risk(open_ports),
            "open_port_count": len(open_ports),
            "server_ecosystem": ecosystem,
            "os_details": os_details,
            "host_status": host_status,
            "resolved_ip": resolved_ip
        }

    except Exception as e:
        print(f"[ERROR] Nmap scan failed: {e}")
        return {
            "status": "Scan Failed",
            "error": str(e),
            "results": [],
            "banner_results": [],
            "risk": "Not Evaluated",
            "open_port_count": 0,
            "server_ecosystem": "Scan Failed",
            "os_details": [],
            "host_status": "error",
            "resolved_ip": None
        }