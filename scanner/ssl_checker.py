import ssl
import socket
import certifi
from datetime import datetime
import re
import urllib.parse
import requests


# ============================================================
# SSL/TLS RISK
# ============================================================

def calculate_ssl_risk(
    ssl_valid,
    tls_version,
    days_remaining,
    trust_status=None,
    hostname_valid=True
):
    score = 0

    # Genuine certificate/trust/hostname problem
    if not ssl_valid:
        score += 5

    # Hostname mismatch is a genuine certificate problem
    if hostname_valid is False:
        score += 5

    # Weak/deprecated TLS
    weak_tls = [
        "TLSv1",
        "TLSv1.1",
        "SSLv2",
        "SSLv3"
    ]

    if tls_version in weak_tls:
        score += 4

    # Certificate expiry
    if days_remaining is not None:
        if days_remaining < 0:
            score += 5
        elif days_remaining < 30:
            score += 3
        elif days_remaining < 90:
            score += 2

    # A local CA verification problem alone must not automatically
    # make the scan Critical.
    #
    # The scanner still records the trust failure separately through
    # trust_status / verification_error.
    if (
        trust_status == "local_trust_store_error"
        and ssl_valid
        and hostname_valid is not False
    ):
        score = max(score - 5, 0)

    if score >= 7:
        return "Critical"

    if score >= 3:
        return "Medium"

    return "Low"


# ============================================================
# TARGET NORMALIZATION
# ============================================================

def normalize_ssl_target(target):
    if not target:
        return ""

    value = str(target).strip()

    if "://" in value:
        parsed = urllib.parse.urlparse(value)
        value = parsed.netloc or parsed.path

    value = value.split("/")[0]

    # Remove port only when explicitly supplied.
    # IPv6 literals are preserved.
    if value.count(":") == 1:
        value = value.split(":")[0]

    return value.strip()


# ============================================================
# CERTIFICATE HELPERS
# ============================================================

def _extract_certificate_field(certificate, field):
    values = certificate.get(field, [])

    result = {}

    for item in values:
        if not item:
            continue

        key = item[0]
        value = item[1] if len(item) > 1 else ""

        result[key] = value

    return result


def extract_hash_algorithm(cipher_name):
    if not cipher_name or cipher_name == "Unknown":
        return "Unknown"

    cipher_upper = cipher_name.upper()

    if "SHA512" in cipher_upper:
        return "SHA512"

    if "SHA384" in cipher_upper:
        return "SHA384"

    if "SHA256" in cipher_upper:
        return "SHA256"

    if "SHA1" in cipher_upper:
        return "SHA1"

    if "MD5" in cipher_upper:
        return "MD5"

    if "SHA" in cipher_upper:
        return "SHA"

    return "Unknown"


def _parse_expiry(certificate):
    not_after = certificate.get("notAfter")

    if not not_after:
        return None

    formats = [
        "%b %d %H:%M:%S %Y %Z",
        "%b %d %H:%M:%S %Y GMT"
    ]

    for fmt in formats:
        try:
            return datetime.strptime(not_after, fmt)
        except ValueError:
            continue

    return None


# ============================================================
# CERTIFICATE INSPECTION
# ============================================================

def inspect_certificate(hostname):
    """
    Performs a TLS connection WITHOUT certificate verification.

    This connection is NOT used to declare the certificate trusted.

    It exists only so SURAKSHA can inspect:
        - peer certificate
        - TLS version
        - cipher
        - expiry
        - issuer
        - subject

    Trust validation is performed separately by verify_certificate().
    """

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection(
        (hostname, 443),
        timeout=10
    ) as sock:

        with context.wrap_socket(
            sock,
            server_hostname=hostname
        ) as secure_sock:

            certificate = secure_sock.getpeercert()

            # With CERT_NONE getpeercert() can return an empty
            # dictionary. Obtain the DER certificate and decode it.
            if not certificate:
                certificate_der = secure_sock.getpeercert(
                    binary_form=True
                )

                if certificate_der:
                    try:
                        decoded_context = ssl.create_default_context(
                            cafile=certifi.where()
                        )

                        # Use private decoder only when available.
                        # It is not used for trust validation.
                        from cryptography import x509

                        parsed_certificate = x509.load_der_x509_certificate(
                            certificate_der
                        )

                        subject = {}
                        issuer = {}

                        for attribute in parsed_certificate.subject:
                            subject[
                                attribute.oid._name
                            ] = attribute.value

                        for attribute in parsed_certificate.issuer:
                            issuer[
                                attribute.oid._name
                            ] = attribute.value

                        not_after = parsed_certificate.not_valid_after_utc
                        not_before = parsed_certificate.not_valid_before_utc

                        certificate = {
                            "subject": [
                                ("commonName", subject.get("common_name", "Unknown"))
                            ],
                            "issuer": [
                                (
                                    "organizationName",
                                    issuer.get("organization_name", "Unknown")
                                )
                            ],
                            "notAfter": not_after.strftime(
                                "%b %d %H:%M:%S %Y GMT"
                            ),
                            "notBefore": not_before.strftime(
                                "%b %d %H:%M:%S %Y GMT"
                            )
                        }

                    except Exception:
                        certificate = {}

            tls_version = secure_sock.version() or "Unknown"

            cipher_info = secure_sock.cipher()

            cipher_name = (
                cipher_info[0]
                if cipher_info
                else "Unknown"
            )

            return {
                "certificate": certificate,
                "tls_version": tls_version,
                "cipher": cipher_name
            }


# ============================================================
# CERTIFICATE TRUST VALIDATION
# ============================================================

def verify_certificate(hostname):
    """
    Performs the actual certificate trust + hostname validation.

    This function is intentionally separate from certificate
    inspection so a local CA problem does not prevent inspection.
    """

    context = ssl.create_default_context(
        cafile=certifi.where()
    )

    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection(
            (hostname, 443),
            timeout=10
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as secure_sock:

                return {
                    "trusted": True,
                    "hostname_valid": True,
                    "verification_error": None
                }

    except ssl.CertificateError as error:
        return {
            "trusted": False,
            "hostname_valid": False,
            "verification_error": str(error),
            "verification_type": "hostname"
        }

    except ssl.SSLCertVerificationError as error:
        return {
            "trusted": False,
            "hostname_valid": True,
            "verification_error": str(error),
            "verification_type": "trust"
        }

    except ssl.SSLError as error:
        return {
            "trusted": False,
            "hostname_valid": True,
            "verification_error": str(error),
            "verification_type": "ssl"
        }

    except Exception as error:
        return {
            "trusted": False,
            "hostname_valid": True,
            "verification_error": str(error),
            "verification_type": "connection"
        }


# ============================================================
# MAIN SSL CHECK
# ============================================================

def get_ssl_details(hostname):
    """
    Backward-compatible helper.

    Returns the inspected certificate/TLS information.
    Trust validation is handled separately.
    """

    inspected = inspect_certificate(hostname)

    certificate = inspected["certificate"]
    tls_version = inspected["tls_version"]
    cipher = inspected["cipher"]

    return certificate, tls_version, cipher


def run_ssl_check(target):
    target = normalize_ssl_target(target)

    if not target:
        return {
            "target": target,
            "ssl_valid": False,
            "certificate_trusted": False,
            "hostname_valid": False,
            "tls_connected": False,
            "risk": "Critical",
            "error": "A valid SSL/TLS target is required."
        }

    result = {
        "target": target,
        "ssl_valid": False,
        "certificate_trusted": False,
        "hostname_valid": None,
        "tls_connected": False,
        "issuer": "Unknown",
        "issued_to": "Unknown",
        "tls_version": "Unknown",
        "cipher": "Unknown",
        "hash_algorithm": "Unknown",
        "expiry_date": "N/A",
        "days_remaining": None,
        "risk": "Critical",
        "error": None,
        "verification_error": None,
        "verification_type": None,
        "trust_status": "unknown"
    }

    # --------------------------------------------------------
    # Step 1: Inspect TLS/certificate even if verification fails
    # --------------------------------------------------------

    try:
        certificate, tls_version, cipher = get_ssl_details(target)

        result["tls_connected"] = True
        result["tls_version"] = tls_version or "Unknown"
        result["cipher"] = cipher or "Unknown"
        result["hash_algorithm"] = extract_hash_algorithm(
            result["cipher"]
        )

        issuer = _extract_certificate_field(
            certificate,
            "issuer"
        )

        subject = _extract_certificate_field(
            certificate,
            "subject"
        )

        result["issuer"] = (
            issuer.get("organizationName")
            or issuer.get("commonName")
            or "Unknown"
        )

        result["issued_to"] = (
            subject.get("commonName")
            or "Unknown"
        )

        expiry_date = _parse_expiry(certificate)

        if expiry_date:
            result["expiry_date"] = expiry_date.strftime(
                "%d %B %Y"
            )

            result["days_remaining"] = (
                expiry_date - datetime.utcnow()
            ).days

    except Exception as error:
        result["error"] = str(error)

        return result

    # --------------------------------------------------------
    # Step 2: Perform actual certificate trust validation
    # --------------------------------------------------------

    verification = verify_certificate(target)

    result["certificate_trusted"] = verification.get(
        "trusted",
        False
    )

    result["hostname_valid"] = verification.get(
        "hostname_valid"
    )

    result["verification_error"] = verification.get(
        "verification_error"
    )

    result["verification_type"] = verification.get(
        "verification_type"
    )

    # --------------------------------------------------------
    # Step 3: Classify verification result
    # --------------------------------------------------------

    if result["certificate_trusted"]:
        result["ssl_valid"] = True
        result["trust_status"] = "trusted"

    else:
        verification_error = str(
            result["verification_error"] or ""
        ).lower()

        if (
            "unable to get local issuer certificate" in verification_error
            or "unable to verify the first certificate" in verification_error
            or "self signed certificate in certificate chain" in verification_error
        ):
            result["trust_status"] = "local_trust_store_error"

        elif (
            "hostname" in verification_error
            or "doesn't match" in verification_error
            or "does not match" in verification_error
        ):
            result["trust_status"] = "hostname_mismatch"
            result["hostname_valid"] = False

        elif "expired" in verification_error:
            result["trust_status"] = "expired_certificate"

        else:
            result["trust_status"] = "untrusted_certificate"

    # --------------------------------------------------------
    # Step 4: Determine actual certificate validity
    # --------------------------------------------------------

    certificate_is_expired = (
        result["days_remaining"] is not None
        and result["days_remaining"] < 0
    )

    hostname_problem = (
        result["hostname_valid"] is False
    )

    # A local CA store problem is NOT equivalent to an invalid
    # certificate when the TLS handshake itself succeeded.
    #
    # The certificate is still marked as not trusted by the local
    # verification environment, but ssl_valid represents the
    # certificate/TLS security state rather than hiding all data
    # behind the verification exception.
    if (
        result["tls_connected"]
        and not certificate_is_expired
        and not hostname_problem
        and result["trust_status"] == "local_trust_store_error"
    ):
        result["ssl_valid"] = True

    elif (
        result["tls_connected"]
        and not certificate_is_expired
        and not hostname_problem
        and result["certificate_trusted"]
    ):
        result["ssl_valid"] = True

    else:
        result["ssl_valid"] = False

    # --------------------------------------------------------
    # Step 5: Risk
    # --------------------------------------------------------

    result["risk"] = calculate_ssl_risk(
        ssl_valid=result["ssl_valid"],
        tls_version=result["tls_version"],
        days_remaining=result["days_remaining"],
        trust_status=result["trust_status"],
        hostname_valid=result["hostname_valid"]
    )

    # --------------------------------------------------------
    # Step 6: Preserve useful error information
    # --------------------------------------------------------

    if result["verification_error"]:
        result["error"] = result["verification_error"]

    return result


# ============================================================
# CONTACT DISCOVERY
# ============================================================

def extract_clean_domain(target):
    if not target:
        return ""

    d = str(target).strip()

    if "://" in d:
        parsed = urllib.parse.urlparse(d)
        d = parsed.netloc or parsed.path

    d = d.split("/")[0]

    if d.count(":") == 1:
        d = d.split(":")[0]

    d = d.strip()

    if d.startswith("www."):
        d = d[4:]

    return d.lower()


def discover_contact_email(target):
    """
    Identifies the official security or technical contact email.

    Priority:
    1. RFC 9116 security.txt
    2. Official security/vulnerability page
    3. Official contact page
    4. RDAP
    5. Explicit fallback
    """

    base_domain = extract_clean_domain(target)

    if not base_domain:
        return {
            "email": "security@unknown-target.local",
            "is_fallback": True,
            "contact_type": "Fallback Contact",
            "source": "Fallback Contact",
            "source_url": None,
            "reason": "No verified security contact was found."
        }

    headers = {
        "User-Agent": "SURAKSHA-Security-Scanner/1.0"
    }

    security_txt_urls = [
        f"https://{base_domain}/.well-known/security.txt",
        f"https://{base_domain}/security.txt",
        f"https://www.{base_domain}/.well-known/security.txt"
    ]

    for url in security_txt_urls:
        try:
            response = requests.get(
                url,
                timeout=3,
                verify=True,
                headers=headers
            )

            if response.status_code != 200:
                continue

            if not response.text:
                continue

            content_type = response.headers.get(
                "Content-Type",
                ""
            ).lower()

            if (
                "text/html" in content_type
                or response.text.strip().startswith("<")
            ):
                continue

            for line in response.text.splitlines():
                line = line.strip()

                if not line.lower().startswith("contact:"):
                    continue

                match = re.search(
                    r"mailto:([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
                    line,
                    re.IGNORECASE
                )

                if not match:
                    match = re.search(
                        r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
                        line
                    )

                if match:
                    found_email = match.group(1).strip()

                    return {
                        "email": found_email,
                        "is_fallback": False,
                        "contact_type": "Official Published Contact",
                        "source": url,
                        "source_url": url,
                        "reason": (
                            "Discovered from official RFC 9116 "
                            f"security.txt at {url}"
                        )
                    }

        except Exception:
            continue

    web_pages = [
        f"https://{base_domain}/security",
        f"https://{base_domain}/vulnerability-disclosure",
        f"https://{base_domain}/vulnerability-disclosure-policy",
        f"https://{base_domain}/contact",
        f"https://{base_domain}/contact-us"
    ]

    for url in web_pages:
        try:
            response = requests.get(
                url,
                timeout=3,
                verify=True,
                headers=headers
            )

            if response.status_code != 200:
                continue

            if not response.text:
                continue

            security_match = re.search(
                r"mailto:(security@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
                response.text,
                re.IGNORECASE
            )

            if security_match:
                return {
                    "email": security_match.group(1).strip(),
                    "is_fallback": False,
                    "contact_type": "Official Website Contact",
                    "source": url,
                    "source_url": url,
                    "reason": (
                        f"Discovered on official website page at {url}"
                    )
                }

            domain_pattern = (
                r"mailto:([a-zA-Z0-9._%+-]+@"
                + re.escape(base_domain)
                + r")"
            )

            domain_match = re.search(
                domain_pattern,
                response.text,
                re.IGNORECASE
            )

            if domain_match:
                return {
                    "email": domain_match.group(1).strip(),
                    "is_fallback": False,
                    "contact_type": "Official Website Contact",
                    "source": url,
                    "source_url": url,
                    "reason": (
                        f"Discovered on official website page at {url}"
                    )
                }

        except Exception:
            continue

    try:
        rdap_url = f"https://www.rdap.net/domain/{base_domain}"

        response = requests.get(
            rdap_url,
            timeout=3,
            headers=headers
        )

        if response.status_code == 200:
            rdap_data = response.json()

            for entity in rdap_data.get("entities", []):
                vcard_array = entity.get(
                    "vcardArray",
                    []
                )

                if len(vcard_array) <= 1:
                    continue

                for item in vcard_array[1]:
                    if (
                        item
                        and len(item) > 3
                        and item[0] == "email"
                    ):
                        potential_email = str(
                            item[3]
                        ).strip()

                        if (
                            "@" in potential_email
                            and "." in potential_email
                            and not any(
                                p in potential_email.lower()
                                for p in [
                                    "whoisproxy",
                                    "privacy",
                                    "anonym",
                                    "contactprivacy"
                                ]
                            )
                        ):
                            return {
                                "email": potential_email,
                                "is_fallback": False,
                                "contact_type": "RDAP Contact",
                                "source": rdap_url,
                                "source_url": rdap_url,
                                "reason": (
                                    "Discovered from RDAP "
                                    "domain registry contact"
                                )
                            }

    except Exception:
        pass

    fallback_email = f"security@{base_domain}"

    return {
        "email": fallback_email,
        "is_fallback": True,
        "contact_type": "Fallback Contact",
        "source": "Fallback Contact",
        "source_url": None,
        "reason": (
            "No verified security contact was found "
            "on the official website."
        )
    }


# ============================================================
# SSL REPORT EMAIL
# ============================================================

def build_ssl_report_email(scan_result, user):
    if not scan_result:
        scan_result = {}

    target = scan_result.get("target") or "target-host"

    clean_target = extract_clean_domain(target)

    sender_email = ""
    sender_name = "Security Analyst"

    if user:
        sender_email = getattr(
            user,
            "email",
            None
        )

        sender_name = getattr(
            user,
            "username",
            None
        ) or sender_name

    if not sender_email:
        sender_email = "analyst@suraksha.local"

    recipient_info = discover_contact_email(target)

    recipient_email = recipient_info["email"]
    is_fallback = recipient_info["is_fallback"]

    contact_type = recipient_info.get(
        "contact_type",
        "Fallback Contact"
    )

    source_url = recipient_info.get(
        "source_url"
    )

    reason = recipient_info.get(
        "reason",
        "No verified security contact was found."
    )

    ssl_valid = scan_result.get(
        "ssl_valid",
        False
    )

    error = scan_result.get("error")

    tls_version = (
        scan_result.get("tls_version")
        or "Unknown"
    )

    cipher = (
        scan_result.get("cipher")
        or "Unknown"
    )

    hash_algorithm = (
        scan_result.get("hash_algorithm")
        or extract_hash_algorithm(cipher)
    )

    expiry_date = (
        scan_result.get("expiry_date")
        or "N/A"
    )

    days_remaining = scan_result.get(
        "days_remaining"
    )

    severity = (
        scan_result.get("risk")
        or "Medium"
    )

    detected_issues = []

    if days_remaining is not None:
        try:
            days_int = int(days_remaining)

            if days_int < 0:
                detected_issues.append(
                    f"Expired SSL/TLS Certificate "
                    f"({abs(days_int)} days beyond expiry)"
                )

            elif days_int <= 30:
                detected_issues.append(
                    f"Certificate Nearing Expiry "
                    f"({days_int} days remaining)"
                )

        except (ValueError, TypeError):
            pass

    if not ssl_valid:
        error_text = str(
            error or
            "SSL/TLS security validation failed"
        )

        if "hostname" in error_text.lower():
            detected_issues.append(
                f"Certificate Hostname Mismatch "
                f"({error_text})"
            )

        elif "expired" in error_text.lower():
            detected_issues.append(
                "Expired SSL/TLS Certificate"
            )

        elif "self-signed" in error_text.lower():
            detected_issues.append(
                "Self-Signed / Untrusted Certificate"
            )

        elif not detected_issues:
            detected_issues.append(
                f"SSL/TLS Validation Issue ({error_text})"
            )

    elif (
        scan_result.get("trust_status")
        == "local_trust_store_error"
    ):
        detected_issues.append(
            "Local certificate trust-store verification "
            "could not be completed. Certificate details "
            "were inspected separately."
        )

    weak_tls = [
        "TLSv1",
        "TLSv1.1",
        "SSLv2",
        "SSLv3"
    ]

    if tls_version in weak_tls:
        detected_issues.append(
            f"Deprecated Insecure Protocol Enabled "
            f"({tls_version})"
        )

    weak_cipher_keywords = [
        "RC4",
        "3DES",
        "DES",
        "MD5",
        "NULL",
        "EXPORT"
    ]

    if any(
        keyword in cipher.upper()
        for keyword in weak_cipher_keywords
    ):
        detected_issues.append(
            f"Weak Cipher Suite Negotiated ({cipher})"
        )

    if not detected_issues:
        detected_issues.append(
            f"SSL/TLS Security Posture "
            f"Evaluated as {severity}"
        )

    detected_issue_text = "\n".join(
        f"- {issue}"
        for issue in detected_issues
    )

    if (
        ssl_valid
        and severity.lower() == "low"
    ):
        ssl_status_text = "Valid"

    elif days_remaining is not None and days_remaining < 0:
        ssl_status_text = "Expired / Invalid"

    elif (
        scan_result.get("trust_status")
        == "local_trust_store_error"
    ):
        ssl_status_text = (
            "TLS Available / Local Trust Verification Issue"
        )

    elif not ssl_valid:
        ssl_status_text = "Invalid / At Risk"

    else:
        ssl_status_text = "At Risk"

    current_date = datetime.now().strftime(
        "%d %B %Y"
    )

    subject = (
        f"SURAKSHA SSL/TLS Security Advisory - "
        f"{clean_target or target}"
    )

    body = f"""Dear Security Team,

SURAKSHA – An Intelligent Vulnerability Scanner has completed an SSL/TLS security assessment for your domain.

Target:
{clean_target or target}

SSL/TLS Status:
{ssl_status_text}

Risk Level:
{severity}

Certificate Trusted:
{"Yes" if scan_result.get("certificate_trusted") else "No"}

Trust Status:
{scan_result.get("trust_status", "Unknown")}

Issuer:
{scan_result.get("issuer", "N/A")}

Issued To:
{scan_result.get("issued_to", "N/A")}

TLS Version:
{tls_version}

Cipher:
{cipher}

Hash Algorithm:
{hash_algorithm}

Expiry Date:
{expiry_date}

Days Remaining:
{str(days_remaining) + " Days" if days_remaining is not None else "N/A"}

Detected Issues:
{detected_issue_text}

Recommendation:
Review the certificate chain, hostname configuration, certificate expiry,
TLS protocol configuration, and cipher configuration according to the
identified finding.

This security advisory was generated by SURAKSHA during an authorized
security assessment.

Regards,

{sender_name}
Cybersecurity Analyst
{current_date}
"""

    return {
        "sender": sender_email,
        "sender_name": sender_name,
        "recipient": recipient_email,
        "is_fallback": is_fallback,
        "contact_type": contact_type,
        "source": recipient_info.get(
            "source",
            "Fallback Contact"
        ),
        "source_url": source_url,
        "reason": reason,
        "recipient_source": contact_type,
        "subject": subject,
        "body": body,
        "target": clean_target or target,
        "risk": severity,
        "date": current_date
    }