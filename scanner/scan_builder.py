def build_scan_arguments(options):
    """
    Build a clean, deduplicated Nmap argument string from the selected scan options.
    
    Intensity hierarchy for version detection:
        banner   → -sV                (default intensity)
        service  → -sV --version-light (intensity 2)
        version  → -sV --version-all   (intensity 9, overrides --version-light)
    
    Only the highest requested intensity is emitted. -sV is never duplicated.
    """

    args = ["-Pn", "-T3", "--host-timeout", "60s", "--max-retries", "2"]

    # ---------------- SYN Scan (always) ----------------
    args.append("-sS")

    # ---------------- Version Detection ----------------
    # Determine the highest version-detection intensity requested.
    # banner → needs -sV (default intensity)
    # service → needs -sV --version-light
    # version → needs -sV --version-all  (overrides --version-light)

    needs_sv = False
    version_intensity = None  # None | "light" | "all"

    if "banner" in options:
        needs_sv = True

    if "service" in options:
        needs_sv = True
        version_intensity = "light"

    if "version" in options:
        needs_sv = True
        version_intensity = "all"  # overrides "light"

    if needs_sv:
        args.append("-sV")
        if version_intensity == "all":
            args.append("--version-all")
        elif version_intensity == "light":
            args.append("--version-light")

    # ---------------- OS Detection ----------------
    if "os" in options:
        args.extend(["-O", "--osscan-limit"])

    # ---------------- Vulnerability Scripts ----------------
    if "vuln" in options:
        args.extend(["--script=vuln", "--script-timeout", "15s"])

    # ---------------- Port Range ----------------
    if "full" in options:
        args.append("-p-")
    elif "port" in options:
        args.extend(["--top-ports", "5000"])
    else:
        args.extend(["--top-ports", "1000"])

    return " ".join(args)