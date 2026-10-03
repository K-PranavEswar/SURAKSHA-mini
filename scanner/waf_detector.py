import requests
WAF_SIGNATURES = {"Cloudflare": ["cloudflare", "__cfduid"], "AWS WAF": ["awselb", "x-amzn"], "Sucuri": ["sucuri"], "Imperva": ["incap_ses", "_incap_"], "Akamai": ["akamai"]}

def detect_waf(url):
    try:
        response = requests.get(url, timeout=8, verify=False)
        headers = str(response.headers).lower()
        cookies = str(response.cookies).lower()

        for waf, signs in WAF_SIGNATURES.items():
            if any(sign.lower() in headers + cookies for sign in signs):
                return {"detected": True, "waf": waf}

        return {"detected": False, "waf": "None"}

    except:
        return {"detected": False, "waf": "Unknown"}