import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
WEB_PORTS = [80, 81, 443, 8000, 8080, 8443, 8888]
def detect_web_service(host, port):
    if port not in WEB_PORTS:
        return None
    urls = []
    if port == 80:
        urls.append(f"http://{host}")

    elif port == 443:
        urls.append(f"https://{host}")

    else:
        urls.append(f"http://{host}:{port}")
        urls.append(f"https://{host}:{port}")
    for url in urls:
        try:
            r = requests.get(url,timeout=3,verify=False,allow_redirects=True)
            title = "Unknown"
            if "<title>" in r.text.lower():
                try:
                    title = (r.text.split("<title>")[1].split("</title>")[0].strip())
                except:
                    pass
            return {"found": True,"url": r.url,"status": r.status_code,"title": title}
        except:
            pass
    return {"found": False}