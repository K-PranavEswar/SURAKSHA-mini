import logging
import re
from typing import List, Dict, Any, Union

import requests
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

MIN_CONFIDENCE = 60

TECH_SIGNATURES = {
    "React": {
        "category": "Frontend",
        "script_patterns": [
            (r"react(?:-dom)?\.production\.min\.js", 90),
            (r"react(?:-dom)?\.development\.js", 90),
            (r"react-dom", 80),
        ],
        "html_attributes": [
            (r"data-reactroot", 95),
            (r"data-reactid", 95)
        ]
    },
    "Next.js": {
        "category": "Frontend",
        "headers": [
            (r"x-nextjs-cache", 90)
        ],
        "script_patterns": [
            (r"_next/static", 95)
        ],
        "html_patterns": [
            (r"id=\"__next\"", 95)
        ]
    },
    "Vue.js": {
        "category": "Frontend",
        "script_patterns": [
            (r"vue(?:[\.-]runtime)?(?:[\.-]global)?(?:[\.-]esm)?(?:\.min)?\.js", 85)
        ],
        "html_attributes": [
            (r"data-v-[a-zA-Z0-9]+", 70)
        ]
    },
    "Nuxt.js": {
        "category": "Frontend",
        "html_patterns": [
            (r"id=\"__nuxt\"", 95)
        ],
        "script_patterns": [
            (r"_nuxt/", 95)
        ]
    },
    "Angular": {
        "category": "Frontend",
        "html_attributes": [
            (r"ng-version=\"([\d\.]+)\"", 95, True) 
        ]
    },
    "Svelte": {
        "category": "Frontend",
        "html_attributes": [
            (r"data-svelte", 95)
        ]
    },
    "jQuery": {
        "category": "JavaScript Library",
        "script_patterns": [
            (r"jquery(?:-([\d\.]+))?(?:\.min)?\.js", 90, True)
        ]
    },
    "Bootstrap": {
        "category": "CSS Framework",
        "stylesheet_patterns": [
            (r"bootstrap(?:-([\d\.]+))?(?:\.min)?\.css", 85, True)
        ],
        "script_patterns": [
            (r"bootstrap(?:-([\d\.]+))?(?:\.bundle)?(?:\.min)?\.js", 85, True)
        ]
    },
    "Tailwind CSS": {
        "category": "CSS Framework",
        "stylesheet_patterns": [
            (r"tailwind(?:css)?(?:@[\d\.]+)?(?:/dist)?/tailwind(?:\.min)?\.css", 85)
        ]
    },
    "Laravel": {
        "category": "Backend",
        "cookies": [
            (r"laravel_session", 90)
        ]
    },
    "Django": {
        "category": "Backend",
        "cookies": [
            (r"csrftoken", 80)
        ],
        "html_patterns": [
            (r"name=\"csrfmiddlewaretoken\"", 85)
        ]
    },
    "Flask": {
        "category": "Backend",
        "cookies": [
            (r"session", 30)
        ]
    },
    "Express.js": {
        "category": "Backend",
        "headers": [
            (r"X-Powered-By:\s*Express", 90)
        ]
    },
    "Node.js": {
        "category": "Backend",
        "headers": [
            (r"X-Powered-By:\s*Node\.js", 90)
        ]
    },
    "Spring": {
        "category": "Backend",
        "headers": [
            (r"X-Application-Context", 80)
        ]
    },
    "ASP.NET": {
        "category": "Backend",
        "headers": [
            (r"X-AspNet-Version", 95),
            (r"X-Powered-By:\s*ASP\.NET", 90)
        ],
        "cookies": [
            (r"ASP\.NET_SessionId", 90)
        ],
        "html_patterns": [
            (r"__VIEWSTATE", 90)
        ]
    },
    "Ruby on Rails": {
        "category": "Backend",
        "headers": [
            (r"X-Rack-Cache", 70),
            (r"X-Powered-By:\s*Phusion Passenger", 80)
        ],
        "cookies": [
            (r"_session_id", 60)
        ],
        "meta": [
            (r"name=\"csrf-param\"\s+content=\"authenticity_token\"", 90)
        ]
    },
    "PHP": {
        "category": "Backend",
        "headers": [
            (r"X-Powered-By:\s*PHP/?([\d\.]+)?", 90, True)
        ],
        "cookies": [
            (r"PHPSESSID", 90)
        ]
    },
    "WordPress": {
        "category": "CMS",
        "meta": [
            (r"name=\"generator\"\s+content=\"WordPress(?: ([\d\.]+))?\"", 98, True)
        ],
        "script_patterns": [
            (r"wp-includes/js", 90),
            (r"wp-content/themes", 90),
            (r"wp-content/plugins", 90)
        ],
        "stylesheet_patterns": [
            (r"wp-includes/css", 90),
            (r"wp-content/themes", 90)
        ],
        "html_patterns": [
            (r"wp-json", 80)
        ]
    },
    "Drupal": {
        "category": "CMS",
        "headers": [
            (r"X-Generator:\s*Drupal(?: ([\d\.]+))?", 90, True)
        ],
        "meta": [
            (r"name=\"Generator\"\s+content=\"Drupal(?: ([\d\.]+))?", 90, True)
        ],
        "script_patterns": [
            (r"sites/all/modules", 85)
        ]
    },
    "Joomla": {
        "category": "CMS",
        "meta": [
            (r"name=\"generator\"\s+content=\"Joomla", 95)
        ]
    },
    "Google Analytics": {
        "category": "Analytics",
        "script_patterns": [
            (r"google-analytics\.com/analytics\.js", 95),
            (r"googletagmanager\.com/gtag/js", 90)
        ]
    },
    "Google Tag Manager": {
        "category": "Analytics",
        "script_patterns": [
            (r"googletagmanager\.com/gtm\.js", 95)
        ]
    },
    "Facebook Pixel": {
        "category": "Analytics",
        "script_patterns": [
            (r"connect\.facebook\.net/en_US/fbevents\.js", 95)
        ]
    }
}

SERVER_SIGNATURES = [
    (r"nginx/?([\d\.]+)?", "Nginx"),
    (r"Apache/?([\d\.]+)?", "Apache"),
    (r"Microsoft-IIS/?([\d\.]+)?", "Microsoft IIS"),
    (r"LiteSpeed", "LiteSpeed")
]

CDN_WAF_SIGNATURES = {
    "Cloudflare": {
        "category": "CDN/WAF",
        "headers": [(r"Server:\s*cloudflare", 98), (r"CF-Ray:\s*", 98)]
    },
    "AWS CloudFront": {
        "category": "CDN/WAF",
        "headers": [(r"X-Amz-Cf-Id:\s*", 98), (r"Via:\s*.*cloudfront\.net", 98)]
    },
    "AWS WAF": {
        "category": "CDN/WAF",
        "headers": [(r"x-amzn-", 98)],
        "cookies": [(r"awselb", 98)]
    },
    "Sucuri": {
        "category": "CDN/WAF",
        "headers": [(r"Server:\s*Sucuri", 98), (r"X-Sucuri", 98)]
    },
    "Imperva": {
        "category": "CDN/WAF",
        "cookies": [(r"incap_ses", 98), (r"_incap_", 98)]
    },
    "Akamai": {
        "category": "CDN/WAF",
        "headers": [(r"Akamai", 98)]
    }
}

class TechDetector:
    def __init__(self, url: str, timeout: int = 10, verify_ssl: bool = True):
        self.url = url
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 SURAKSHA/1.0"
        })
        self.results = {}

    def _analyze_evidence(self, tech_name: str, category: str, pattern_tuple: tuple, source_text: str, evidence_msg: str):
        pattern = pattern_tuple[0]
        confidence = pattern_tuple[1]
        has_version = len(pattern_tuple) > 2 and pattern_tuple[2]

        match = re.search(pattern, source_text, re.IGNORECASE)
        if match:
            version = "Unknown"
            if has_version and match.groups():
                version = match.group(1) or "Unknown"

            if tech_name not in self.results:
                self.results[tech_name] = {
                    "name": tech_name,
                    "version": version,
                    "category": category,
                    "confidence": confidence,
                    "evidence": set()
                }
            else:
                self.results[tech_name]["confidence"] = min(100, self.results[tech_name]["confidence"] + confidence // 2)
                if version != "Unknown" and self.results[tech_name]["version"] == "Unknown":
                    self.results[tech_name]["version"] = version

            self.results[tech_name]["evidence"].add(evidence_msg)

    def detect(self) -> List[Dict[str, Any]]:
        try:
            logger.info(f"[TECH] Scanning: {self.url}")
            response = self.session.get(self.url, timeout=self.timeout, verify=self.verify_ssl, allow_redirects=True)
            logger.info(f"[TECH] Final URL: {response.url}")
            
            headers_str = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
            for tech, config in {**TECH_SIGNATURES, **CDN_WAF_SIGNATURES}.items():
                category = config.get("category", "Unknown")
                for pat in config.get("headers", []):
                    self._analyze_evidence(tech, category, pat, headers_str, f"Header match for '{pat[0]}'")

            server_header = response.headers.get("Server", "")
            if server_header:
                for pattern, name in SERVER_SIGNATURES:
                    match = re.search(pattern, server_header, re.IGNORECASE)
                    if match:
                        version = "Unknown"
                        if match.groups() and match.group(1):
                            version = match.group(1)
                        if name not in self.results:
                            self.results[name] = {
                                "name": name,
                                "version": version,
                                "category": "Web Server",
                                "confidence": 95,
                                "evidence": set([f"Server header: {server_header}"])
                            }

            cookies_str = "; ".join(response.cookies.keys())
            for tech, config in {**TECH_SIGNATURES, **CDN_WAF_SIGNATURES}.items():
                category = config.get("category", "Unknown")
                for pat in config.get("cookies", []):
                    self._analyze_evidence(tech, category, pat, cookies_str, f"Cookie detected: '{pat[0]}'")
            
            html_content = response.text
            soup = BeautifulSoup(html_content, "html.parser")

            meta_str = "\n".join([str(meta) for meta in soup.find_all("meta")])
            for tech, config in TECH_SIGNATURES.items():
                category = config.get("category", "Unknown")
                for pat in config.get("meta", []):
                    self._analyze_evidence(tech, category, pat, meta_str, f"Meta tag match: '{pat[0]}'")

            for script in soup.find_all("script"):
                src = script.get("src", "")
                if src:
                    for tech, config in TECH_SIGNATURES.items():
                        category = config.get("category", "Unknown")
                        for pat in config.get("script_patterns", []):
                            self._analyze_evidence(tech, category, pat, src, f"Script URL match: '{pat[0]}'")

            for link in soup.find_all("link", rel="stylesheet"):
                href = link.get("href", "")
                if href:
                    for tech, config in TECH_SIGNATURES.items():
                        category = config.get("category", "Unknown")
                        for pat in config.get("stylesheet_patterns", []):
                            self._analyze_evidence(tech, category, pat, href, f"Stylesheet URL match: '{pat[0]}'")

            for tech, config in TECH_SIGNATURES.items():
                category = config.get("category", "Unknown")
                for pat in config.get("html_patterns", []):
                    self._analyze_evidence(tech, category, pat, html_content, f"HTML structure match: '{pat[0]}'")
                for pat in config.get("html_attributes", []):
                    self._analyze_evidence(tech, category, pat, html_content, f"HTML attribute match: '{pat[0]}'")

            final_results = []
            for tech, data in self.results.items():
                if data["confidence"] >= MIN_CONFIDENCE:
                    data["evidence"] = list(data["evidence"])
                    final_results.append(data)
                    logger.info(f"[TECH] {tech} detected - {data['confidence']}%")

            logger.info("[TECH] Detection completed")
            return final_results
            
        except requests.exceptions.Timeout:
            logger.error("[TECH] Request Timeout")
            return [{"error": "Timeout"}]
        except requests.exceptions.ConnectionError:
            logger.error("[TECH] Connection Error")
            return [{"error": "ConnectionError"}]
        except requests.exceptions.TooManyRedirects:
            logger.error("[TECH] Too Many Redirects")
            return [{"error": "TooManyRedirects"}]
        except requests.exceptions.SSLError:
            logger.error("[TECH] SSL Error")
            return [{"error": "SSLError"}]
        except requests.exceptions.RequestException as e:
            logger.error(f"[TECH] Request Exception: {e}")
            return [{"error": "RequestException"}]

def detect_technology(url: str, timeout: int = 10, verify_ssl: bool = True, detailed: bool = False) -> Union[List[str], List[Dict[str, Any]]]:
    detector = TechDetector(url, timeout, verify_ssl)
    results = detector.detect()
    
    if results and "error" in results[0]:
        if detailed:
            return []
        return ["Detection Failed"]
        
    if detailed:
        return results
    
    names = [r["name"] for r in results]
    return names if names else []

if __name__ == "__main__":
    import sys
    import json
    if len(sys.argv) > 1:
        print(json.dumps(detect_technology(sys.argv[1], detailed=True), indent=2))