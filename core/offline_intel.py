import re
import math
import ipaddress
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse


HIGH_RISK_TLDS = [
    "zip", "top", "xyz", "cc", "tk", "ml", "ga", "cf", "gq", "link",
    "webcam", "download", "stream", "racing", "review", "country", "kim",
    "work", "party", "click", "loan", "win", "men", "mom", "bid", "trade",
    "date", "accountant", "science", "gdn", "loan", "racing", "faith",
]

SUSPICIOUS_TLDS = [
    "info", "biz", "icu", "live", "site", "online", "tech", "fun",
    "rest", "cyou", "top", "vip", "pro", "one", "today",
]

KNOWN_CVES = {
    "CVE-2021-44228": {
        "name": "Log4Shell",
        "vendor": "Apache Log4j",
        "description": "Remote code execution in Apache Log4j 2 via JNDI lookups in log messages.",
        "cisa_kev": True,
        "base_score": 10.0,
        "severity": "Critical",
        "mitre": ["T1105", "T1059"],
        "year": 2021,
    },
    "CVE-2023-34362": {
        "name": "MOVEit Transfer SQL Injection",
        "vendor": "Progress Software",
        "description": "SQL injection in MOVEit Transfer enabling remote code execution and data theft.",
        "cisa_kev": True,
        "base_score": 9.8,
        "severity": "Critical",
        "mitre": ["T1190"],
        "year": 2023,
    },
    "CVE-2023-48788": {
        "name": "Fortinet FortiClient EMS SQL Injection",
        "vendor": "Fortinet",
        "description": "SQL injection vulnerability in FortiClient EMS allowing code execution.",
        "cisa_kev": True,
        "base_score": 9.8,
        "severity": "Critical",
        "mitre": ["T1190"],
        "year": 2023,
    },
    "CVE-2024-21762": {
        "name": "FortiOS / FortiProxy Out-of-Bound Write",
        "vendor": "Fortinet",
        "description": "Out-of-bounds write in FortiOS/FortiProxy SSL VPN enabling remote code execution.",
        "cisa_kev": True,
        "base_score": 9.6,
        "severity": "Critical",
        "mitre": ["T1190", "T1105"],
        "year": 2024,
    },
    "CVE-2023-27350": {
        "name": "PaperCut MF / NG RCE",
        "vendor": "PaperCut",
        "description": "Authentication bypass leading to remote code execution in PaperCut MF/NG.",
        "cisa_kev": True,
        "base_score": 9.8,
        "severity": "Critical",
        "mitre": ["T1190"],
        "year": 2023,
    },
    "CVE-2023-0669": {
        "name": "Fortinet FortiGate RCE",
        "vendor": "Fortinet",
        "description": "Remote code execution in FortiGate SSL VPN via crafted HTTP requests.",
        "cisa_kev": True,
        "base_score": 9.8,
        "severity": "Critical",
        "mitre": ["T1190", "T1059"],
        "year": 2023,
    },
    "CVE-2021-34527": {
        "name": "PrintNightmare",
        "vendor": "Microsoft",
        "description": "Windows Print Spooler remote code execution vulnerability.",
        "cisa_kev": True,
        "base_score": 8.8,
        "severity": "High",
        "mitre": ["T1212"],
        "year": 2021,
    },
    "CVE-2023-27351": {
        "name": "PaperCut MF / NG Authenticated RCE",
        "vendor": "PaperCut",
        "description": "Second authentication bypass path in PaperCut MF/NG enabling RCE.",
        "cisa_kev": True,
        "base_score": 9.8,
        "severity": "Critical",
        "mitre": ["T1190"],
        "year": 2023,
    },
    "CVE-2022-26134": {
        "name": "Atlassian Confluence OGNL Injection",
        "vendor": "Atlassian",
        "description": "Unauthenticated OGNL injection in Confluence leading to RCE.",
        "cisa_kev": True,
        "base_score": 9.8,
        "severity": "Critical",
        "mitre": ["T1190", "T1059"],
        "year": 2022,
    },
    "CVE-2023-44487": {
        "name": "HTTP/2 Rapid Reset",
        "vendor": "Multiple",
        "description": "HTTP/2 stream reset amplification enabling DDoS attacks.",
        "cisa_kev": True,
        "base_score": 7.5,
        "severity": "High",
        "mitre": ["T1498"],
        "year": 2023,
    },
    "CVE-2021-26086": {
        "name": "Atlassian Confluence LFI",
        "vendor": "Atlassian",
        "description": "Local file inclusion vulnerability in Atlassian Confluence.",
        "cisa_kev": True,
        "base_score": 6.1,
        "severity": "Medium",
        "mitre": ["T1552"],
        "year": 2021,
    },
    "CVE-2023-20198": {
        "name": "Cisco IOS XE Web UI Privilege Escalation",
        "vendor": "Cisco",
        "description": "Privilege escalation in Cisco IOS XE Web UI enabling full device compromise.",
        "cisa_kev": True,
        "base_score": 10.0,
        "severity": "Critical",
        "mitre": ["T1190", "T1078"],
        "year": 2023,
    },
    "CVE-2022-22954": {
        "name": "VMware Workspace ONE SSTI",
        "vendor": "VMware",
        "description": "Server-side template injection in VMware Workspace ONE Access (RCE).",
        "cisa_kev": True,
        "base_score": 9.8,
        "severity": "Critical",
        "mitre": ["T1190", "T1059"],
        "year": 2022,
    },
    "CVE-2024-4577": {
        "name": "PHP-CGI Argument Injection RCE",
        "vendor": "PHP",
        "description": "Argument injection in PHP-CGI on Windows enabling remote code execution.",
        "cisa_kev": True,
        "base_score": 9.8,
        "severity": "Critical",
        "mitre": ["T1190", "T1059"],
        "year": 2024,
    },
    "CVE-2021-1675": {
        "name": "Windows Print Spooler RCE (PrintNightmare)", 
        "vendor": "Microsoft",
        "description": "Remote code execution in Windows Print Spooler.",
        "cisa_kev": True,
        "base_score": 8.8,
        "severity": "High",
        "mitre": ["T1212"],
        "year": 2021,
    },
}

DEFAULT_REGIONS = [
    {"label": "US", "lat": 37.0902, "lon": -95.7129, "radius_km": 2000},
    {"label": "US-EAST", "lat": 38.8977, "lon": -77.0365, "radius_km": 500},
    {"label": "EU", "lat": 51.1657, "lon": 10.4515, "radius_km": 1500},
    {"label": "DE", "lat": 51.1657, "lon": 10.4515, "radius_km": 400},
    {"label": "RU", "lat": 61.5240, "lon": 105.3188, "radius_km": 1500},
    {"label": "CN", "lat": 35.8617, "lon": 104.1954, "radius_km": 1200},
    {"label": "IN", "lat": 20.5937, "lon": 78.9629, "radius_km": 1000},
    {"label": "BR", "lat": -14.2350, "lon": -51.9253, "radius_km": 1200},
    {"label": "SG", "lat": 1.3521, "lon": 103.8198, "radius_km": 300},
    {"label": "NL", "lat": 52.1326, "lon": 5.2913, "radius_km": 400},
    {"label": "FR", "lat": 46.2276, "lon": 2.2137, "radius_km": 400},
    {"label": "AU", "lat": -25.2744, "lon": 133.7751, "radius_km": 1000},
    {"label": "HK", "lat": 22.3193, "lon": 114.1694, "radius_km": 300},
    {"label": "SE", "lat": 60.1282, "lon": 18.6435, "radius_km": 400},
    {"label": "PL", "lat": 51.9194, "lon": 19.1451, "radius_km": 400},
]

ORGANIC_IP_POOL = [
    # (ip, lat, lon, label)
    ("8.8.8.8", 37.4192, -122.0574, "Google DNS"),
    ("1.1.1.1", -33.8688, 151.2093, "Cloudflare DNS"),
    ("9.9.9.9", 38.8977, -77.0365, "Quad9 DNS"),
    ("185.220.101.1", 48.8566, 2.3522, "Tor Exit"),
    ("45.155.205.233", 60.1699, 24.9384, "Scan Source"),
    ("104.16.132.229", 40.7128, -74.0060, "CDN Front"),
]


def calculate_shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    value = value.lower()
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    entropy = 0.0
    for count in counts.values():
        p = count / n
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def extract_domain_part(value: str, ioc_type: str) -> str:
    if ioc_type in ("domain", "hostname"):
        return value.strip().lower()
    if ioc_type == "url":
        try:
            parsed = urlparse(value)
            host = parsed.netloc or parsed.path
            if not host:
                return value.lower()
            if ":" in host and not host.startswith("["):
                host = host.split(":")[0]
            return host.lower()
        except Exception:
            return value.lower()
    return value.strip().lower()


def get_sld(value: str) -> Optional[str]:
    domain = extract_domain_part(value, "domain")
    parts = [p for p in domain.split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return None


def get_tld(value: str) -> str:
    domain = extract_domain_part(value, "domain")
    parts = [p for p in domain.split(".") if p]
    if not parts:
        return ""
    return parts[-1].lower()


def ip_entropy_signal(ip_value: str, ioc_type: str) -> Tuple[float, bool]:
    if ioc_type not in ("ipv4", "ipv6"):
        return 0.0, False
    try:
        addr = ipaddress.ip_address(ip_value)
        if ioc_type == "ipv6" and addr.ipv4_mapped:
            return 0.0, False
    except ValueError:
        return 0.0, False
    octets = ip_value.split(".")
    ent = calculate_shannon_entropy(ip_value.replace(".", ""))
    return ent, ent > 4.6


def lookup_cve(cve_id: str) -> Optional[Dict]:
    normalized = cve_id.strip().upper()
    return KNOWN_CVES.get(normalized)


def get_regions_by_entropy(entropy: float) -> List[Dict]:
    if entropy > 4.6:
        return DEFAULT_REGIONS[:5]
    return DEFAULT_REGIONS


def build_dga_signal(entropy: float) -> Tuple[bool, int]:
    if entropy >= 4.5:
        return True, 30
    if entropy >= 4.0:
        return True, 15
    return False, 0