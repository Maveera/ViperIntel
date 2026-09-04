import re
from typing import Optional, Tuple, List

IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
IPV6_RE = re.compile(
    r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
    r"|^([0-9a-fA-F]{1,4}:){1,7}:$"
    r"|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$"
    r"|^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$"
    r"|^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$"
    r"|^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$"
    r"|^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$"
    r"|^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})$"
    r"|^:((:[0-9a-fA-F]{1,4}){1,7}|:)$"
    r"|^([0-9a-fA-F]{1,4}:){1,5}((:[0-9a-fA-F]{0,4}){1,2})?$"
    r"|^([0-9a-fA-F]{1,4}:){1,4}((:[0-9a-fA-F]{0,4}){1,3})?$"
    r"|^([0-9a-fA-F]{1,4}:){1,3}((:[0-9a-fA-F]{0,4}){1,4})?$"
    r"|^([0-9a-fA-F]{1,4}:){1,2}((:[0-9a-fA-F]{0,4}){1,5})?$"
    r"|^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{0,4}){1,6})?$"
)
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
URL_RE = re.compile(
    r"^https?://[^\s<>\"']+"
    r"(\.[^\s<>\"']+)+(/[^\s<>\"']*)?"
    r"(\?[^\s<>\"']*)?$", re.IGNORECASE
)
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}$"
)
HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)

IOC_TYPES = [
    "ipv4", "ipv6", "sha256", "sha1", "md5",
    "cve", "email", "url", "domain", "hostname",
]

IOC_LABELS = {
    "ipv4": "IPv4 Address",
    "ipv6": "IPv6 Address",
    "sha256": "SHA-256 Hash",
    "sha1": "SHA-1 Hash",
    "md5": "MD5 Hash",
    "cve": "CVE ID",
    "email": "Email Address",
    "url": "URL",
    "domain": "Domain",
    "hostname": "Hostname",
}

IOC_ICONS = {
    "ipv4": "\U0001f310",
    "ipv6": "\U0001f310",
    "sha256": "\U0001f9ea",
    "sha1": "\U0001f9ea",
    "md5": "\U0001f9ea",
    "cve": "\U0001f6a8",
    "email": "\u2709\ufe0f",
    "url": "\U0001f310",
    "domain": "\U0001f310",
    "hostname": "\U0001f5a5\ufe0f",
}

NATURAL_ORDER = [
    "cve", "email", "url", "sha256", "sha1", "md5",
    "ipv4", "ipv6", "domain", "hostname",
]


def detect_ioc_type(value: str) -> Optional[str]:
    value = value.strip()
    if not value:
        return None

    for ioc_type in NATURAL_ORDER:
        match = _matches(ioc_type, value)
        if match:
            return ioc_type
    return None


def _matches(ioc_type: str, value: str) -> bool:
    if ioc_type == "cve":
        return bool(CVE_RE.match(value))
    if ioc_type == "email":
        return bool(EMAIL_RE.match(value))
    if ioc_type == "url":
        return bool(URL_RE.match(value))
    if ioc_type == "sha256":
        return bool(SHA256_RE.match(value))
    if ioc_type == "sha1":
        return bool(SHA1_RE.match(value))
    if ioc_type == "md5":
        return bool(MD5_RE.match(value))
    if ioc_type == "ipv4":
        return bool(IPV4_RE.match(value))
    if ioc_type == "ipv6":
        return bool(IPV6_RE.match(value))
    if ioc_type == "domain":
        if URL_RE.match(value):
            return False
        return bool(DOMAIN_RE.match(value))
    if ioc_type == "hostname":
        if URL_RE.match(value):
            return False
        return bool(HOSTNAME_RE.match(value))
    return False


def validate_ioc(value: str, ioc_type: Optional[str] = None) -> Tuple[bool, Optional[str], str]:
    value = value.strip()
    if not value:
        return False, None, "Empty input"
    if len(value) > 2048:
        return False, None, "Input exceeds 2048 characters"

    if ioc_type:
        if ioc_type not in IOC_TYPES:
            return False, None, f"Unsupported type: {ioc_type}"
        if _matches(ioc_type, value):
            return True, ioc_type, ""
        return False, None, f"Invalid format for {ioc_type}"

    detected = detect_ioc_type(value)
    if detected:
        return True, detected, ""
    return False, None, "Unable to auto-detect IOC type"


def expand_cidr(cidr: str) -> List[str]:
    import ipaddress
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
        hosts = list(net.hosts())
        if len(hosts) > 1024:
            return [str(h) for h in hosts[:1024]]
        return [str(h) for h in hosts]
    except ValueError:
        return []


def is_public_ip(ip_str: str) -> bool:
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip_str)
        return not (addr.is_private or addr.is_loopback or addr.is_reserved
                    or addr.is_multicast or addr.is_link_local)
    except ValueError:
        return False


def parse_bulk_file(content: str) -> List[Tuple[str, Optional[str]]]:
    TYPE_ALIASES = {
        "ip": "ipv4",
        "ip-address": "ipv4",
        "ipaddress": "ipv4",
        "sha256": "sha256",
        "sha1": "sha1",
        "md5": "md5",
        "cve": "cve",
        "email": "email",
        "url": "url",
        "domain": "domain",
        "hostname": "hostname",
        "host": "hostname",
    }
    HEADER_WORDS = {"type", "ioc", "indicator", "value", "indicator_type", "ip", "hash"}
    results = []
    for idx, line in enumerate(content.strip().split("\n")):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in re.split(r"[,\t;|]", line) if p.strip()]
        if len(parts) >= 2 and parts[0].lower() in TYPE_ALIASES:
            results.append((parts[1], TYPE_ALIASES[parts[0].lower()]))
        else:
            first_word = parts[0].split()[0].lower() if parts else ""
            if idx == 0 and len(parts) >= 2 and first_word in HEADER_WORDS:
                continue
            results.append((parts[0], None))
    return results
