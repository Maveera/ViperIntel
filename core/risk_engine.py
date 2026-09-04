from typing import Dict, List, Optional
from dataclasses import dataclass, field

from core.detector import detect_ioc_type
from core.offline_intel import (
    calculate_shannon_entropy,
    extract_domain_part,
    get_tld,
    get_sld,
    HIGH_RISK_TLDS,
    SUSPICIOUS_TLDS,
    lookup_cve,
    ip_entropy_signal,
)


@dataclass
class RiskFactor:
    name: str
    points: int
    reason: str
    tier: str = "analysis"


@dataclass
class RiskScoreResult:
    score: int
    verdict: str
    severity: str
    factors: List[RiskFactor] = field(default_factory=list)
    explanation: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    entropy: float = 0.0
    confidence: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "score": self.score,
            "verdict": self.verdict,
            "severity": self.severity,
            "factors": [
                {"name": f.name, "points": f.points, "reason": f.reason, "tier": f.tier}
                for f in self.factors
            ],
            "explanation": self.explanation,
            "mitre_techniques": self.mitre_techniques,
            "entropy": self.entropy,
            "confidence": self.confidence,
        }


def _bounded(value: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, value))


def score_ioc(value: str, ioc_type: Optional[str] = None) -> RiskScoreResult:
    value = value.strip()
    if not ioc_type:
        ioc_type = detect_ioc_type(value) or "unknown"

    factors: List[RiskFactor] = []
    mitre: List[str] = []
    points = 0

    if ioc_type == "cve":
        points, factors, mitre = _score_cve(value)
        if points >= 80:
            verdict, severity = "MALICIOUS", "Critical"
        elif points >= 60:
            verdict, severity = "MALICIOUS", "High"
        elif points >= 40:
            verdict, severity = "SUSPICIOUS", "Medium"
        elif points >= 20:
            verdict, severity = "LOW", "Low"
        else:
            verdict, severity = "CLEAN", "Informational"

        return RiskScoreResult(
            score=_bounded(points),
            verdict=verdict,
            severity=severity,
            factors=factors,
            explanation=[f.reason for f in factors],
            mitre_techniques=mitre,
            entropy=calculate_shannon_entropy(value),
            confidence=0.95 if points >= 60 else 0.8,
        )

    if ioc_type in ("domain", "url", "hostname"):
        return _score_domain_like(value, ioc_type, factors, mitre)

    if ioc_type in ("ipv4", "ipv6"):
        return _score_ip(value, ioc_type, factors, mitre)

    if ioc_type in ("sha256", "sha1", "md5"):
        points = 0
        manual_hits = _manual_hash_signals(value.lower())
        for hit in manual_hits:
            points += hit["points"]
            factors.append(RiskFactor(name=hit["name"], points=hit["points"], reason=hit["reason"]))
            mitre.extend(hit.get("mitre", []))
        verdict, severity = _classify(points)
        return RiskScoreResult(
            score=_bounded(points),
            verdict=verdict,
            severity=severity,
            factors=factors,
            explanation=[f.reason for f in factors],
            mitre_techniques=list(dict.fromkeys(mitre)),
            entropy=calculate_shannon_entropy(value),
            confidence=0.75,
        )

    if ioc_type == "email":
        domain = value.split("@")[-1].lower()
        tld = get_tld(domain)
        points = 0
        p = get_sld(domain)
        if tld in HIGH_RISK_TLDS:
            points += 60
            factors.append(RiskFactor("High-Risk TLD", 60, "Email domain uses high-risk TLD (.{}).".format(tld)))
            mitre.append("T1566.002")
        elif tld in SUSPICIOUS_TLDS:
            points += 20
            factors.append(RiskFactor("Suspicious TLD", 20, "Email domain uses suspicious TLD (.{}).".format(tld)))
            mitre.append("T1566.002")
        if p and any(segment.isdigit() for segment in p.split(".")):
            points += 10
            factors.append(RiskFactor("Numeric Domain", 10, "Email domain contains numeric segment(s) common in phishing."))
            mitre.append("T1566.002")
        domain_entropy = calculate_shannon_entropy(domain)
        if domain_entropy >= 3.8:
            points += 15
            factors.append(RiskFactor("High Entropy Domain", 15, "Email domain has high Shannon entropy ({:.2f}), suggesting DGA.".format(domain_entropy)))
            mitre.append("T1071.001")
        verdict, severity = _classify(points)
        return RiskScoreResult(
            score=_bounded(points),
            verdict=verdict,
            severity=severity,
            factors=factors,
            explanation=[f.reason for f in factors],
            mitre_techniques=list(dict.fromkeys(mitre)),
            entropy=domain_entropy,
            confidence=0.7,
        )

    points = 0
    verdict, severity = _classify(points)
    return RiskScoreResult(
        score=0,
        verdict=verdict,
        severity=severity,
        factors=[],
        explanation=["Unknown IOC type. No local analysis applied."],
        mitre_techniques=[],
        entropy=0.0,
        confidence=0.0,
    )


def _score_cve(value: str):
    factors = []
    mitre = []
    points = 0

    known = lookup_cve(value)
    if known:
        base = known.get("base_score", 0)
        points += int(round(base * 10))
        factors.append(RiskFactor(
            "CISA KEV Cataloged",
            int(round(base * 10)),
            "{} is cataloged in the CISA Known Exploited Vulnerabilities list.".format(value.upper()),
        ))
        if known.get("cisa_kev"):
            points += 15
            factors.append(RiskFactor(
                "Actively Exploited",
                15,
                "Vulnerability is known to be actively exploited in the wild.",
            ))
        if known.get("name"):
            points += 15
            factors.append(RiskFactor(
                "Well-Known Vulnerability",
                15,
                "{} ({}) is a widely documented and exploited vulnerability.".format(
                    known["name"], known.get("vendor", "Unknown")),
            ))
        mitre.extend(known.get("mitre", []))
        if len(mitre) >= 2:
            points += 5
            factors.append(RiskFactor("Multiple MITRE Techniques", 5,
                                      "Vulnerability maps to multiple MITRE ATT&CK techniques."))
    else:
        year = _cve_year(value)
        points += 35
        factors.append(RiskFactor("Unknown CVE", 35, "CVE not in local catalog; treat as high-priority and verify."))
        if year and year <= 2024:
            points += 10
            factors.append(RiskFactor("Older CVE Year", 10, "CVE from {} has had more time for public exploitation.".format(year)))

    points = _bounded(points)
    mitre = list(dict.fromkeys(mitre))
    return points, factors, mitre


def _score_domain_like(value, ioc_type, factors, mitre):
    points = 0
    domain = extract_domain_part(value, ioc_type)
    tld = get_tld(domain)
    entropy = calculate_shannon_entropy(domain)

    if tld in HIGH_RISK_TLDS:
        points += 35
        factors.append(RiskFactor("High-Risk TLD", 35, "Domain uses high-risk TLD (.{}).".format(tld)))
        mitre.append("T1071.001")
    elif tld in SUSPICIOUS_TLDS:
        points += 15
        factors.append(RiskFactor("Suspicious TLD", 15, "Domain uses suspicious TLD (.{}).".format(tld)))
        mitre.append("T1071.001")
    elif not tld and ioc_type == "hostname":
        factors.append(RiskFactor("Hostname Informational", 0, "Hostname has no TLD; informational."))

    signal, dga_points = _dga_rule(entropy)
    if signal:
        points += dga_points
        factors.append(RiskFactor("DGA Entropy", dga_points,
                                  "High Shannon entropy ({:.2f}) suggests algorithmically generated domain.".format(entropy)))
        mitre.append("T1071.001")

    label = "URL" if ioc_type == "url" else ("Domain" if ioc_type == "domain" else "Hostname")

    if len(domain) > 45:
        points += 15
        factors.append(RiskFactor("Very Long Domain", 15, "{} length ({}) is abnormal for legitimate registrations.".format(label, len(domain))))
        if "T1071.001" not in mitre:
            mitre.append("T1071.001")

    numeric_segments = [s for s in domain.split(".") if s.isdigit()]
    if numeric_segments:
        points += 15
        factors.append(RiskFactor("Numeric Segments", 15, "Domain contains numeric segment(s) common in phishing domains."))
        if "T1566.002" not in mitre:
            mitre.append("T1566.002")

    hyphens = domain.count("-")
    if hyphens >= 3:
        points += 10
        factors.append(RiskFactor("Excessive Hyphens", 10, "Domain contains {} hyphens, common in phishing lookalikes.".format(hyphens)))
        if "T1566.002" not in mitre:
            mitre.append("T1566.002")

    if any(seg in domain for seg in ("paypal", "login", "secure", "bank", "apple")):
        points += 10
        factors.append(RiskFactor("Brand Impersonation Keywords", 10,
                                  "Domain contains brand-related keywords often spoofed in phishing."))
        if "T1566.002" not in mitre:
            mitre.append("T1566.002")

    if ioc_type == "url":
        from urllib.parse import urlparse
        parsed = urlparse(value)
        if parsed.username or parsed.password:
            points += 20
            factors.append(RiskFactor("Embedded Credentials", 20, "URL contains embedded username/password (credential harvesting indicator)."))
            mitre.append("T1566.002")
        if parsed.port and parsed.port not in (80, 443, 8080):
            points += 15
            factors.append(RiskFactor("Uncommon Port", 15, "URL uses uncommon port ({}) to avoid detection.".format(parsed.port)))
            mitre.append("T1071.001")
        if parsed.path and len(parsed.path) > 10 and _no_slashes_suspicious(parsed.path):
            points += 10
            factors.append(RiskFactor("Obfuscated Path", 10, "URL path contains many suspicious characters, typical of phishing links."))
            mitre.append("T1566.002")
        if "@" in (parsed.netloc or value):
            points += 15
            factors.append(RiskFactor("At-Sign Obfuscation", 15, "URL uses @-sign obfuscation to disguise the real destination."))
            mitre.append("T1566.002")
        if re_ipv4_in_host(parsed.netloc):
            points += 15
            factors.append(RiskFactor("Raw IP in URL", 15, "URL host is a raw IP address, bypassing domain-based blocklists."))
            mitre.append("T1071.001")

    points = _bounded(points)
    verdict, severity = _classify(points)
    return RiskScoreResult(
        score=points,
        verdict=verdict,
        severity=severity,
        factors=factors,
        explanation=[f.reason for f in factors],
        mitre_techniques=list(dict.fromkeys(mitre)),
        entropy=entropy,
        confidence=0.8 if points >= 40 else 0.6,
    )


def _score_ip(value, ioc_type, factors, mitre):
    points = 0
    ent, high_ent = ip_entropy_signal(value, ioc_type)

    if ioc_type == "ipv6":
        points += 15
        factors.append(RiskFactor("IPv6 Address", 15, "IPv6 addresses are commonly used to evade IPv4-based monitoring."))
        mitre.append("T1071.001")

    if high_ent:
        points += 10
        factors.append(RiskFactor("High Entropy IPv4", 10,
                                  "High Shannon entropy ({:.2f}) in IP octets can indicate algorithmic assignment.".format(ent)))

    if value.startswith(("185.", "45.", "103.", "94.", "5.")):
        points += 15
        factors.append(RiskFactor("Known Risk Range", 15, "IP falls within frequently abused hosting ranges (5.x/45.x/94.x/185.x)."))
        mitre.append("T1071.001")

    first_octet = int(value.split(".")[0]) if ioc_type == "ipv4" and value.split(".")[0].isdigit() else None
    if first_octet in (5, 45, 94, 185):
        points += 20
        factors.append(RiskFactor("Common Abuse Octet", 20, "Leading octet {} is disproportionately reported for abuse.".format(first_octet)))
        if "T1071.001" not in mitre:
            mitre.append("T1071.001")

    points = _bounded(points)
    verdict, severity = _classify(points)
    return RiskScoreResult(
        score=points,
        verdict=verdict,
        severity=severity,
        factors=factors,
        explanation=[f.reason for f in factors],
        mitre_techniques=list(dict.fromkeys(mitre)),
        entropy=ent,
        confidence=0.7,
    )


def _manual_hash_signals(sha256: str) -> List[Dict]:
    hits = []
    if "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in sha256:
        hits.append({"name": "Empty File Hash", "points": 10, "reason": "Hash matches known empty-file SHA-256.", "mitre": []})
    return hits


def _dga_rule(entropy: float):
    if entropy >= 4.5:
        return True, 30
    if entropy >= 4.0:
        return True, 15
    return False, 0


def _classify(points: int):
    if points >= 80:
        return "MALICIOUS", "Critical"
    if points >= 60:
        return "MALICIOUS", "High"
    if points >= 40:
        return "SUSPICIOUS", "Medium"
    if points >= 20:
        return "LOW", "Low"
    return "CLEAN", "Informational"


def _cve_year(value: str) -> Optional[int]:
    try:
        year = int(value.split("-")[1])
        return year
    except Exception:
        return None


def _no_slashes_suspicious(path: str) -> bool:
    suspicious_chars = 0
    for ch in path:
        if ch in "-_%@":
            suspicious_chars += 1
    return suspicious_chars >= 3


def re_ipv4_in_host(netloc: str) -> bool:
    import re
    return bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$", netloc or ""))


def apply_tier(rr: RiskScoreResult, tier: str) -> RiskScoreResult:
    for f in rr.factors:
        f.tier = tier
    return rr


def aggregate_bulk_scores(items: List[Dict]) -> Dict:
    total = len(items)
    malicious = sum(1 for i in items if i.get("verdict") == "MALICIOUS")
    suspicious = sum(1 for i in items if i.get("verdict") == "SUSPICIOUS")
    low = sum(1 for i in items if i.get("verdict") == "LOW")
    clean = sum(1 for i in items if i.get("verdict") == "CLEAN")
    return {
        "total": total,
        "malicious": malicious,
        "suspicious": suspicious,
        "low": low,
        "clean": clean,
    }