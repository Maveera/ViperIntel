from typing import Dict, List, Optional
from dataclasses import dataclass, field

from core.detector import detect_ioc_type
from core.offline_intel import (
    calculate_shannon_entropy,
    get_tld,
    HIGH_RISK_TLDS,
    SUSPICIOUS_TLDS,
    ip_entropy_signal,
)


@dataclass
class RiskFactor:
    name: str
    points: int
    reason: str
    source: str = "analysis"


@dataclass
class ProviderSummary:
    provider: str
    available: bool
    reason: str
    verdict: str
    risk_points: int
    detections: int
    confidence: float
    mitre: List[str] = field(default_factory=list)


@dataclass
class RiskScoreResult:
    score: int
    verdict: str
    severity: str
    factors: List[RiskFactor] = field(default_factory=list)
    explanation: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    providers: List[ProviderSummary] = field(default_factory=list)
    entropy: float = 0.0
    confidence: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "score": self.score,
            "verdict": self.verdict,
            "severity": self.severity,
            "factors": [{"name": f.name, "points": f.points, "reason": f.reason, "source": f.source}
                        for f in self.factors],
            "explanation": self.explanation,
            "mitre_techniques": self.mitre_techniques,
            "confidence": self.confidence,
            "entropy": self.entropy,
        }


def _bounded(value: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, value))


def classify(points: int):
    if points >= 80:
        return "MALICIOUS", "Critical"
    if points >= 60:
        return "MALICIOUS", "High"
    if points >= 40:
        return "SUSPICIOUS", "Medium"
    if points >= 20:
        return "LOW", "Low"
    return "CLEAN", "Informational"


def score_from_providers(value: str, provider_results: List[Dict],
                         ioc_type: Optional[str] = None) -> RiskScoreResult:
    value = value.strip()
    if not ioc_type:
        ioc_type = detect_ioc_type(value) or "unknown"

    factors: List[RiskFactor] = []
    mitre: List[str] = []
    summaries: List[ProviderSummary] = []
    avail = [r for r in provider_results if r.get("available")]

    weighted_sum, weight_total = 0.0, 0.0
    malicious_feeds = 0
    suspicious_feeds = 0
    detected_feeds = 0

    for r in provider_results:
        summaries.append(ProviderSummary(
            provider=r.get("provider", "?"),
            available=bool(r.get("available")),
            reason=r.get("reason", ""),
            verdict=r.get("verdict", "unknown"),
            risk_points=int(r.get("risk_points", 0)),
            detections=int(r.get("detections", 0)),
            confidence=float(r.get("confidence", 0.0)),
            mitre=list(r.get("mitre", [])),
        ))
        mitre.extend(r.get("mitre", []))

        if not r.get("available"):
            continue
        detected_feeds += 1
        verdict = r.get("verdict", "unknown")
        if verdict == "malicious":
            malicious_feeds += 1
        elif verdict == "suspicious":
            suspicious_feeds += 1

        pts = int(r.get("risk_points", 0))
        conf = float(r.get("confidence", 0.0))
        w = 0.5 + conf
        weighted_sum += pts * w
        weight_total += w

        name = r.get("provider", "?")
        data = r.get("data", {})
        _append_provider_factors(factors, name, verdict, pts, data)

    # Supplement with offline heuristics (entropy / TLD / known ranges)
    _append_heuristic_factors(value, ioc_type, factors, mitre)

    if weight_total > 0 and detected_feeds > 0:
        base_score = int(weighted_sum / weight_total)
    else:
        base_score = len(factors) * 10

    # Boost when multiple independent feeds agree on malicious
    if malicious_feeds >= 2:
        base_score += 5
    if malicious_feeds >= 3:
        base_score += 5
    if malicious_feeds > 0 and suspicious_feeds >= 2:
        base_score += 5

    score = _bounded(base_score)
    verdict, severity = classify(score)

    if avail:
        confidence = sum(float(r.get("confidence", 0.0)) for r in avail) / len(avail)
        confidence = min(1.0, confidence + 0.05 * min(len(avail), 5))
    else:
        confidence = 0.0

    explanation = _build_explanation(score, verdict, factors, detected_feeds)

    return RiskScoreResult(
        score=score,
        verdict=verdict,
        severity=severity,
        factors=factors,
        explanation=explanation,
        mitre_techniques=list(dict.fromkeys([t for t in mitre if t.startswith("T")])),
        providers=summaries,
        entropy=calculate_shannon_entropy(value),
        confidence=round(confidence, 3),
    )


def _append_provider_factors(factors: List[RiskFactor], name: str, verdict: str,
                             pts: int, data: Dict) -> None:
    if name == "VirusTotal":
        mal = data.get("malicious", 0)
        total = data.get("total_engines", 0)
        if mal > 0:
            factors.append(RiskFactor(
                "VirusTotal Detections", pts,
                "Flagged malicious by {}/{} engines".format(mal, total), name))
        elif data.get("suspicious", 0) > 0:
            factors.append(RiskFactor(
                "VirusTotal Suspicious", pts,
                "Flagged suspicious by {} engines".format(data.get("suspicious", 0)), name))
    elif name == "AbuseIPDB":
        sc = data.get("abuse_confidence_score", 0)
        rep = data.get("total_reports", 0)
        if sc > 0:
            factors.append(RiskFactor(
                "AbuseIPDB Score", min(pts, 100),
                "Abuse confidence {}% with {} reports ({} recent)".format(
                    sc, rep, data.get("recent_reports", 0)), name))
    elif name == "AlienVault OTX":
        n = data.get("pulse_count", 0)
        if n > 0:
            factors.append(RiskFactor(
                "OTX Pulses", min(pts, 100),
                "Found in {} OTX pulses".format(n), name))
        if data.get("malware_families"):
            factors.append(RiskFactor(
                "OTX Malware", 20,
                "Malware families: {}".format(", ".join(data["malware_families"][:3])), name))
        if data.get("threat_actors"):
            factors.append(RiskFactor(
                "OTX Threat Actors", 15,
                "Threat actors: {}".format(", ".join(data["threat_actors"][:3])), name))
    elif name == "GreyNoise":
        if data.get("noise"):
            factors.append(RiskFactor(
                "GreyNoise", min(pts, 100),
                "Noise: {}".format(data.get("classification", "unknown")), name))
    elif name == "Shodan":
        v = data.get("vulnerabilities", [])
        p = data.get("ports", [])
        if v:
            factors.append(RiskFactor(
                "Shodan Vulnerabilities", pts,
                "{} exposed CVEs: {}".format(len(v), ", ".join(v[:4])), name))
        elif p:
            factors.append(RiskFactor(
                "Shodan Ports", min(pts, 100),
                "Exposed ports: {}".format(", ".join(map(str, p[:8]))), name))
    elif name == "URLScan.io":
        n = data.get("scans_found", 0)
        if n > 0:
            factors.append(RiskFactor(
                "URLScan Detections", min(pts, 100),
                "{} scans found for indicator".format(n), name))
    elif name == "NVD":
        if data.get("base_score"):
            factors.append(RiskFactor(
                "NVD CVSS", min(pts, 100),
                "CVSS {}/10 ({})".format(data["base_score"], data.get("severity", "")), name))
    elif name == "CISA KEV":
        if data.get("in_kev"):
            factors.append(RiskFactor(
                "CISA KEV", pts,
                "{} actively exploited (added {})".format(
                    data.get("cveID", ""), data.get("dateAdded", "")), name))


def _append_heuristic_factors(value: str, ioc_type: str,
                              factors: List[RiskFactor], mitre: List[str]) -> None:
    if ioc_type in ("domain", "url", "hostname"):
        tld = get_tld(value)
        entropy = calculate_shannon_entropy(value)
        if tld in HIGH_RISK_TLDS:
            factors.append(RiskFactor("High-Risk TLD", 35,
                                       "High-risk TLD (.{}): commonly used for phishing/DGA".format(tld)))
            mitre.append("T1071.001")
        elif tld in SUSPICIOUS_TLDS:
            factors.append(RiskFactor("Suspicious TLD", 15,
                                       "Suspicious TLD (.{}).".format(tld)))
            mitre.append("T1071.001")
        if entropy >= 4.3:
            factors.append(RiskFactor("DGA Entropy", 25,
                                       "High Shannon entropy ({:.2f}) suggests algorithmically generated name".format(entropy)))
            mitre.append("T1071.001")
    elif ioc_type in ("sha256", "sha1", "md5"):
        entropy = calculate_shannon_entropy(value)
        factors.append(RiskFactor("Hash Verified", 0,
                                   "Hash format validated ({} chars, entropy {:.2f}).".format(
                                       len(value), entropy)))
    elif ioc_type in ("ipv4", "ipv6"):
        ent, high = ip_entropy_signal(value, ioc_type)
        if high:
            factors.append(RiskFactor("High Entropy IPv4", 10,
                                       "Unusual numeric entropy in IP octets.".format(ent)))
        if value.startswith(("185.", "45.", "5.", "94.")):
            factors.append(RiskFactor("Known Abuse Range", 15,
                                       "Leading octet {} is disproportionately reported for abuse.".format(
                                           value.split(".")[0])))


def _build_explanation(score: int, verdict: str,
                       factors: List[RiskFactor], feeds: int) -> List[str]:
    lines = []
    positives = [f for f in factors if f.points > 0]
    if positives:
        lines.append("Detected by {} threat intelligence feed(s).".format(feeds))
        lines.append("")
        lines.append("Key contributing factors:")
        for f in sorted(positives, key=lambda x: x.points, reverse=True)[:6]:
            lines.append("  +{} {} - {}".format(f.points, f.name, f.reason))
    elif verdict == "CLEAN":
        lines.append("No threat-intelligence sources flagged this indicator.")
        lines.append("IOC appears clean across configured feeds.")
    else:
        lines.append("Signals detected from {} feed(s).".format(feeds))
    return lines


def score_offline_only(value: str, ioc_type: Optional[str] = None) -> RiskScoreResult:
    """Fallback scoring when no API keys are configured: use heuristics + CVE catalog."""
    from core.offline_intel import lookup_cve

    factors: List[RiskFactor] = []
    mitre: List[str] = []
    value = value.strip()
    if not ioc_type:
        ioc_type = detect_ioc_type(value) or "unknown"

    if ioc_type == "cve":
        known = lookup_cve(value)
        if known:
            factors.append(RiskFactor(
                "CISA KEV Cataloged", min(100, int(known["base_score"] * 10)),
                "{} is a known exploited vulnerability: {}".format(value, known["name"])))
            mitre.extend(known.get("mitre", []))
    else:
        _append_heuristic_factors(value, ioc_type, factors, mitre)

    score = _bounded(sum(f.points for f in factors))
    verdict, severity = classify(score)
    return RiskScoreResult(
        score=score,
        verdict=verdict,
        severity=severity,
        factors=factors,
        explanation=[f.reason for f in factors] if factors else ["No configured feeds; offline heuristics only."],
        mitre_techniques=list(dict.fromkeys([t for t in mitre if t.startswith("T")])),
        entropy=calculate_shannon_entropy(value),
        confidence=0.5,
    )


def aggregate_bulk_scores(rows: List[Dict]) -> Dict:
    total = len(rows)
    return {
        "total": total,
        "malicious": sum(1 for r in rows if r.get("verdict") == "MALICIOUS"),
        "suspicious": sum(1 for r in rows if r.get("verdict") == "SUSPICIOUS"),
        "low": sum(1 for r in rows if r.get("verdict") == "LOW"),
        "clean": sum(1 for r in rows if r.get("verdict") == "CLEAN"),
    }