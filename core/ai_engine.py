from typing import Dict, List
from dataclasses import dataclass, field

from core.detector import detect_ioc_type
from core.risk_engine import RiskScoreResult


@dataclass
class AIAnalysis:
    executive_summary: str
    technical_analysis: str
    why_suspicious: List[str] = field(default_factory=list)
    mitre_attack_mapping: List[Dict] = field(default_factory=list)
    recommended_soc_actions: List[str] = field(default_factory=list)
    customer_friendly_summary: str = ""

    def to_dict(self) -> Dict:
        return {
            "executive_summary": self.executive_summary,
            "technical_analysis": self.technical_analysis,
            "why_suspicious": self.why_suspicious,
            "mitre_attack_mapping": self.mitre_attack_mapping,
            "recommended_soc_actions": self.recommended_soc_actions,
            "customer_friendly_summary": self.customer_friendly_summary,
        }


MITRE_KNOWN = {
    "T1071.001": {
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols associated with web traffic to avoid detection.",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Adversaries may transfer tools or other files from an external system into a compromised environment.",
    },
    "T1566.002": {
        "name": "Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversaries may send spearphishing emails with a malicious link to gain access to victim systems.",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may exploit a software vulnerability in an internet-facing system.",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining initial access.",
    },
    "T1212": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may exploit software vulnerabilities to escalate privileges.",
    },
    "T1498": {
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries may target a network to impede its availability.",
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "description": "Adversaries may search compromised systems to find and obtain insecurely stored credentials.",
    },
}


def analyze(value: str, risk: RiskScoreResult) -> AIAnalysis:
    detected = detect_ioc_type(value) or "unknown"
    score = risk.score
    verdict = risk.verdict

    executive_summary = _executive_summary(value, ioc_type=detected, score=score, verdict=verdict)
    technical_analysis = _technical_analysis(value, detected, risk)
    why_suspicious = _why_suspicious(risk)
    mitre_map = _mitre_mapping(risk, detected)
    actions = _soc_actions(detected, verdict, value)
    customer = _customer_summary(value, score, verdict)

    return AIAnalysis(
        executive_summary=executive_summary,
        technical_analysis=technical_analysis,
        why_suspicious=why_suspicious,
        mitre_attack_mapping=mitre_map,
        recommended_soc_actions=actions,
        customer_friendly_summary=customer,
    )


def _executive_summary(value: str, ioc_type: str, score: int, verdict: str) -> str:
    head = "VIPER INTEL - Local SOC Analysis"
    if verdict == "MALICIOUS":
        tone = "The indicator is evaluated as MALICIOUS based on local offline heuristics."
    elif verdict == "SUSPICIOUS":
        tone = "The indicator is evaluated as SUSPICIOUS and warrants analyst attention."
    elif verdict == "LOW":
        tone = "The indicator carries minor anomalies but is not conclusively malicious."
    else:
        tone = "The indicator presents no significant threat signals locally."
    return "{} {} IOC type: {} | Score: {}/100 | Verdict: {}".format(
        head, tone, ioc_type.upper(), score, verdict)


def _technical_analysis(value: str, ioc_type: str, risk: RiskScoreResult) -> str:
    lines = ["### Technical Analysis", ""]
    lines.append("- **IOC:** `{}`".format(value))
    lines.append("- **Detected Type:** {}".format(ioc_type.upper()))
    if risk.entropy:
        lines.append("- **Shannon Entropy:** {:.2f}".format(risk.entropy))
    lines.append("- **Confidence:** {:.0%}".format(risk.confidence))
    lines.append("")
    lines.append("**Scoring Factors:**")
    for f in risk.factors:
        if f.points > 0:
            lines.append("- {} ({} pts): {}".format(f.name, f.points, f.reason))
    return "\n".join(lines)


def _why_suspicious(risk: RiskScoreResult) -> List[str]:
    top = [f for f in risk.factors if f.points > 0]
    top = sorted(top, key=lambda f: f.points, reverse=True)[:6]
    if not top:
        return ["No significant suspicious indicators observed."]
    return [f.reason for f in top]


def _mitre_mapping(risk: RiskScoreResult, ioc_type: str) -> List[Dict]:
    mapping = []
    for tid in risk.mitre_techniques:
        info = MITRE_KNOWN.get(tid)
        if info:
            mapping.append({
                "id": tid,
                "name": info["name"],
                "tactic": info["tactic"],
                "description": info["description"],
            })
    if not mapping:
        if ioc_type in ("domain", "url", "hostname"):
            mapping.append({
                "id": "T1071.001",
                "name": "Web Protocols",
                "tactic": "Command and Control",
                "description": "Domain-based indicators are commonly used for C2 or phishing infrastructure.",
            })
    # de-dup
    seen = set()
    unique = []
    for m in mapping:
        if m["id"] not in seen:
            seen.add(m["id"])
            unique.append(m)
    return unique


def _soc_actions(ioc_type: str, verdict: str, value: str) -> List[str]:
    base = [
        "Block {} at firewall / proxy / DNS filtering layers.".format(ioc_type),
        "Search SIEM for historical communication involving `{}`.".format(value),
        "Check DNS logs for resolution activity of related domains.",
        "Review authentication logs for anomalies associated with this indicator.",
    ]
    if verdict == "MALICIOUS":
        base += [
            "Isolate affected endpoints and initiate incident response.",
            "Hunt for lateral movement and data exfiltration indicators.",
            "Add indicator to blocklists and intelligence feeds.",
            "Re-scan related IOCs extracted from any affected hosts.",
        ]
    elif verdict == "SUSPICIOUS":
        base += [
            "Add to watchlist and monitor for escalation in activity.",
            "Correlate with any internal alerts referencing this indicator.",
        ]
    return base


def _customer_summary(value: str, score: int, verdict: str) -> str:
    if verdict == "MALICIOUS":
        return "This indicator has been flagged as malicious by the local analysis engine. Security teams should block it and investigate any associated activity."
    if verdict == "SUSPICIOUS":
        return "This indicator shows suspicious characteristics. Please review any related logs and monitor for further activity."
    return "This indicator does not appear threatening based on local analysis. No immediate action is required."


def render_markdown_report(value: str, risk: RiskScoreResult, ai: AIAnalysis) -> str:
    lines = [
        "# VIPER INTEL - Investigation Report",
        "",
        "**IOC:** `{}`".format(value),
        "**Type:** {}".format(ai_ioc_type(value)),
        "**Score:** {}/100".format(risk.score),
        "**Verdict:** {}".format(risk.verdict),
        "**Severity:** {}".format(risk.severity),
        "",
        "## 1. Executive Summary",
        "",
        ai.executive_summary,
        "",
        "## 2. Technical Analysis",
        "",
        ai.technical_analysis,
        "",
        "## 3. Why Suspicious",
        "",
    ]
    for w in ai.why_suspicious:
        lines.append("- {}".format(w))
    lines += ["", "## 4. MITRE ATT&CK Mapping", ""]
    for m in ai.mitre_attack_mapping:
        lines.append("- **{} {}** - {} ({})".format(m["id"], m["name"], m["tactic"], m["description"]))
    lines += ["", "## 5. Recommended SOC Actions", ""]
    for a in ai.recommended_soc_actions:
        lines.append("- {}".format(a))
    lines += ["", "## 6. Risk Factors Detail", ""]
    for f in risk.factors:
        lines.append("- {}: {} pts - {}".format(f.name, f.points, f.reason))
    lines += ["", "---", "Report generated locally by Viper Intel. No external data sources used.", ""]
    return "\n".join(lines)


def ai_ioc_type(value: str) -> str:
    detected = detect_ioc_type(value) or "unknown"
    return detected.upper()