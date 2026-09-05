import base64
from typing import Dict, List

import requests


def get_api_key(name: str) -> str:
    """Resolve an API key from Streamlit secrets / env vars (preferred) or session state."""
    import os
    import streamlit as st

    env_keys = {
        "virustotal": "VIRUSTOTAL_API_KEY",
        "abuseipdb": "ABUSEIPDB_API_KEY",
        "alienvault": "ALIENVAULT_API_KEY",
        "greynoise": "GREYNOISE_API_KEY",
        "shodan": "SHODAN_API_KEY",
        "urlscan": "URLSCAN_API_KEY",
    }
    env_name = env_keys.get(name)
    if env_name and os.getenv(env_name):
        return os.getenv(env_name, "").strip()
    try:
        if env_name and st.secrets.get(env_name):
            return str(st.secrets.get(env_name)).strip()
    except Exception:
        pass
    try:
        keys = st.session_state.get("api_keys", {})
        if keys.get(name):
            return str(keys.get(name)).strip()
    except Exception:
        pass
    return str(st.session_state.get(name + "_key", "") or st.session_state.get("key_" + name) or "").strip()


PROVIDER_CATALOG = [
    {
        "id": "virustotal",
        "name": "VirusTotal",
        "types": ["ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5"],
        "needs_key": True,
        "key_hint": "VIRUSTOTAL_API_KEY",
        "free": "1 req/15s quota, free signup",
    },
    {
        "id": "abuseipdb",
        "name": "AbuseIPDB",
        "types": ["ipv4", "ipv6"],
        "needs_key": True,
        "key_hint": "ABUSEIPDB_API_KEY",
        "free": "1000 req/day free",
    },
    {
        "id": "alienvault",
        "name": "AlienVault OTX",
        "types": ["ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5", "cve"],
        "needs_key": True,
        "key_hint": "ALIENVAULT_API_KEY",
        "free": "Free API token",
    },
    {
        "id": "greynoise",
        "name": "GreyNoise",
        "types": ["ipv4", "ipv6"],
        "needs_key": True,
        "key_hint": "GREYNOISE_API_KEY",
        "free": "Community API v3",
    },
    {
        "id": "shodan",
        "name": "Shodan",
        "types": ["ipv4", "ipv6"],
        "needs_key": True,
        "key_hint": "SHODAN_API_KEY",
        "free": "Free tier available",
    },
    {
        "id": "urlscan",
        "name": "URLScan.io",
        "types": ["domain", "url", "ipv4", "ipv6"],
        "needs_key": True,
        "key_hint": "URLSCAN_API_KEY",
        "free": "50 req/min with API key",
    },
]


class TIProvider:
    """Base class for a threat-intelligence feed. Subclasses implement lookup()."""

    id = ""
    name = ""
    types: List[str] = []
    needs_key = True

    def __init__(self, timeout: int = 12):
        self.timeout = timeout
        self.key = ""

    def is_configured(self) -> bool:
        return not self.needs_key or bool(self.key)

    def _get(self, url: str, headers: Dict = None, params: Dict = None) -> Dict:
        try:
            resp = requests.get(
                url, headers=headers or {}, params=params or {},
                timeout=self.timeout,
            )
            if resp.status_code == 429:
                return {"error": "Rate limited"}
            if resp.status_code >= 500:
                return {"error": "Provider error (HTTP {})".format(resp.status_code)}
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.Timeout:
            return {"error": "Request timeout"}
        except requests.exceptions.ConnectionError:
            return {"error": "Connection failed"}
        except requests.exceptions.HTTPError as e:
            return {"error": "HTTP error: {}".format(getattr(e.response, "status_code", "?"))}
        except Exception as e:
            return {"error": str(e)[:120]}

    def _base_result(self, ioc_type: str, value: str) -> Dict:
        return {
            "provider": self.name,
            "ioc_type": ioc_type,
            "ioc": value,
            "available": False,
            "reason": "",
            "verdict": "unknown",
            "detections": 0,
            "risk_points": 0,
            "confidence": 0.0,
            "mitre": [],
            "data": {},
            "error": None,
        }

    def lookup(self, ioc_type: str, value: str) -> Dict:
        raise NotImplementedError

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in self.types


class VirusTotalProvider(TIProvider):
    id = "virustotal"
    name = "VirusTotal"
    types = ["ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5"]
    needs_key = True
    base = "https://www.virustotal.com/api/v3"

    def lookup(self, ioc_type: str, value: str) -> Dict:
        out = self._base_result(ioc_type, value)
        if not self.is_configured():
            out["reason"] = "No API key configured"
            return out
        try:
            headers = {"x-apikey": self.key}
            if ioc_type in ("ipv4", "ipv6"):
                endpoint = "/ip_addresses/{}".format(value)
            elif ioc_type == "domain":
                endpoint = "/domains/{}".format(value)
            elif ioc_type == "url":
                uid = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
                endpoint = "/urls/{}".format(uid)
            else:
                endpoint = "/files/{}".format(value)

            res = self._get(self.base + endpoint, headers=headers)
            if "error" in res:
                out["reason"] = res["error"]
                out["error"] = res["error"]
                if "Not found" in res["error"] or "404" in res["error"]:
                    out["available"] = True
                    out["verdict"] = "clean"
                    out["data"] = {"message": "Not found in VirusTotal"}
                return out

            attrs = res.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            susp = stats.get("suspicious", 0)
            undet = stats.get("undetected", 0)
            harmless = stats.get("harmless", 0)
            total = sum(stats.values())
            reputation = attrs.get("reputation") or 0

            # Verdict mirrors VirusTotal's own analysis: any malicious engine vote
            # = malicious, otherwise suspicious votes / negative reputation.
            if mal > 0:
                verdict = "malicious"
            elif susp > 0:
                verdict = "suspicious"
            elif reputation < -10:
                verdict = "suspicious"
            else:
                verdict = "clean"

            if mal > 0:
                risk_points = min(100, 80 + mal * 3 + susp * 2)
            elif susp > 0:
                risk_points = min(100, 45 + susp * 3)
            elif reputation < 0:
                risk_points = min(50, 40 + int(abs(reputation) / 10))
            else:
                risk_points = 0

            out["available"] = True
            out["detections"] = mal
            out["verdict"] = verdict
            out["risk_points"] = risk_points
            det_signal = mal + susp
            out["confidence"] = 0.5 + 0.45 * min(1.0, det_signal / max(total or 1, 1))
            out["mitre"] = ["T1105"] if mal > 0 else (["T1105"] if susp > 0 else [])
            out["data"] = {
                "malicious": mal,
                "suspicious": susp,
                "undetected": undet,
                "harmless": harmless,
                "total_engines": total,
                "reputation": reputation,
                "country": attrs.get("country", ""),
                "asn": attrs.get("asn", ""),
                "as_owner": attrs.get("as_owner", ""),
                "network": attrs.get("network", ""),
                "last_analysis_date": attrs.get("last_analysis_date"),
                "categories": attrs.get("categories", []),
                "registrar": attrs.get("registrar", ""),
                "creation_date": attrs.get("creation_date", ""),
                "type_description": attrs.get("type_description", ""),
                "meaningful_name": attrs.get("meaningful_name", ""),
                "size": attrs.get("size", ""),
                "md5": attrs.get("md5", ""),
                "sha1": attrs.get("sha1", ""),
                "sha256": attrs.get("sha256", ""),
            }
        except Exception as e:
            out["reason"] = "Error"
            out["error"] = str(e)[:120]
        return out


class AbuseIPDBProvider(TIProvider):
    id = "abuseipdb"
    name = "AbuseIPDB"
    types = ["ipv4", "ipv6"]
    needs_key = True
    base = "https://api.abuseipdb.com/api/v2"

    def lookup(self, ioc_type: str, value: str) -> Dict:
        out = self._base_result(ioc_type, value)
        if not self.is_configured():
            out["reason"] = "No API key configured"
            return out
        try:
            res = self._get(
                self.base + "/check",
                headers={"Key": self.key, "Accept": "application/json"},
                params={"ipAddress": value, "maxAgeInDays": 90, "verbose": True},
            )
            if "error" in res:
                out["reason"] = res["error"]
                out["error"] = res["error"]
                return out

            data = res.get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            reports = data.get("totalReports", 0)
            recent = len([
                r for r in data.get("reports", [])
                if r.get("reportedAt", "").startswith(("2024", "2025", "2026"))
            ])

            out["available"] = True
            out["detections"] = reports
            out["verdict"] = "malicious" if score >= 75 else "suspicious" if score >= 25 else "clean"
            out["risk_points"] = min(100, score + min(recent * 2, 20))
            out["confidence"] = min(1.0, score / 100.0 + 0.15)
            out["mitre"] = ["T1046"] if score > 0 else []
            out["data"] = {
                "abuse_confidence_score": score,
                "total_reports": reports,
                "recent_reports": recent,
                "last_reported": data.get("lastReportedAt", ""),
                "country": data.get("countryName", ""),
                "country_code": data.get("countryCode", ""),
                "isp": data.get("isp", ""),
                "domain": data.get("domain", ""),
                "hostnames": data.get("hostnames", []),
                "is_tor": data.get("isTor", False),
                "is_whitelisted": data.get("isWhitelisted", False),
                "usage_type": data.get("usageType", ""),
                "reports": [{"date": r.get("reportedAt"), "comment": r.get("comment", "")[:160]}
                            for r in data.get("reports", [])[:5]],
            }
        except Exception as e:
            out["reason"] = "Error"
            out["error"] = str(e)[:120]
        return out


class AlienVaultProvider(TIProvider):
    id = "alienvault"
    name = "AlienVault OTX"
    types = ["ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5", "cve"]
    needs_key = True
    base = "https://otx.alienvault.com/api/v1"

    def lookup(self, ioc_type: str, value: str) -> Dict:
        out = self._base_result(ioc_type, value)
        if not self.is_configured():
            out["reason"] = "No API key configured"
            return out
        try:
            otx_type = {
                "ipv4": "IPv4", "ipv6": "IPv6", "domain": "domain",
                "hostname": "hostname", "url": "url", "cve": "CVE",
            }.get(ioc_type, "file")
            res = self._get(
                "{}/indicators/{}/{}/general".format(self.base, otx_type, value),
                headers={"X-OTX-API-KEY": self.key},
            )
            if "error" in res:
                out["reason"] = res["error"]
                out["error"] = res["error"]
                return out

            pulses = (res.get("pulse_info") or {}).get("pulses", [])
            tags = sorted({t for p in pulses for t in p.get("tags", [])})
            malware = sorted({m for p in pulses for m in p.get("malware_families", [])})
            actors = sorted({a for p in pulses for a in p.get("threat_actors", [])})
            attacks = sorted({a.get("id") for p in pulses
                              for a in p.get("attack_ids", []) if a.get("id")})

            out["available"] = True
            out["detections"] = len(pulses)
            out["verdict"] = "malicious" if len(pulses) > 5 else "suspicious" if len(pulses) > 0 else "clean"
            out["risk_points"] = min(100, len(pulses) * 10 + len(attacks) * 5)
            out["confidence"] = min(1.0, len(pulses) * 0.1 + 0.1)
            out["mitre"] = list({t for t in attacks if t and t.startswith("T")})
            out["data"] = {
                "pulse_count": len(pulses),
                "tags": tags,
                "malware_families": malware,
                "threat_actors": actors,
                "country": res.get("country_code", ""),
                "city": res.get("city", ""),
                "asn": res.get("asn", ""),
                "reputation": res.get("reputation", 0),
                "pulses": [
                    {"name": p.get("name"), "created": p.get("created"),
                     "description": (p.get("description") or "")[:160]}
                    for p in pulses[:5]
                ],
            }
        except Exception as e:
            out["reason"] = "Error"
            out["error"] = str(e)[:120]
        return out


class GreyNoiseProvider(TIProvider):
    id = "greynoise"
    name = "GreyNoise"
    types = ["ipv4", "ipv6"]
    needs_key = True
    base = "https://api.greynoise.io/v3"

    def lookup(self, ioc_type: str, value: str) -> Dict:
        out = self._base_result(ioc_type, value)
        if not self.is_configured():
            out["reason"] = "No API key configured"
            return out
        try:
            res = self._get(
                "{}/community/{}".format(self.base, value),
                headers={"key": self.key},
            )
            if "error" in res:
                out["reason"] = res["error"]
                out["error"] = res["error"]
                return out

            noise = res.get("noise", False)
            riot = res.get("riot", False)
            classification = res.get("classification", "unknown")
            meta = res.get("metadata", {}) or {}

            out["available"] = True
            if noise and classification == "malicious":
                out["verdict"] = "malicious"
                out["risk_points"] = 80
            elif noise:
                out["verdict"] = "suspicious"
                out["risk_points"] = 40
            elif riot:
                out["verdict"] = "clean"
                out["risk_points"] = 5
            else:
                out["verdict"] = "clean"
                out["risk_points"] = 5
            out["confidence"] = 0.7
            out["mitre"] = ["T1046"] if noise else []
            out["data"] = {
                "noise": noise,
                "riot": riot,
                "classification": classification,
                "name": res.get("name", ""),
                "last_seen": res.get("last_seen", ""),
                "country": meta.get("country", ""),
                "city": meta.get("city", ""),
                "organization": meta.get("organization", ""),
                "asn": meta.get("asn", ""),
                "os": meta.get("os", ""),
                "categories": meta.get("categories", []),
                "tags": res.get("tags", []),
            }
        except Exception as e:
            out["reason"] = "Error"
            out["error"] = str(e)[:120]
        return out


class ShodanProvider(TIProvider):
    id = "shodan"
    name = "Shodan"
    types = ["ipv4", "ipv6"]
    needs_key = True
    base = "https://api.shodan.io"

    def lookup(self, ioc_type: str, value: str) -> Dict:
        out = self._base_result(ioc_type, value)
        if not self.is_configured():
            out["reason"] = "No API key configured"
            return out
        try:
            res = self._get(
                "{}/shodan/host/{}".format(self.base, value),
                params={"key": self.key},
            )
            if "error" in res:
                out["reason"] = res["error"]
                out["error"] = res["error"]
                return out

            ports = res.get("ports", [])
            vulns = list(res.get("vulns", {}).keys())
            suspicious_ports = [p for p in ports
                                if p in (21, 22, 23, 25, 445, 1433, 3306, 3389, 5900, 6379, 27017)]

            out["available"] = True
            out["detections"] = len(vulns)
            out["verdict"] = "suspicious" if (vulns or suspicious_ports) else "clean"
            out["risk_points"] = min(100, len(vulns) * 25 + len(suspicious_ports) * 3)
            out["confidence"] = 0.65
            out["mitre"] = ["T1046"] if suspicious_ports else []
            out["data"] = {
                "country": res.get("country_name", ""),
                "city": res.get("city", ""),
                "org": res.get("org", ""),
                "isp": res.get("isp", ""),
                "asn": res.get("asn", ""),
                "ports": ports,
                "hostnames": res.get("hostnames", []),
                "domains": res.get("domains", []),
                "os": res.get("os", ""),
                "vulnerabilities": vulns,
                "tags": res.get("tags", []),
                "services": [{"port": d.get("port"), "product": d.get("product", ""),
                              "version": d.get("version", "")}
                             for d in res.get("data", [])[:8]],
            }
        except Exception as e:
            out["reason"] = "Error"
            out["error"] = str(e)[:120]
        return out


class URLScanProvider(TIProvider):
    id = "urlscan"
    name = "URLScan.io"
    types = ["domain", "url", "ipv4", "ipv6"]
    needs_key = True
    base = "https://urlscan.io/api/v1"

    def lookup(self, ioc_type: str, value: str) -> Dict:
        out = self._base_result(ioc_type, value)
        if not self.is_configured():
            out["reason"] = "No API key configured"
            return out
        try:
            q = "domain:{}".format(value) if ioc_type == "domain" else "ip:{}".format(value)
            res = self._get(
                self.base + "/search/",
                headers={"API-Key": self.key},
                params={"q": q, "size": 5},
            )
            if "error" in res:
                out["reason"] = res["error"]
                out["error"] = res["error"]
                return out

            results = res.get("results", [])
            malicious_hits = 0
            latest = None
            for r in results:
                v = (r.get("page", {}) or {}).get("url", "")
                if "mal" in str(r.get("result", "")).lower():
                    malicious_hits += 1
                if latest is None:
                    latest = v

            out["available"] = True
            out["detections"] = len(results)
            out["verdict"] = "suspicious" if results else "clean"
            out["risk_points"] = min(100, len(results) * 15)
            out["confidence"] = min(1.0, len(results) * 0.1 + 0.1)
            out["data"] = {
                "scans_found": len(results),
                "latest_url": latest,
                "results": [
                    {"url": (r.get("page", {}) or {}).get("url"),
                     "ip": (r.get("page", {}) or {}).get("ip"),
                     "server": (r.get("page", {}) or {}).get("server")}
                    for r in results[:5]
                ],
            }
        except Exception as e:
            out["reason"] = "Error"
            out["error"] = str(e)[:120]
        return out


def build_providers() -> Dict[str, TIProvider]:
    providers = {
        "virustotal": VirusTotalProvider(),
        "abuseipdb": AbuseIPDBProvider(),
        "alienvault": AlienVaultProvider(),
        "greynoise": GreyNoiseProvider(),
        "shodan": ShodanProvider(),
        "urlscan": URLScanProvider(),
    }
    for pid, p in providers.items():
        p.key = get_api_key(pid)
    return providers


def providers_for_type(providers: Dict[str, TIProvider], ioc_type: str) -> List[TIProvider]:
    return [p for p in providers.values() if p.supports(ioc_type)]


def configured_providers_for_type(providers: Dict[str, TIProvider], ioc_type: str) -> List[TIProvider]:
    return [p for p in providers.values()
            if p.supports(ioc_type) and p.is_configured()]