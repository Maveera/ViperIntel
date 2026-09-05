"""
Viper Intel - SOC Threat Intelligence Scanner

Bulk IP / Hash / Domain / URL / CVE analysis against configurable
threat-intelligence feeds (VirusTotal, AbuseIPDB, AlienVault OTX,
GreyNoise, Shodan, URLScan.io, NVD, CISA KEV, EPSS).

No hardcoded secrets. API keys are supplied via the sidebar at runtime,
or via Streamlit secrets / environment variables for deployments.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

import pandas as pd
import streamlit as st

from core.detector import detect_ioc_type, parse_bulk_file, validate_ioc
from core.providers import (
    PROVIDER_CATALOG,
    build_providers,
    configured_providers_for_type,
    get_api_key,
)
from core.risk_engine import (
    RiskScoreResult,
    aggregate_bulk_scores,
    score_from_providers,
    score_offline_only,
)

st.set_page_config(page_title="Viper Intel", layout="wide",
                   page_icon="🐍", initial_sidebar_state="expanded")

APP_TAG = "v3.0 API scan"


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------

def _s(key: str, default=None):
    if key not in st.session_state:
        st.session_state[key] = default
    return st.session_state[key]


def _init_state() -> None:
    _s("api_keys", {})
    _s("providers", None)
    _s("bulk_results", [])
    _s("bulk_source", None)


# ---------------------------------------------------------------------------
# Horizontal space to mimic scores 0-100
# ---------------------------------------------------------------------------

VERDICT_HTML = {
    "MALICIOUS": '<span style="background:#b91c1c;color:#fff;padding:1px 8px;border-radius:8px;font-weight:600;">MALICIOUS</span>',
    "SUSPICIOUS": '<span style="background:#ea580c;color:#fff;padding:1px 8px;border-radius:8px;font-weight:600;">SUSPICIOUS</span>',
    "LOW": '<span style="background:#facc15;color:#111;padding:1px 8px;border-radius:8px;font-weight:600;">LOW</span>',
    "CLEAN": '<span style="background:#16a34a;color:#fff;padding:1px 8px;border-radius:8px;font-weight:600;">CLEAN</span>',
    "UNKNOWN": '<span style="background:#6b7280;color:#fff;padding:1px 8px;border-radius:8px;font-weight:600;">UNKNOWN</span>',
}

PROVIDER_BADGE = {
    "available": '<span style="color:#16a34a;">&#10004;</span>',
    "unavailable": '<span style="color:#6b7280;">&#10005;</span>',
    "error": '<span style="color:#ea580c;">&#9888;</span>',
}


def _score_bar_html(score: int) -> str:
    score = max(0, min(100, score))
    color = "#b91c1c" if score >= 80 else "#ea580c" if score >= 60 else \
        "#facc15" if score >= 40 else "#16a34a"
    return '<div style="background:#e5e7eb;border-radius:6px;width:110px;height:14px;">' \
           '<div style="background:{};width:{}%;height:14px;border-radius:6px;"></div></div>'.format(
               color, score)


est = _dt.datetime.now()


# ---------------------------------------------------------------------------
# Sidebar: API key configuration (same as before - no hardcoded secrets)
# ---------------------------------------------------------------------------

def _encrypt_save(keys: Dict[str, str]) -> None:
    try:
        from cryptography.fernet import Fernet
        key_file = ".secret.key"
        if not os.path.exists(key_file):
            with open(key_file, "wb") as f:
                f.write(Fernet.generate_key())
        with open(key_file, "rb") as f:
            fkey = Fernet(f.read())
        payload = fkey.encrypt(json.dumps(keys).encode())
        with open("config.json", "wb") as f:
            f.write(payload)
        st.sidebar.success("API keys saved (encrypted: config.json)")
    except Exception as e:
        st.sidebar.error("Save failed: {}".format(e))


def _decrypt_load() -> None:
    try:
        from cryptography.fernet import Fernet, InvalidToken
        if not (os.path.exists("config.json") and os.path.exists(".secret.key")):
            st.sidebar.info("No saved config found.")
            return
        with open(".secret.key", "rb") as f:
            fkey = Fernet(f.read())
        with open("config.json", "rb") as f:
            payload = fkey.decrypt(f.read())
        keys = json.loads(payload.decode())
        cur = dict(_s("api_keys", {}))
        cur.update(keys)
        st.session_state["api_keys"] = cur
        st.session_state["providers"] = None  # force rebuild
        st.sidebar.success("API keys loaded from config.json")
    except InvalidToken:
        st.sidebar.error("config.json is corrupted or key mismatch")
    except Exception as e:
        st.sidebar.error("Load failed: {}".format(e))


def render_sidebar() -> None:
    st.sidebar.header("🐍 Viper Intel")
    st.sidebar.caption(APP_TAG + " | " + est.strftime("%Y-%m-%d %H:%M"))

    with st.sidebar.expander("🔑 API Key Configuration", expanded=True):
        st.caption("Enter your threat-feed API keys. Keys are kept in-session "
                   "(never committed). For cloud deployments, set the matching "
                   "environment variable / Streamlit secret instead.")
        keys = dict(_s("api_keys", {}))
        for p in PROVIDER_CATALOG:
            if not p["needs_key"]:
                continue
            val = keys.get(p["id"], "")
            hint = os.getenv(p["key_hint"], "") or val
            new_val = st.text_input(
                p["name"], type="password", key="key_" + p["id"],
                value=hint, help="{} | {}".format(p["key_hint"], p["free"]),
            )
            if new_val:
                keys[p["id"]] = new_val.strip()
        st.session_state["api_keys"] = keys
        c1, c2 = st.columns(2)
        if c1.button("💾 Save config"):
            _encrypt_save(keys)
        if c2.button("📂 Load config"):
            _decrypt_load()

    with st.sidebar.expander("🛰 TI Feeds Active", expanded=False):
        provs = st.session_state.get("providers") or build_providers()
        provs = _refresh_providers(provs)
        rows = []
        for p in PROVIDER_CATALOG:
            prov = provs[p["id"]]
            if not prov.needs_key:
                rows.append([prov.name, "Always on", ", ".join(prov.types)])
            else:
                configured = prov.is_configured()
                rows.append([prov.name, "✓ configured" if configured else "— key missing",
                             ", ".join(prov.types)])
        st.dataframe(pd.DataFrame(rows, columns=["Feed", "Status", "Supports"]),
                     hide_index=True, height=260)

    with st.sidebar.expander("ℹ About", expanded=False):
        st.markdown(
            "Viper Intel correlates configurable TI feeds to produce an "
            "explainable **risk score (0-100)** and colour-coded verdict "
            "table for bulk IOC triage.\n\n"
            "**Scores**: 0-21 Clean · 22-39 Low · 40-59 Suspicious · 60+ Malicious")


def _refresh_providers(provs: Dict[str, object]) -> Dict[str, object]:
    """Re-read API keys into provider instances (cheap, re-reads session keys)."""
    for pid, p in provs.items():
        p.key = get_api_key(pid)
    return provs


# ---------------------------------------------------------------------------
# IOC intake helpers
# ---------------------------------------------------------------------------

def collect_iocs(uploaded, paste_text: str) -> List[Tuple[str, Optional[str]]]:
    items: List[Tuple[str, Optional[str]]] = []
    if uploaded is not None:
        raw = uploaded.read()
        for enc in (uploaded.type and "utf-8" or None, "utf-8-sig", "latin-1"):
            try:
                content = raw.decode(enc)
                break
            except Exception:
                continue
        items.extend(parse_bulk_file(content))
    if paste_text:
        items.extend(parse_bulk_file(paste_text))
    # drop empty and dedupe preserving order
    seen = set()
    out = []
    for value, ioc_type in items:
        value = value.strip()
        if not value or value.lower() in seen:
            continue
        seen.add(value.lower())
        out.append((value, ioc_type))
    return out


def _resolve_type(value: str, ioc_type: Optional[str]) -> Optional[str]:
    if ioc_type:
        return ioc_type
    return detect_ioc_type(value)


def _suggest_type_specific(value: str, guessed: Optional[str]) -> Optional[str]:
    """For hashes: upgrade generic guess to exact hash type."""
    if not guessed:
        return None
    if guessed in ("domain", "url"):
        return guessed
    if re.fullmatch(r"[0-9a-f]{32}", value, re.I):
        return "md5"
    if re.fullmatch(r"[0-9a-f]{40}", value, re.I):
        return "sha1"
    if re.fullmatch(r"[0-9a-f]{64}", value, re.I):
        return "sha256"
    return guessed


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def scan_single(value: str, ioc_type: Optional[str], provs: Dict[str, object],
                use_offline: bool = True) -> Optional[Dict]:
    value = value.strip()
    t = _suggest_type_specific(value, _resolve_type(value, ioc_type))
    if not t:
        return None
    ok, _, _ = validate_ioc(value, t)
    if not ok:
        return None

    configured = configured_providers_for_type(provs, t)
    if configured:
        results = []
        for prov in configured:
            results.append(prov.lookup(t, value))
        r = score_from_providers(value, results, ioc_type=t)
    elif use_offline:
        r = score_offline_only(value, ioc_type=t)
    else:
        r = RiskScoreResult(score=0, verdict="UNKNOWN", severity="?", factors=[],
                            explanation=["No TI feed configured for type {}.".format(t)])
        r.providers = []

    hits = [p for p in r.providers if p.available and p.verdict in ("malicious", "suspicious")]
    feeds_checked = len(r.providers)
    return {
        "ioc": value,
        "type": t,
        "verdict": r.verdict,
        "severity": r.severity,
        "score": r.score,
        "confidence": r.confidence,
        "entropy": r.entropy,
        "feeds_checked": feeds_checked,
        "feed_hits": len(hits),
        "summary": _summarize(r),
        "factors": [f.name for f in r.factors if f.points > 0],
        "mitre": r.mitre_techniques,
        "detail": r,
    }


def _summarize(r: RiskScoreResult) -> str:
    if r.explanation:
        text = "\n".join(r.explanation)
        return re.sub(r"\s+", " ", text)[:220]
    return ""


def scan_bulk(items: List[Tuple[str, Optional[str]]], max_workers: int = 8) -> List[Dict]:
    provs = _refresh_providers(st.session_state.get("providers") or build_providers())
    st.session_state["providers"] = provs
    rows: List[Dict] = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(scan_single, v, t, provs): (v, t) for v, t in items}
        for fut in as_completed(futs):
            try:
                row = fut.result()
                if row:
                    rows.append(row)
            except Exception:
                v, t = futs[fut]
                rows.append({"ioc": v, "type": t or "unknown", "verdict": "UNKNOWN",
                             "severity": "?", "score": 0, "confidence": 0.0,
                             "entropy": 0.0, "feeds_checked": 0, "feed_hits": 0,
                             "summary": "Scan failed", "factors": [], "mitre": []})
    rows.sort(key=lambda r: (-r["score"], r["ioc"]))
    return rows


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def colored_table(rows: List[Dict]) -> str:
    html = ['<table style="border-collapse:collapse;width:100%;font-size:14px;">']
    html.append('<tr style="background:#111827;color:#fff;">'
                '<th style="padding:8px;">Veritas</th><th>Indicator</th><th>Type</th>'
                '<th>Score</th><th>Confidence</th><th>Feeds</th><th>Signals</th>'
                '<th>Summary</th><th>Actions</th></tr>')
    for r in rows:
        verdict = r.get("verdict", "UNKNOWN")
        sc = r.get("score", 0)
        fe = r.get("feeds_checked", 0)
        hi = r.get("feed_hits", 0)
        html.append(
            '<tr style="border-bottom:1px solid #e5e7eb;">'
            '<td style="padding:6px;">{}</td>'
            '<td style="padding:6px;font-family:monospace;">{}</td>'
            '<td style="padding:6px;">{}</td>'
            '<td style="padding:6px;">{} {}</td>'
            '<td style="padding:6px;">{:.0%}</td>'
            '<td style="padding:6px;">{}/{}<br><span style="color:#6b7280;font-size:12px;">feeds / signals</span></td>'
            '<td style="padding:6px;">{}</td>'
            '<td style="padding:6px;">{}</td>'
            '<td style="padding:6px;">{}</td>'
            '</tr>'.format(
                VERDICT_HTML.get(verdict, VERDICT_HTML["UNKNOWN"]),
                r.get("ioc", ""),
                r.get("type", ""),
                _score_bar_html(sc),
                sc,
                r.get("confidence", 0.0),
                fe,
                hi,
                _detail_badge(r),
                r.get("summary", ""),
                _action_badges(r),
            )
        )
    html.append("</table>")
    return "".join(html)


def _detail_badge(r: Dict) -> str:
    details = r.get("detail")
    if not details:
        return ""
    info = r.get("type", "")
    return info


def _action_badges(r: Dict) -> str:
    return '<span style="color:#6b7280;">&#128065;</span>'


def verdict_df(rows: List[Dict]) -> pd.DataFrame:
    return pd.DataFrame([
        {"Indicator": r["ioc"], "Type": r["type"], "Verdict": r["verdict"],
         "Score": r["score"], "Confidence": r["confidence"],
         "Feeds": r["feeds_checked"], "Signals": r["feed_hits"],
         "Summary": r["summary"]}
        for r in rows
    ])


def render_verdict_chart(rows: List[Dict]) -> None:
    import pandas as pd
    df = pd.DataFrame([
        {"Verdict": r["verdict"], "Count": 1} for r in rows
    ])
    if df.empty:
        st.info("No results to chart.")
        return
    vc = df.groupby("Verdict")["Count"].count().reindex(
        ["MALICIOUS", "SUSPICIOUS", "LOW", "CLEAN"], fill_value=0)
    colors = {"MALICIOUS": "#b91c1c", "SUSPICIOUS": "#ea580c",
              "LOW": "#facc15", "CLEAN": "#16a34a"}
    chart = pd.DataFrame(
        {"verdict": vc.index, "count": vc.values,
         "color": [colors[v] for v in vc.index]})
    st.bar_chart(chart, x="verdict", y="count", color="color",
                 stack=False)


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

def render_dashboard(rows: List[Dict], source: str) -> None:
    col1, col2, col3, col4 = st.columns(4)
    st.markdown("### 📊 Dashboard")
    if not rows:
        st.info("Run a scan first, or upload IOCs on the **Bulk Analysis** tab.")
        return
    agg = aggregate_bulk_scores([{"ioc": r["ioc"], "verdict": r["verdict"]} for r in rows])
    m1 = col1.metric("Total Indicators", agg["total"])
    m2 = col1.metric("Malicious", agg["malicious"])
    m3 = col2.metric("Suspicious", agg["suspicious"])
    m4 = col2.metric("Low", agg["low"])
    m5 = col3.metric("Clean", agg["clean"])
    m6 = col3.metric("Avg. Score", round(sum(r["score"] for r in rows) / max(len(rows), 1), 1)
                     if rows else 0)
    col4.metric("Feeds Hit", sum(r["feed_hits"] for r in rows))
    avg = sum(r["confidence"] for r in rows) / max(len(rows), 1)
    col4.metric("Avg. Confidence", "{:.0%}".format(avg))

    st.subheader("Verdict Distribution")
    render_verdict_chart(rows)

    st.subheader("Critical Findings (top 10)")
    crit = [r for r in rows if r["verdict"] in ("MALICIOUS", "SUSPICIOUS")][:10]
    if crit:
        st.markdown(colored_table(crit), unsafe_allow_html=True)
    else:
        st.success("No malicious findings in the current dataset.")

    st.subheader("Full Dataset")
    st.dataframe(verdict_df(rows), hide_index=True, use_container_width=True)


def render_bulk() -> None:
    st.markdown("### 🚀 Bulk IOC Analysis")
    st.caption("Upload a CSV/TXT with one indicator per line, or paste below. "
               "Types are auto-detected (IPv4, IPv6, domain, URL, MD5/SHA-1/SHA-256, CVE). "
               "A second column can force the type (e.g. `sha256,abc…`).")
    c1, c2 = st.columns([1, 2])
    with c1:
        uploaded = st.file_uploader("Upload IOC list", type=["csv", "txt"], key="bulk_up")
        paste = st.text_area("Or paste IOCs (one per line)", height=140, key="bulk_paste")
    with c2:
        st.markdown("**Configured TI feeds for this run**")
        provs = _refresh_providers(st.session_state.get("providers") or build_providers())
        st.session_state["providers"] = provs
        rows_preview = []
        for pid, p in provs.items():
            rows_preview.append([p.name, "✓" if p.is_configured() or not p.needs_key else "—"])
        st.dataframe(pd.DataFrame(rows_preview, columns=["Feed", "Ready"]),
                     hide_index=True, use_container_width=True, height=220)

    run = st.button("🔍 Scan Now", type="primary", use_container_width=True)
    if run:
        items = collect_iocs(uploaded, paste or "")
        if not items:
            st.warning("No indicators found. Check the format and try again.")
            return
        with st.spinner("Scanning {} indicator(s) across configured TI feeds…".format(len(items))):
            rows = scan_bulk(items)
        st.session_state["bulk_results"] = rows
        st.session_state["bulk_source"] = source_name(uploaded, paste)
        st.session_state["scan_time"] = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows = st.session_state.get("bulk_results") or []
    if rows:
        src = st.session_state.get("bulk_source", "")
        st.markdown("### Results — {}".format(src))
        agg = aggregate_bulk_scores([{"ioc": r["ioc"], "verdict": r["verdict"]} for r in rows])
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Total", agg["total"])
        m2.metric("Malicious", agg["malicious"])
        m3.metric("Suspicious", agg["suspicious"])
        m4.metric("Low", agg["low"])
        m5.metric("Clean", agg["clean"])
        st.markdown(colored_table(rows), unsafe_allow_html=True)
        csv = verdict_df(rows).to_csv(index=False).encode()
        st.download_button("⬇ Download CSV", csv,
                           file_name="viperintel_results_{}.csv".format(
                               _dt.datetime.now().strftime("%Y%m%d_%H%M%S")),
                           mime="text/csv")

    st.divider()
    st.markdown("**Per-indicator drill-down**")
    detail_ioc = st.selectbox(
        "Choose an indicator to inspect the evidence, or use the Investigate tab",
        [r["ioc"] for r in rows] if rows else ["— run a scan first —"])
    if rows and detail_ioc in [r["ioc"] for r in rows]:
        for r in rows:
            if r["ioc"] == detail_ioc:
                render_single_result(r)


def source_name(uploaded, paste: str) -> str:
    if uploaded is not None:
        return uploaded.name
    if paste:
        paste = paste.strip()
        return "manual-paste ({} IOC)".format(len(paste.split("\n")))
    return "no-input"


def render_investigate() -> None:
    st.markdown("### 🔍 Investigate Single Indicator")
    ioc = st.text_input("Indicator (IP / domain / URL / hash / CVE)", key="inv_ioc")
    run = st.button("Analyze", key="inv_go", type="primary")
    provs = _refresh_providers(st.session_state.get("providers") or build_providers())
    st.session_state["providers"] = provs
    if not run:
        if not ioc:
            st.info("Enter any indicator to run a deep analysis across your configured feeds.")
        return
    if not ioc or not ioc.strip():
        st.warning("Please enter an indicator.")
        return
    with st.spinner("Querying configured TI feeds…"):
        row = scan_single(ioc.strip(), None, provs)
    if row is None:
        st.error("Unrecognised IOC format. Supported: IPv4/IPv6, domain, URL, "
                 "MD5/SHA-1/SHA-256 hash, CVE identifier.")
        return
    render_single_result(row)


def render_single_result(r: Dict) -> None:
    detail: RiskScoreResult = r["detail"]
    st.markdown("## {}".format(r["ioc"]))
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Verdict", detail.verdict)
    c2.metric("Risk Score", "{}/100".format(detail.score))
    c3.metric("Confidence", "{:.0%}".format(detail.confidence))
    c4.metric("Type", r["type"])
    entra = detail.entropy
    if entra:
        st.progress(min(entra / 6.0, 1.0), text="Shannon entropy {:.2f}".format(entra))

    st.subheader("Threat Feed Results")
    provs = detail.providers or []
    if not provs:
        st.info("No TI feeds were run. Configure API keys in the sidebar to scan "
                "this indicator type against live feeds.")
        return
    prov_rows = []
    for p in provs:
        if p.available:
            prov_rows.append([p.provider, VERDICT_HTML.get(p.verdict.upper(), "?"),
                              p.detections, p.confidence,
                              ", ".join(p.mitre) if p.mitre else "—"])
        else:
            prov_rows.append([p.provider, "not available",
                              "—", "—", p.reason if p.reason else "no key/data"])
    st.dataframe(pd.DataFrame(prov_rows, columns=["Feed", "Verdict", "Detections",
                                                  "Confidence", "Details"]),
                 hide_index=True, use_container_width=True)

    st.subheader("Structured intelligence")
    st.json(_stripped_detail(detail))

    st.subheader("Signal & Explanation")
    if detail.explanation:
        for line in detail.explanation:
            st.markdown(line)
    if detail.factors:
        with st.expander("View risk factors ({})".format(len(detail.factors))):
            for f in sorted(detail.factors, key=lambda x: x.points, reverse=True):
                st.markdown("- **+{} {}** — {}  *({})*".format(
                    f.points, f.name, f.reason, f.source))

    st.subheader("Recommended actions")
    for action in recommend_actions(detail):
        st.markdown("- {}".format(action))


def _stripped_detail(detail: RiskScoreResult) -> Dict:
    return {
        "score": detail.score,
        "verdict": detail.verdict,
        "severity": detail.severity,
        "confidence": detail.confidence,
        "entropy": detail.entropy,
        "mitre_techniques": detail.mitre_techniques,
        "factors": [{"name": f.name, "points": f.points, "reason": f.reason,
                     "source": f.source} for f in detail.factors],
    }


def recommend_actions(detail: RiskScoreResult) -> List[str]:
    out = []
    if detail.score >= 80:
        out.append("🛑 **Block**: add indicator to firewall/CDN/EDR blocklists and Sinkhole.")
        out.append("🚨 **Contain**: isolate affected hosts for forensic imaging.")
    if detail.score >= 40:
        out.append("🔍 **Hunt**: search SIEM for traffic to/from this indicator (last 90 days).")
    if detail.mitre_techniques:
        out.append("📚 **MITRE ATT&CK**: investigate techniques {}".format(
            ", ".join(detail.mitre_techniques)))
    if detail.entropy and detail.entropy >= 4.3:
        out.append("🧬 **DGA alert**: high entropy suggests algorithmically-generated domain - "
                   "check DNS logs for periodic generation.")
    if not out:
        out.append("✅ **No action required** — indicator appears benign across configured feeds.")
    return out


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

def main() -> None:
    _init_state()
    render_sidebar()

    tabs = ["📊 Dashboard", "🚀 Bulk Analysis", "🔍 Investigate"]
    page = st.tabs(tabs)
    rows = st.session_state.get("bulk_results") or []
    source = st.session_state.get("bulk_source", "")

    with page[0]:
        render_dashboard(rows, source)
    with page[1]:
        render_bulk()
    with page[2]:
        render_investigate()


if __name__ == "__main__":
    main()