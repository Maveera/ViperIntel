"""
Viper Intel - SOC Threat Intelligence Scanner

Bulk IP / Hash / Domain / URL / CVE analysis against configurable
threat-intelligence feeds (VirusTotal, AbuseIPDB, AlienVault OTX,
GreyNoise, Shodan, URLScan.io). Only feeds with an API key are queried.

No hardcoded secrets. API keys are supplied via the sidebar at runtime,
or via Streamlit secrets / environment variables for deployments.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import pickle
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
)

st.set_page_config(page_title="Viper Intel", layout="wide",
                   page_icon="🐍", initial_sidebar_state="expanded")

APP_TAG = "v3.0 API scan"
DATA_FILE = "viperintel_data.pkl"


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------

def _s(key: str, default=None):
    if key not in st.session_state:
        st.session_state[key] = default
    return st.session_state[key]


def _snapshot_save() -> None:
    try:
        with open(DATA_FILE, "wb") as f:
            pickle.dump({
                "rows": st.session_state.get("bulk_results", []),
                "source": st.session_state.get("bulk_source", ""),
            }, f, protocol=pickle.HIGHEST_PROTOCOL)
    except Exception:
        pass


def _snapshot_load() -> None:
    try:
        if os.path.exists(DATA_FILE) and not st.session_state.get("bulk_results"):
            with open(DATA_FILE, "rb") as f:
                snap = pickle.load(f)
            st.session_state["bulk_results"] = snap.get("rows", [])
            st.session_state["bulk_source"] = snap.get("source", "")
    except Exception:
        pass  # corrupt/old snapshot is ignored


def _snapshot_clear() -> None:
    st.session_state["bulk_results"] = []
    st.session_state["bulk_source"] = ""
    st.session_state["bulk_items"] = []
    try:
        os.remove(DATA_FILE)
    except OSError:
        pass


def _init_state() -> None:
    _s("api_keys", {})
    _s("providers", None)
    _s("bulk_results", [])
    _s("bulk_source", None)
    _s("bulk_items", [])
    _snapshot_load()


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


def _mask_key(key: str) -> str:
    key = str(key or "")
    if not key:
        return ""
    return "•" * min(len(key), 24)


def _load_config_silent() -> None:
    """Load saved (encrypted) keys once at startup; silently ignore problems."""
    try:
        from cryptography.fernet import Fernet
        if not (os.path.exists("config.json") and os.path.exists(".secret.key")):
            return
        with open(".secret.key", "rb") as f:
            fkey = Fernet(f.read())
        with open("config.json", "rb") as f:
            payload = fkey.decrypt(f.read())
        stored = json.loads(payload.decode())
        cur = dict(st.session_state.get("api_keys", {}))
        cur.update({k: v for k, v in stored.items() if v})
        st.session_state["api_keys"] = cur
        st.session_state["_keys_hash"] = hash(frozenset(cur.items()))
    except Exception:
        pass  # corrupt / missing config is handled by re-entering keys


def render_sidebar() -> None:
    st.sidebar.header("🐍 Viper Intel")
    st.sidebar.caption(APP_TAG + " | " + est.strftime("%Y-%m-%d %H:%M"))

    # restore saved keys once per session
    if not st.session_state.get("_cfg_loaded"):
        _load_config_silent()
        st.session_state["_cfg_loaded"] = True

    with st.sidebar.expander("🔑 API Key Configuration", expanded=True):
        st.caption("Add **only the feeds you need**. Keys are saved encrypted "
                   "and are always masked on screen → `config.json`. "
                   "For cloud, the matching env var / Streamlit secret "
                   "takes priority over any saved key.")
        keys = dict(st.session_state.get("api_keys", {}))
        configured = {p["id"] for p in PROVIDER_CATALOG
                      if p["needs_key"] and keys.get(p["id"])}
        pending = [p for p in PROVIDER_CATALOG
                   if p["needs_key"] and p["id"] not in configured]
        if pending:
            sel = st.selectbox(
                "Choose a feed to configure",
                [p["id"] for p in pending],
                format_func=lambda i: next(p["name"] for p in pending if p["id"] == i),
                key="add_sel")
            p_sel = next((p for p in pending if p["id"] == sel), None)
        else:
            p_sel = None
        if p_sel is not None:
            hint = os.getenv(p_sel["key_hint"], "") or keys.get(p_sel["id"], "")
            st.text_input(
                p_sel["name"], type="password", key="add_inp_" + p_sel["id"],
                value=hint, help="{} | {} | Press Enter to save".format(
                    p_sel["key_hint"], p_sel["free"]),
            )
            val = str(st.session_state.get("add_inp_" + p_sel["id"], "") or "").strip()
            if val:
                keys[p_sel["id"]] = val
            else:
                keys.pop(p_sel["id"], None)
        elif pending:
            st.caption("Select another feed above.")
        else:
            st.caption("All key-based feeds are already configured for this run. "
                       "Use 🗑 in **💾 Saved API Keys** to remove one first.")
        st.session_state["api_keys"] = keys

        # auto-save on change (e.g. after pressing Enter)
        kh = hash(frozenset(keys.items()))
        if keys and kh != st.session_state.get("_keys_hash"):
            _encrypt_save(keys)
            st.session_state["_keys_hash"] = kh
        if keys:
            st.caption("🔐  {} key(s) saved & encrypted → `config.json`".format(len(keys)))

    with st.sidebar.expander("💾 Saved API Keys", expanded=True):
        saved = st.session_state.get("api_keys", {})
        if not saved:
            st.caption("No keys saved yet. Add them above.")
        for p in PROVIDER_CATALOG:
            if not p["needs_key"]:
                continue
            key = saved.get(p["id"])
            if not key:
                continue
            reveal = st.session_state.get("reveal_" + p["id"], False)
            c1, c2, c3, c4 = st.columns([2.1, 1.7, 0.6, 0.6])
            c1.markdown("**{}**".format(p["name"]))
            c2.markdown("`{}`".format(key if reveal else _mask_key(key)),
                        unsafe_allow_html=True)
            if c3.button("👁", key="view_" + p["id"], help="Show / hide key"):
                st.session_state["reveal_" + p["id"]] = not reveal
                st.rerun()
            if c4.button("🗑", key="del_" + p["id"], help="Delete this key"):
                remaining = dict(st.session_state.get("api_keys", {}))
                remaining.pop(p["id"], None)
                st.session_state["api_keys"] = remaining
                st.session_state["_keys_hash"] = None
                st.session_state["providers"] = None
                _encrypt_save(remaining)
                st.rerun()
        if saved:
            if st.button("🗑 Clear all saved keys", key="clear_keys"):
                st.session_state["api_keys"] = {}
                st.session_state["_keys_hash"] = None
                st.session_state["providers"] = None
                try:
                    os.remove("config.json")
                    os.remove(".secret.key")
                except OSError:
                    pass
                st.rerun()

    with st.sidebar.expander("🛰 TI Feeds Active", expanded=False):
        provs = st.session_state.get("providers") or build_providers()
        provs = _refresh_providers(provs)
        rows = []
        for p in PROVIDER_CATALOG:
            prov = provs[p["id"]]
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

def scan_single(value: str, ioc_type: Optional[str], provs: Dict[str, object]) -> Optional[Dict]:
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
    else:
        r = RiskScoreResult(
            score=0, verdict="UNKNOWN", severity="?", factors=[],
            explanation=["No API key configured for type {} — add a key in the sidebar.".format(t)])
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


def _rows_to_json(rows: List[Dict]) -> str:
    def detail(d):
        return {
            "score": d.score,
            "verdict": d.verdict,
            "severity": d.severity,
            "confidence": d.confidence,
            "entropy": d.entropy,
            "mitre_techniques": d.mitre_techniques,
            "explanation": d.explanation,
            "factors": [{"name": f.name, "points": f.points, "reason": f.reason,
                         "source": f.source} for f in d.factors],
            "providers": [
                {"provider": p.provider, "available": p.available, "reason": p.reason,
                 "verdict": p.verdict, "risk_points": p.risk_points,
                 "detections": p.detections, "confidence": p.confidence,
                 "mitre": p.mitre, "data": p.data}
                for p in d.providers
            ],
        }

    out = []
    for r in rows:
        row = {k: v for k, v in r.items() if k != "detail"}
        row["detail"] = detail(r["detail"])
        out.append(row)
    return json.dumps({
        "app": APP_TAG,
        "exported_at": _dt.datetime.now().isoformat(),
        "count": len(rows),
        "results": out,
    }, indent=2, default=str)


VERDICT_PALETTE = {
    "MALICIOUS": "#b91c1c",
    "SUSPICIOUS": "#ea580c",
    "LOW": "#facc15",
    "CLEAN": "#16a34a",
}


def render_verdict_donut(rows: List[Dict]) -> None:
    """Verdict distribution: donut chart (CSS) with the bar chart on the right."""
    counts = {v: 0 for v in VERDICT_PALETTE}
    for r in rows:
        verdict = r.get("verdict", "UNKNOWN")
        if verdict in counts:
            counts[verdict] += 1
    total = sum(counts.values())
    if total == 0:
        st.caption("No results to chart.")
        return

    active = [v for v in VERDICT_PALETTE if counts[v] > 0]
    col_donut, col_bar = st.columns([1, 1], gap="large")

    with col_donut:
        st.markdown("**Donut — verdict share**")
        acc = 0.0
        segs = []
        for v in active:
            pct = counts[v] / total * 100
            segs.append("{} {}% {}%".format(VERDICT_PALETTE[v], round(acc, 2),
                                            round(acc + pct, 2)))
            acc += pct
        gradient = ", ".join(segs)

        html = ['<div style="display:flex;gap:28px;align-items:center;flex-wrap:wrap;">']
        html.append(
            '<div style="width:170px;height:170px;border-radius:50%;'
            'background:conic-gradient({});position:relative;">'
            '<div style="width:108px;height:108px;border-radius:50%;background:#fff;'
            'position:absolute;top:31px;left:31px;'
            'display:flex;align-items:center;justify-content:center;'
            'font-weight:700;font-size:20px;color:#111827;">{}</div>'
            '</div>'.format(gradient, total))
        html.append('<div>')
        for v in active:
            html.append(
                '<div style="display:flex;align-items:center;gap:10px;margin:6px 0;">'
                '<span style="width:14px;height:14px;border-radius:3px;background:{};"></span>'
                '<span style="color:#111827;">{} &nbsp; {} ({:.0f}%)</span>'
                '</div>'.format(VERDICT_PALETTE[v], v, counts[v], counts[v] / total * 100))
        html.append('</div></div>')
        st.markdown("".join(html), unsafe_allow_html=True)

    with col_bar:
        st.markdown("**Bar — verdict comparison**")
        chart = pd.DataFrame({
            "verdict": active,
            "count": [counts[v] for v in active],
            "color": [VERDICT_PALETTE[v] for v in active],
        })
        if not chart.empty:
            st.bar_chart(chart, x="verdict", y="count", color="color", stack=False,
                         height=280)


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

def render_common_results(rows: List[Dict]) -> None:
    """Dashboard content shared by the Dashboard tab and the Bulk Analysis results."""
    agg = aggregate_bulk_scores([{"ioc": r["ioc"], "verdict": r["verdict"]} for r in rows])
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Indicators", agg["total"])
    col1.metric("Malicious", agg["malicious"])
    col2.metric("Suspicious", agg["suspicious"])
    col2.metric("Low", agg["low"])
    col3.metric("Clean", agg["clean"])
    col3.metric("Avg. Score", round(sum(r["score"] for r in rows) / max(len(rows), 1), 1))
    col4.metric("Feeds Hit", sum(r["feed_hits"] for r in rows))
    col4.metric("Avg. Confidence", "{:.0%}".format(
        sum(r["confidence"] for r in rows) / max(len(rows), 1)))

    st.markdown("### Verdict Distribution")
    render_verdict_donut(rows)

    st.markdown("### Critical Findings (top 10)")
    crit = [r for r in rows if r["verdict"] in ("MALICIOUS", "SUSPICIOUS")][:10]
    if crit:
        st.markdown(colored_table(crit), unsafe_allow_html=True)
    else:
        st.success("No malicious findings in the current dataset.")

    st.markdown("### Full Dataset")
    st.dataframe(verdict_df(rows), hide_index=True, use_container_width=True)


def render_dashboard(rows: List[Dict], source: str) -> None:
    st.markdown("### 📊 Dashboard")
    if not rows:
        st.info("Run a scan first, or upload IOCs on the **Bulk Analysis** tab.")
        return
    render_common_results(rows)


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
            rows_preview.append([p.name, "✓ configured" if p.is_configured() else "— key missing"])
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
        st.session_state["bulk_items"] = items
        st.session_state["bulk_source"] = source_name(uploaded, paste)
        st.session_state["scan_time"] = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _snapshot_save()
        st.rerun()

    rows = st.session_state.get("bulk_results") or []
    if rows:
        src = st.session_state.get("bulk_source", "")
        st.markdown("### Results — {}".format(src))

        btn1, btn2, btn3, btn4, btn5 = st.columns(5)
        with btn1:
            refresh = st.button("🔄 Refresh Data", key="bulk_refresh", use_container_width=True)
        with btn2:
            reset = st.button("♻️ Reset Data", key="bulk_reset", use_container_width=True)
        with btn3:
            st.download_button(
                "💾 Save All (JSON)", data=_rows_to_json(rows).encode(),
                file_name="viperintel_full_{}.json".format(
                    _dt.datetime.now().strftime("%Y%m%d_%H%M%S")),
                mime="application/json", use_container_width=True, key="bulk_save_json")
        with btn4:
            csv = verdict_df(rows).to_csv(index=False).encode()
            st.download_button("⬇ Download CSV", csv,
                               file_name="viperintel_results_{}.csv".format(
                                   _dt.datetime.now().strftime("%Y%m%d_%H%M%S")),
                               mime="text/csv", use_container_width=True, key="bulk_dl_csv")
        with btn5:
            st.markdown("")
        if reset:
            _snapshot_clear()
            st.rerun()
        if refresh:
            items = st.session_state.get("bulk_items") or []
            if items:
                with st.spinner("Re-scanning {} indicator(s)…".format(len(items))):
                    refreshed = scan_bulk(items)
                st.session_state["bulk_results"] = refreshed
                st.session_state["scan_time"] = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                _snapshot_save()
                st.rerun()
            else:
                st.info("No previous scan to refresh — run a scan first.")

        # Dashboard-style summary (same content as the Dashboard tab)
        render_common_results(rows)

        st.markdown("### All Indicators — Details")
        st.markdown(colored_table(rows), unsafe_allow_html=True)

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


def _provider_detail_text(p) -> str:
    details = []
    data = getattr(p, "data", {}) or {}
    if p.provider == "VirusTotal":
        if p.data.get("reputation") not in (None, 0):
            details.append("reputation {}".format(p.data["reputation"]))
        if p.data.get("as_owner"):
            details.append(p.data["as_owner"])
        if p.data.get("reinforcement") or p.data.get("tags"):
            pass
    elif p.provider == "AbuseIPDB":
        details.append("{}% confidence".format(p.data.get("abuse_confidence_score", 0)))
        if p.data.get("isp"):
            details.append(p.data["isp"])
    elif p.provider == "AlienVault OTX":
        tags = p.data.get("tags", [])
        if tags:
            details.append(", ".join(tags[:4]))
        if p.data.get("malware_families"):
            details.append("families: " + ", ".join(p.data["malware_families"][:2]))
    elif p.provider == "GreyNoise":
        details.append(p.data.get("classification", "unknown"))
    elif p.provider == "Shodan":
        ports = p.data.get("ports", [])
        if ports:
            details.append("ports: " + ", ".join(map(str, ports[:6])))
        if p.data.get("vulnerabilities"):
            details.append(", ".join(p.data["vulnerabilities"][:2]))
    if p.mitre and not details:
        details.append(", ".join(p.mitre))
    return " | ".join(details) if details else "—"


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

    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("**Per-feed risk contribution**")
        risk_df = pd.DataFrame([{"Feed": p.provider, "Risk Points": p.risk_points}
                                for p in provs if p.available])
        if not risk_df.empty:
            st.bar_chart(risk_df.set_index("Feed"))
        else:
            st.caption("No feed data returned.")
    with col_b:
        vt = next((p for p in provs if p.provider == "VirusTotal" and p.available), None)
        if vt and vt.data and vt.data.get("total_engines"):
            d = vt.data
            eng_df = pd.DataFrame([{
                "Category": k.replace("_", " ").title(), "Engines": v}
                for k, v in {"malicious": d.get("malicious", 0),
                             "suspicious": d.get("suspicious", 0),
                             "undetected": d.get("undetected", 0),
                             "harmless": d.get("harmless", 0)}.items()
                if v > 0])
            if not eng_df.empty:
                st.markdown("**VirusTotal engine analysis ({}/{} voted)**".format(
                    d.get("malicious", 0) + d.get("suspicious", 0), d.get("total_engines", 0)))
                st.bar_chart(eng_df.set_index("Category"))
        else:
            st.caption("VirusTotal engine data not available.")

    st.markdown("**Feed details**")
    prov_rows = []
    for p in provs:
        if p.available:
            prov_rows.append([p.provider, VERDICT_HTML.get(p.verdict.upper(), "?"),
                              p.risk_points, p.confidence,
                              _provider_detail_text(p)])
        else:
            prov_rows.append([p.provider, "not available",
                              "—", "—", p.reason if p.reason else "no key/data"])
    st.dataframe(pd.DataFrame(prov_rows, columns=["Feed", "Verdict", "Risk Pts",
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

# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------

def render_footer() -> None:
    year = _dt.datetime.now().year
    st.markdown(
        '<div style="margin-top:48px;padding-top:14px;border-top:1px solid #e5e7eb;'
        'text-align:center;color:#6b7280;font-size:13px;">'
        '\u00a9 {} All Rights Reserved | Maveera</div>'.format(year),
        unsafe_allow_html=True)


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

    render_footer()


if __name__ == "__main__":
    main()