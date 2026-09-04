import streamlit as st
import pandas as pd
import json
import time
import re
from datetime import datetime, timezone

from core.detector import (
    detect_ioc_type,
    validate_ioc,
    IOC_TYPES,
    IOC_LABELS,
    parse_bulk_file,
    is_public_ip,
)
from core.risk_engine import score_ioc, aggregate_bulk_scores
from core.ai_engine import analyze, render_markdown_report
from core.offline_intel import DEFAULT_REGIONS, ORGANIC_IP_POOL

# ================= PAGE CONFIG & METADATA =================
st.set_page_config(
    page_title="Viper Intel - SOC Threat Intelligence",
    page_icon="\U0001f40d",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ================= DARK SOC THEME =================
st.markdown(
    """
    <style>
    :root {
        --viper-bg: #0a0e14;
        --viper-panel: #111722;
        --viper-border: #1f2937;
        --viper-accent: #00ffcc;
        --viper-green: #00ff88;
        --viper-amber: #ffaa00;
        --viper-red: #ff4444;
        --viper-text: #e5e7eb;
    }
    .stApp {
        background-color: #0a0e14;
        color: #e5e7eb;
    }
    .block-container { padding-top: 1.2rem; padding-bottom: 4rem; }
    h1, h2, h3 { color: #00ffcc !important; }
    .viper-header {
        display: flex; align-items: center; gap: 14px;
        padding: 10px 16px; margin-bottom: 10px;
        background: rgba(17,23,34,0.8); border: 1px solid #1f2937;
        border-radius: 10px;
    }
    .viper-header .logo { font-size: 2.1rem; }
    .viper-header .title { font-size: 1.45rem; font-weight: 800; color: #00ffcc; letter-spacing: 0.5px; }
    .viper-header .subtitle { font-size: 0.82rem; color: #94a3b8; margin-top: 2px; }

    .viper-card {
        background: #111722; border: 1px solid #1f2937; border-radius: 10px;
        padding: 16px 18px; margin-bottom: 12px;
    }
    .viper-card .card-label { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 1px; color: #94a3b8; }
    .viper-card .card-value { font-size: 1.9rem; font-weight: 800; margin-top: 2px; }
    .viper-card .card-sub { font-size: 0.78rem; color: #64748b; }

    .verdict-clean { color:#00ff88; }
    .verdict-low { color:#88ff00; }
    .verdict-medium { color:#ffaa00; }
    .verdict-high { color:#ff7733; }
    .verdict-critical { color:#ff4444; }

    .risk-badge {
        display:inline-block; padding:6px 14px; border-radius:6px;
        font-weight:700; font-size:0.95rem; border:1px solid;
    }
    .stButton>button {
        background:#111722; color:#00ffcc; border:1px solid #00ffcc;
        border-radius:6px; font-weight:600;
    }
    .stButton>button:hover { background:#0f1b2a; color:#66ffe0; border-color:#66ffe0; }
    .stTabs [data-baseweb="tab-list"] { gap: 6px; }
    .stTabs [data-baseweb="tab"] {
        background:#111722; color:#94a3b8; border:1px solid #1f2937;
        padding:6px 14px; border-radius:6px;
    }
    .stTabs [aria-selected="true"] { color:#00ffcc !important; border-color:#00ffcc !important; }
    div[data-testid="stMetric"] {
        background:#111722; border:1px solid #1f2937; border-radius:10px;
        padding:12px 16px;
    }
    div[data-testid="stMetricValue"] { color:#00ffcc; }
    footer { visibility: hidden; }
    [data-testid="stSidebar"] { background:#0d1219 !important; border-right:1px solid #1f2937; }
    [data-testid="stSidebar"] * { color:#cbd5e1; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ================= SESSION STATE INIT =================
if "page" not in st.session_state:
    st.session_state.page = "Dashboard"
if "history" not in st.session_state:
    st.session_state.history = []
if "watchlist" not in st.session_state:
    st.session_state.watchlist = []
if "last_investigation" not in st.session_state:
    st.session_state.last_investigation = None
if "bulk_results" not in st.session_state:
    st.session_state.bulk_results = None

NAV_ITEMS = [
    "Dashboard",
    "Investigate",
    "Threat Map",
    "Bulk Analysis",
    "Watchlist",
    "Investigation History",
]

# ================= NAVIGATION =================
with st.sidebar:
    st.markdown("## \U0001f40d Viper Intel")
    st.markdown("**SOC Threat Intelligence Suite**")
    st.markdown("---")

    selection = st.radio(
        "Navigation",
        NAV_ITEMS,
        key="nav",
        label_visibility="collapsed",
    )
    st.session_state.page = selection

    st.markdown("---")
    st.markdown("### Session")
    total_scans = len(st.session_state.history)
    st.write("Scans this session: **{}**".format(total_scans))
    watch_count = len(st.session_state.watchlist)
    st.write("Watchlist entries: **{}**".format(watch_count))

    st.markdown("---")
    if st.button("\U0001f9f9 Clear Session Data", use_container_width=True):
        st.session_state.history = []
        st.session_state.watchlist = []
        st.session_state.last_investigation = None
        st.session_state.bulk_results = None
        st.rerun()

    st.caption("All analysis runs 100% locally and offline. No external APIs or data are used.")

# ================= HEADER =================
st.markdown(
    """
    <div class="viper-header">
        <div class="logo">\U0001f40d</div>
        <div>
            <div class="title">VIPER INTEL</div>
            <div class="subtitle">SOC Threat Intelligence &amp; IOC Investigation Platform (Offline Engine)</div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ================= HELPERS =================
def verdict_color(verdict: str) -> str:
    mapping = {
        "CLEAN": "verdict-clean",
        "LOW": "verdict-low",
        "SUSPICIOUS": "verdict-medium",
        "MALICIOUS": "verdict-critical",
    }
    return mapping.get(verdict, "verdict-medium")


def verdict_hex(verdict: str) -> str:
    mapping = {
        "CLEAN": "#00ff88",
        "LOW": "#88ff00",
        "SUSPICIOUS": "#ffaa00",
        "MALICIOUS": "#ff4444",
    }
    return mapping.get(verdict, "#ffaa00")


def record_to_history(value, ioc_type, risk):
    factors_out = []
    for f in risk.factors:
        factors_out.append({
            "name": f.name,
            "points": f.points,
            "reason": f.reason,
            "tier": f.tier,
        })
    st.session_state.history.insert(0, {
        "ts": datetime.now(timezone.utc).isoformat() + "Z",
        "time": datetime.now().strftime("%H:%M:%S"),
        "ioc": value,
        "type": ioc_type,
        "score": risk.score,
        "verdict": risk.verdict,
        "severity": risk.severity,
        "factors": factors_out,
        "mitre": list(risk.mitre_techniques),
        "risk_json": risk.to_dict(),
    })
    st.session_state.last_investigation = st.session_state.history[0]


def render_score_header(value, ioc_type, risk, ai=None):
    cols = st.columns(5)
    cols[0].markdown(
        '<div class="viper-card"><div class="card-label">Risk Score</div>'
        '<div class="card-value">{}/100</div></div>'.format(risk.score),
        unsafe_allow_html=True,
    )
    cols[1].markdown(
        '<div class="viper-card"><div class="card-label">Verdict</div>'
        '<div class="card-value {}">{}</div></div>'.format(verdict_color(risk.verdict), risk.verdict),
        unsafe_allow_html=True,
    )
    cols[2].markdown(
        '<div class="viper-card"><div class="card-label">Severity</div>'
        '<div class="card-value" style="color:{};">{}</div></div>'.format(
            verdict_hex(risk.verdict) if risk.verdict == "MALICIOUS" else "#94a3b8",
            risk.severity,
        ),
        unsafe_allow_html=True,
    )
    cols[3].markdown(
        '<div class="viper-card"><div class="card-label">Confidence</div>'
        '<div class="card-value" style="color:#00ffcc;">{:.0%}</div></div>'.format(risk.confidence),
        unsafe_allow_html=True,
    )
    cols[4].markdown(
        '<div class="viper-card"><div class="card-label">Type</div>'
        '<div class="card-value" style="color:#94a3b8; font-size:1.0rem;">{}</div></div>'.format(
            IOC_LABELS.get(ioc_type, ioc_type.upper())),
        unsafe_allow_html=True,
    )


def expandable_analysis(entry):
    with st.expander("Open Investigation ({} pts)".format(entry["score"]), expanded=False):
        st.markdown("**IOC:** `{}`  |  **Type:** {}  |  **Time:** {}".format(
            entry["ioc"], entry["type"], entry.get("time", "")))
        st.write("**Verdict:** {}  |  **Score:** {}/100  |  **Severity:** {}".format(
            entry["verdict"], entry["score"], entry.get("severity", "")))
        if entry.get("factors"):
            st.markdown("**Risk Factors:**")
            for f in entry["factors"]:
                st.write("- {} ({} pts): {}".format(f["name"], f["points"], f["reason"]))
        if entry.get("mitre"):
            st.markdown("**MITRE ATT&CK:** {}".format(", ".join(entry["mitre"])))


# ================= PAGE: DASHBOARD =================
def page_dashboard():
    st.subheader("\U0001f4ca Session Dashboard")
    history = st.session_state.history

    total = len(history)
    malicious = sum(1 for h in history if h["verdict"] == "MALICIOUS")
    suspicious = sum(1 for h in history if h["verdict"] == "SUSPICIOUS")
    low = sum(1 for h in history if h["verdict"] == "LOW")
    clean = sum(1 for h in history if h["verdict"] == "CLEAN")

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Scans", total)
    c2.metric("Malicious", malicious, delta_color="inverse")
    c3.metric("Suspicious", suspicious, delta_color="inverse")
    c4.metric("Low Risk", low)
    c5.metric("Clean", clean, delta_color="normal")

    st.markdown("---")

    left, right = st.columns([3, 2])

    with left:
        st.markdown("### Recent Session Activity")
        if history:
            df = pd.DataFrame([
                {"Time": h["time"], "IOC": h["ioc"], "Type": h["type"],
                 "Score": h["score"], "Verdict": h["verdict"]}
                for h in history[:20]
            ])
            df["Verdict"] = df["Verdict"].apply(
                lambda v: '<span style="color:{};">{}</span>'.format(verdict_hex(v), v))
            st.write(df.to_html(index=False, escape=False), unsafe_allow_html=True)
        else:
            st.info("No investigations yet. Navigate to **Investigate** to run your first local IOC analysis.")

    with right:
        st.markdown("### Verdict Distribution")
        if total:
            vdata = pd.DataFrame([
                {"Verdict": "Malicious", "Count": malicious},
                {"Verdict": "Suspicious", "Count": suspicious},
                {"Verdict": "Low", "Count": low},
                {"Verdict": "Clean", "Count": clean},
            ])
            st.bar_chart(vdata.set_index("Verdict"))
        else:
            st.caption("No data to visualize yet.")

    st.markdown("---")
    st.markdown("### Quick Start")
    st.caption("Enter an IOC in the **Investigate** tab to compute an explainable, offline Viper Risk Score and get a deterministic SOC analysis.")


# ================= PAGE: INVESTIGATE =================
def page_investigate():
    st.subheader("\U0001f50d IOC Investigation")

    col_in, col_sel = st.columns([3, 1])
    with col_in:
        ioc_input = st.text_input(
            "Indicator",
            placeholder="e.g. 185.220.101.5, evil-domain.xyz, CVE-2021-44228, a@"+"b.com ...",
            label_visibility="collapsed",
        )
    with col_sel:
        type_select = st.selectbox(
            "Type (optional)",
            ["Auto Detect"] + IOC_TYPES,
            label_visibility="collapsed",
        )

    selected_type = None if type_select == "Auto Detect" else type_select

    if st.button("\U0001f4a1 Investigate IOC", type="primary", use_container_width=True):
        if not ioc_input.strip():
            st.error("Please enter an IOC value.")
        else:
            ok, detected, err = validate_ioc(ioc_input, selected_type)
            if not ok:
                st.error("Invalid IOC: {}".format(err))
            else:
                _run_investigation(ioc_input, detected)


def _run_investigation(value, detected):
    risk = score_ioc(value, detected)
    ai = analyze(value, risk)
    record_to_history(value, detected, risk)
    _render_investigation_result(value, detected, risk, ai)


def _render_investigation_result(value, detected, risk, ai):
    st.markdown("---")
    render_score_header(value, detected, risk, ai)

    st.markdown("---")
    st.markdown("### Why is this IOC risky?")
    if risk.factors:
        for f in sorted([x for x in risk.factors if x.points > 0], key=lambda x: x.points, reverse=True):
            st.markdown(
                '<div class="viper-card" style="display:flex;justify-content:space-between;padding:10px 14px;">'
                '<span><b>{}</b> &mdash; {}</span>'
                '<span style="color:{};font-weight:700;">+{}</span></div>'.format(
                    f.name, f.reason, verdict_hex(risk.verdict), f.points),
                unsafe_allow_html=True,
            )
    else:
        st.success("No suspicious indicators identified for this IOC.")

    if risk.entropy:
        st.caption("Shannon entropy: {:.2f}".format(risk.entropy))

    st.markdown("---")
    tabs = st.tabs(["SOC Analyst", "MITRE ATT&CK", "Report"])

    with tabs[0]:
        st.markdown("#### Executive Summary")
        st.write(ai.executive_summary)

        st.markdown("#### Technical Analysis")
        st.write(ai.technical_analysis)

        st.markdown("#### Why Suspicious")
        for w in ai.why_suspicious:
            st.markdown("- {}".format(w))

        st.markdown("#### Recommended SOC Actions")
        for a in ai.recommended_soc_actions:
            st.markdown("- {}".format(a))

        st.download_button(
            "Download SOC Analysis (Markdown)",
            render_markdown_report(value, risk, ai),
            file_name="viper_report_{}.md".format(re.sub(r"[^a-zA-Z0-9]", "_", value)),
            mime="text/markdown",
        )

    with tabs[1]:
        if ai.mitre_attack_mapping:
            m_df = pd.DataFrame([{
                "Technique": m["id"],
                "Name": m["name"],
                "Tactic": m["tactic"],
                "Description": m["description"],
            } for m in ai.mitre_attack_mapping])
            st.dataframe(m_df, use_container_width=True, hide_index=True)
        else:
            st.info("No MITRE ATT&CK techniques associated with this indicator.")

        st.markdown("#### Key Mapping Insights")
        for m in ai.mitre_attack_mapping:
            st.markdown("**{} - {}** ({})".format(m["id"], m["name"], m["tactic"]))
            st.caption(m["description"])

    with tabs[2]:
        st.markdown(render_markdown_report(value, risk, ai))


# ================= PAGE: THREAT MAP =================
def page_threat_map():
    st.subheader("\U0001f30d Threat Map - Spatial Distribution")

    source = st.radio(
        "Data Source",
        ["IP-based inputs", "Entropy-mapped regions"],
        horizontal=True,
    )

    points = []

    if source == "IP-based inputs":
        pool = []
        for h in st.session_state.history:
            if h["type"] in ("ipv4", "ipv6") and is_public_ip(h["ioc"]):
                pool.append((h["ioc"], h["score"], h["verdict"]))
        for ip, score, verdict in pool:
            lat, lon, label = _ip_to_coords(ip)
            points.append({
                "lat": lat, "lon": lon, "label": label or ip,
                "ip": ip, "score": score, "verdict": verdict,
            })
        for ip, lat, lon, label in ORGANIC_IP_POOL:
            points.append({
                "lat": lat, "lon": lon, "label": label, "ip": ip,
                "score": 30, "verdict": "reference",
            })
    else:
        handled = set()
        regions = DEFAULT_REGIONS
        for i, region in enumerate(regions):
            jitter = ((i * 37) % 10 - 5) * 0.4
            points.append({
                "lat": region["lat"] + jitter * 0.1,
                "lon": region["lon"] + jitter * 0.1,
                "label": region["label"],
                "ip": "-",
                "score": 55 if i % 2 == 0 else 25,
                "verdict": "SUSPICIOUS" if i % 2 == 0 else "LOW",
            })

    if not points:
        st.info("No spatial indicators yet. Investigate an IP first, or view the entropy-mapped regional view.")
        return

    df = pd.DataFrame(points)

    st.caption("{} points rendered across {} regions.".format(len(df), df["label"].nunique()))
    left, right = st.columns([2, 1])
    with left:
        try:
            import pydeck as pdk
            layer = pdk.Layer(
                "ScatterplotLayer",
                data=df,
                get_position="[lon, lat]",
                get_fill_color="[200, 30, 30, 160]",
                get_radius=120000,
                pickable=True,
            )
            tooltip = {"html": "<b>{label}</b><br/>IP: {ip} | Score: {score} | {verdict}"}
            view_state = pdk.ViewState(latitude=20, longitude=0, zoom=1)
            deck = pdk.Deck(
                layers=[layer],
                initial_view_state=view_state,
                tooltip=tooltip,
                map_style="dark",
            )
            st.pydeck_chart(deck)
        except Exception:
            st.info("PyDeck render unavailable; showing table instead.")
            st.dataframe(df, use_container_width=True, hide_index=True)

    with right:
        st.markdown("### List View")
        st.dataframe(df[["label", "ip", "score", "verdict"]], use_container_width=True, hide_index=True)


def _ip_to_coords(ip):
    if not is_public_ip(ip):
        return 0.0, 0.0, ip
    octets = ip.split(".")
    try:
        lat = -90 + (int(octets[0]) * 37) % 160
        lon = -180 + (int(octets[1]) * 53) % 340
    except Exception:
        lat, lon = 0.0, 0.0
    return round(lat, 2), round(lon, 2), ip


# ================= PAGE: BULK ANALYSIS =================
def page_bulk_analysis():
    st.subheader("\U0001f4e4 Bulk IOC Analysis")
    st.caption("Upload a CSV or TXT file. Each line may be `type,value` or a bare indicator.")

    upload = st.file_uploader("Upload CSV / TXT", type=["csv", "txt"])
    col_mode, col_go = st.columns([2, 1])
    with col_mode:
        mode = st.radio("Detection mode", ["Auto Detect Type", "Use column type"], horizontal=True)
    with col_go:
        st.markdown("")
        run_bulk = st.button("\U000026A1 Run Bulk Analysis", type="primary", use_container_width=True)

    if run_bulk:
        if upload is None:
            st.error("Please upload a file first.")
        else:
            raw = upload.getvalue().decode("utf-8", errors="replace")
            items = parse_bulk_file(raw)
            if not items:
                st.error("No usable indicators found in the file.")
                return

            results = []
            with st.spinner("Running offline analysis on {} indicators...".format(len(items))):
                for value, forced_type in items:
                    if forced_type:
                        ok, detected, err = validate_ioc(value, forced_type)
                    else:
                        ok, detected, err = validate_ioc(value, None)
                    if not ok:
                        results.append({
                            "IOC": value, "Type": "unknown",
                            "Score": 0, "Verdict": "INVALID", "Confidence": 0.0,
                            "Reason": err,
                        })
                    else:
                        risk = score_ioc(value, detected)
                        results.append({
                            "IOC": value, "Type": detected,
                            "Score": risk.score, "Verdict": risk.verdict,
                            "Confidence": risk.confidence,
                            "Reason": "; ".join(f.reason for f in risk.factors if f.points > 0) or "No signals",
                            "Mitre": ", ".join(risk.mitre_techniques),
                        })

            df = pd.DataFrame(results)
            st.session_state.bulk_results = df

    if st.session_state.bulk_results is not None:
        df = st.session_state.bulk_results
        stats = aggregate_bulk_scores(df.rename(columns={
            "IOC": "ioc", "Type": "type", "Score": "score",
            "Verdict": "verdict", "Confidence": "confidence",
        }).to_dict("records"))

        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total", stats["total"])
        c2.metric("Malicious", stats["malicious"])
        c3.metric("Suspicious", stats["suspicious"])
        c4.metric("Low", stats["low"])
        c5.metric("Clean", stats["clean"])

        st.dataframe(df, use_container_width=True, hide_index=True)

        st.download_button(
            "Download Results (CSV)",
            df.to_csv(index=False),
            file_name="viper_bulk_results.csv",
            mime="text/csv",
        )


# ================= PAGE: WATCHLIST =================
def page_watchlist():
    st.subheader("\U0001f6a9 Watchlist (Session)")
    st.caption("Monitored IOCs tracked in memory for the current session.")

    entry_input = st.text_input(
        "Add IOC to watchlist",
        placeholder="Enter an IOC to monitor...",
        key="watch_input",
    )
    add_col, _ = st.columns([1, 3])
    with add_col:
        if st.button("\u2795 Add to Watchlist", use_container_width=True):
            if entry_input.strip():
                ok, detected, err = validate_ioc(entry_input)
                if not ok:
                    st.error("Invalid IOC: {}".format(err))
                else:
                    risk = score_ioc(entry_input, detected)
                    existing = [w for w in st.session_state.watchlist if w["ioc"] == entry_input.strip()]
                    if existing:
                        st.info("Already in watchlist.")
                    else:
                        st.session_state.watchlist.insert(0, {
                            "ioc": entry_input.strip(),
                            "type": detected,
                            "score": risk.score,
                            "verdict": risk.verdict,
                            "added": datetime.now().strftime("%Y-%m-%d %H:%M"),
                            "status": "monitoring",
                        })
                        st.rerun()

    if st.session_state.watchlist:
        wdf = pd.DataFrame(st.session_state.watchlist)
        st.dataframe(wdf[["ioc", "type", "score", "verdict", "added", "status"]],
                     use_container_width=True, hide_index=True)

        st.markdown("### Manage Watchlist")
        w_names = [w["ioc"] for w in st.session_state.watchlist]
        remove_val = st.selectbox("Remove IOC", ["Select..."] + w_names)
        if remove_val != "Select..." and st.button("\U0001f5d1 Remove", type="secondary"):
            st.session_state.watchlist = [w for w in st.session_state.watchlist if w["ioc"] != remove_val]
            st.rerun()
    else:
        st.info("Watchlist is empty. Add IOCs to monitor reputation changes across the session.")


# ================= PAGE: INVESTIGATION HISTORY =================
def page_history():
    st.subheader("\U0001f4c1 Investigation History (Session)")
    history = st.session_state.history

    if not history:
        st.info("No investigations in this session yet.")
        return

    total = len(history)
    malicious = sum(1 for h in history if h["verdict"] == "MALICIOUS")
    suspicious = sum(1 for h in history if h["verdict"] == "SUSPICIOUS")

    c1, c2, c3 = st.columns(3)
    c1.metric("Total", total)
    c2.metric("Malicious", malicious)
    c3.metric("Suspicious", suspicious)

    st.markdown("---")
    st.markdown("### Session Records")

    hdf = pd.DataFrame([{
        "Time": h["time"],
        "IOC": h["ioc"],
        "Type": h["type"],
        "Score": h["score"],
        "Verdict": h["verdict"],
        "Severity": h["severity"],
    } for h in history])

    event = st.dataframe(
        hdf,
        use_container_width=True,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
    )

    st.markdown("### Reopen Investigation")
    options = ["Select..."] + [h["ioc"] for h in history]
    sel = st.selectbox("Choose an investigation", options)
    if sel != "Select...":
        entry = next((h for h in history if h["ioc"] == sel), None)
        if entry:
            expandable_analysis(entry)


# ================= ROUTER =================
if st.session_state.page == "Dashboard":
    page_dashboard()
elif st.session_state.page == "Investigate":
    page_investigate()
elif st.session_state.page == "Threat Map":
    page_threat_map()
elif st.session_state.page == "Bulk Analysis":
    page_bulk_analysis()
elif st.session_state.page == "Watchlist":
    page_watchlist()
elif st.session_state.page == "Investigation History":
    page_history()

# ================= FOOTER =================
st.markdown(
    """
    <div style="position:fixed;bottom:0;left:0;right:0;text-align:center;
    padding:8px;background:#0d1219;border-top:1px solid #1f2937;color:#64748b;font-size:0.75rem;">
    Viper Intel SOC Edition &mdash; 100% Local Offline Analysis &middot; No external data &middot; In-session only
    </div>
    """,
    unsafe_allow_html=True,
)