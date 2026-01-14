import streamlit as st
import requests
import pandas as pd
import time
import folium
from streamlit_folium import st_folium

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="ViperIntel Pro | By Maveera",
    page_icon="🛡️",
    layout="wide"
)

# ---------------- GLOBAL TI CATALOG ----------------
ALL_TI_ENGINES = [
    # Reputation / Abuse
    "AbuseIPDB",
    "IPQualityScore",
    "GreyNoise",
    "Spamhaus",
    "Project Honey Pot",
    "IPInfo",
    "MaxMind",
    "Spur.us",

    # Malware / IOC
    "VirusTotal",
    "Hybrid Analysis",
    "MalwareBazaar",
    "Any.Run",
    "Joe Sandbox",

    # Open Feeds
    "AlienVault OTX",
    "MISP",
    "OpenPhish",
    "PhishTank",
    "URLhaus",
    "CIRCL",

    # Enterprise TI
    "Recorded Future",
    "Cisco Talos",
    "IBM X-Force",
    "Microsoft Defender TI",
    "CrowdStrike Falcon",
    "Kaspersky TI",
    "Check Point ThreatCloud"
]

# APIs actually implemented
SUPPORTED_TI = ["AbuseIPDB", "VirusTotal"]

MAX_VISIBLE_TI = 3

# ---------------- SESSION STATE ----------------
if "active_ti" not in st.session_state:
    st.session_state.active_ti = ALL_TI_ENGINES[:MAX_VISIBLE_TI]

for ti in ALL_TI_ENGINES:
    st.session_state.setdefault(f"{ti}_key", "")
    st.session_state.setdefault(f"{ti}_locked", False)

st.session_state.setdefault("scan_results", None)

# ---------------- STYLES ----------------
st.markdown("""
<style>
.stApp { background-color: #0a0e14; color: #e0e6ed; }
footer { visibility: hidden; }

.key-freeze-row {
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 8px;
    padding: 8px;
    color: #8b949e;
    letter-spacing: 2px;
    font-family: monospace;
}

.custom-footer {
    position: fixed;
    left: 0;
    bottom: 0;
    width: 100%;
    background-color: rgba(10,14,20,0.95);
    color: #94a3b8;
    text-align: center;
    padding: 14px;
    border-top: 1px solid #1f2937;
    z-index: 1000;
}
</style>
""", unsafe_allow_html=True)

# ---------------- HEADER ----------------
st.title("🛡️ ViperIntel Pro")
st.markdown("#### Universal Threat Intelligence & Forensic Aggregator")

# ---------------- SIDEBAR ----------------
with st.sidebar:
    st.markdown("## 🛡️ TI Command Center")
    st.subheader("🔑 Global API Configuration")

    def api_input(ti):
        if not st.session_state[f"{ti}_locked"]:
            val = st.text_input(f"{ti} Key", type="password", key=f"inp_{ti}")
            if val:
                st.session_state[f"{ti}_key"] = val
                st.session_state[f"{ti}_locked"] = True
                st.rerun()
        else:
            col_mask, col_edit = st.columns([3, 1])
            with col_mask:
                st.markdown("<div class='key-freeze-row'>••••••••••••••••</div>", unsafe_allow_html=True)
            with col_edit:
                if st.button("Edit", key=f"edit_{ti}"):
                    st.session_state[f"{ti}_locked"] = False
                    st.rerun()

    # Show active TI (max 3)
    for ti in st.session_state.active_ti:
        api_input(ti)

    # Add more TI
    remaining_ti = [ti for ti in ALL_TI_ENGINES if ti not in st.session_state.active_ti]
    if remaining_ti:
        st.divider()
        add_ti = st.selectbox("➕ Add Threat Intelligence Source", ["Select TI"] + remaining_ti)
        if add_ti != "Select TI":
            st.session_state.active_ti.append(add_ti)
            st.rerun()

# ---------------- FILE UPLOAD ----------------
uploaded_file = st.file_uploader("Upload CSV (IPs in first column)", type=["csv"])

# ---------------- EXECUTE SCAN ----------------
if st.button("⚡ EXECUTE DEEP SCAN"):
    active_supported = [
        ti for ti in st.session_state.active_ti
        if ti in SUPPORTED_TI and st.session_state[f"{ti}_key"]
    ]

    if not active_supported:
        st.error("❌ No supported TI API configured. Add at least one valid API (AbuseIPDB or VirusTotal).")
    elif not uploaded_file:
        st.error("❌ Please upload a CSV file with IP addresses.")
    else:
        df = pd.read_csv(uploaded_file, header=None)
        ips = df.iloc[:, 0].astype(str).str.strip().tolist()

        results = []
        progress = st.progress(0)
        status = st.empty()

        for i, ip in enumerate(ips):
            status.markdown(f"🔍 **Analyzing:** `{ip}` ({i+1}/{len(ips)})")

            intel = {
                "IP": ip,
                "Status": "Clean",
                "Abuse Score": 0,
                "VT Hits": 0,
                "Lat": None,
                "Lon": None
            }

            if "AbuseIPDB" in active_supported:
                try:
                    r = requests.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        headers={"Key": st.session_state["AbuseIPDB_key"], "Accept": "application/json"},
                        params={"ipAddress": ip},
                        timeout=10
                    ).json()
                    data = r.get("data", {})
                    intel["Abuse Score"] = data.get("abuseConfidenceScore", 0)
                    intel["Lat"], intel["Lon"] = data.get("latitude"), data.get("longitude")
                except:
                    pass

            if "VirusTotal" in active_supported:
                try:
                    r = requests.get(
                        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                        headers={"x-apikey": st.session_state["VirusTotal_key"]},
                        timeout=10
                    ).json()
                    intel["VT Hits"] = r["data"]["attributes"]["last_analysis_stats"].get("malicious", 0)
                except:
                    pass

            if intel["Abuse Score"] > 25 or intel["VT Hits"] > 0:
                intel["Status"] = "🚨 Malicious"

            results.append(intel)
            progress.progress((i + 1) / len(ips))
            time.sleep(0.1)

        st.session_state.scan_results = pd.DataFrame(results)
        status.empty()

# ---------------- RESULTS ----------------
if st.session_state.scan_results is not None:
    res = st.session_state.scan_results.copy()
    res.index = res.index + 1
    res.index.name = "S.No"

    st.subheader("📋 Intelligence Report")
    st.dataframe(res.drop(columns=["Lat", "Lon"]), use_container_width=True)

    st.subheader("🌍 Geographic Threat Origin")
    m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
    for _, r in res.iterrows():
        if r["Lat"] and r["Lon"]:
            folium.CircleMarker(
                [r["Lat"], r["Lon"]],
                radius=7,
                color="red" if r["Status"] != "Clean" else "#00ffcc",
                fill=True
            ).add_to(m)
    st_folium(m, width=1200, height=450)

# ---------------- FOOTER ----------------
st.markdown("""
<div class="custom-footer">
© 2026 <b>ViperIntel Pro</b> | All Rights Reserved
</div>
""", unsafe_allow_html=True)
