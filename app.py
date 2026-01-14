import streamlit as st
import requests
import pandas as pd
import time
import folium
from streamlit_folium import st_folium
import json
import os

# ================= PERSISTENCE =================
CONFIG_FILE = "config.json"

DEFAULT_CONFIG = {
    "active_ti": [
        "AbuseIPDB",
        "VirusTotal",
        "AlienVault OTX"
    ],
    "inactive_ti": [
        "IPQualityScore",
        "GreyNoise",
        "Spamhaus",
        "Recorded Future",
        "Cisco Talos",
        "IBM X-Force"
    ],
    "keys": {},
    "locked": {}
}

def load_config():
    if not os.path.exists(CONFIG_FILE):
        return DEFAULT_CONFIG.copy()
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

def save_config():
    config = {
        "active_ti": st.session_state.active_ti,
        "inactive_ti": st.session_state.inactive_ti,
        "keys": {ti: st.session_state[f"{ti}_key"] for ti in ALL_TI_ENGINES},
        "locked": {ti: st.session_state[f"{ti}_locked"] for ti in ALL_TI_ENGINES}
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)

# ================= PAGE CONFIG =================
st.set_page_config(
    page_title="ViperIntel Pro",
    page_icon="🛡️",
    layout="wide"
)

# ================= GLOBAL TI =================
ALL_TI_ENGINES = [
    "AbuseIPDB",
    "VirusTotal",
    "AlienVault OTX",
    "IPQualityScore",
    "GreyNoise",
    "Spamhaus",
    "Recorded Future",
    "Cisco Talos",
    "IBM X-Force"
]

SUPPORTED_TI = ["AbuseIPDB", "VirusTotal"]

# ================= LOAD CONFIG =================
config = load_config()

st.session_state.setdefault("active_ti", config["active_ti"])
st.session_state.setdefault("inactive_ti", config["inactive_ti"])

for ti in ALL_TI_ENGINES:
    st.session_state.setdefault(f"{ti}_key", config["keys"].get(ti, ""))
    st.session_state.setdefault(f"{ti}_locked", config["locked"].get(ti, False))

st.session_state.setdefault("scan_results", None)

# ================= STYLES =================
st.markdown("""
<style>
.stApp { background-color: #0a0e14; color: #e0e6ed; }
footer { visibility: hidden; }

.key-box {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 10px;
    padding: 12px;
    margin-bottom: 12px;
}

.key-mask {
    font-family: monospace;
    letter-spacing: 3px;
    color: #9aa4b2;
    margin-bottom: 8px;
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
}
</style>
""", unsafe_allow_html=True)

# ================= HEADER =================
st.title("🛡️ ViperIntel Pro")
st.markdown("#### Universal Threat Intelligence & Forensic Aggregator")

# ================= SIDEBAR =================
with st.sidebar:
    st.subheader("🔑 Global API Configuration")

    def ti_block(ti):
        with st.container():
            st.markdown('<div class="key-box">', unsafe_allow_html=True)
            st.markdown(f"### {ti}")

            if not st.session_state[f"{ti}_locked"]:
                val = st.text_input(
                    "",
                    type="password",
                    key=f"input_{ti}",
                    placeholder=f"Enter {ti} API Key",
                    label_visibility="collapsed"
                )
                if val:
                    st.session_state[f"{ti}_key"] = val
                    st.session_state[f"{ti}_locked"] = True
                    save_config()
                    st.rerun()
            else:
                st.markdown('<div class="key-mask">••••••••••••••••</div>', unsafe_allow_html=True)
                if st.button("Edit", key=f"edit_{ti}"):
                    st.session_state[f"{ti}_locked"] = False
                    save_config()
                    st.rerun()

            if st.button("Remove", key=f"remove_{ti}"):
                st.session_state.active_ti.remove(ti)
                st.session_state.inactive_ti.append(ti)
                save_config()
                st.rerun()

            st.markdown('</div>', unsafe_allow_html=True)

    for ti in st.session_state.active_ti:
        ti_block(ti)

    if st.session_state.inactive_ti:
        st.divider()
        add_ti = st.selectbox(
            "➕ Add Threat Intelligence Source",
            ["Select TI"] + st.session_state.inactive_ti
        )
        if add_ti != "Select TI":
            st.session_state.inactive_ti.remove(add_ti)
            st.session_state.active_ti.append(add_ti)
            save_config()
            st.rerun()

# ================= FILE UPLOAD =================
uploaded_file = st.file_uploader("Upload CSV (IPs in first column)", type=["csv"])

# ================= EXECUTE SCAN =================
if st.button("⚡ EXECUTE DEEP SCAN"):
    active_supported = [
        ti for ti in st.session_state.active_ti
        if ti in SUPPORTED_TI and st.session_state[f"{ti}_key"]
    ]

    if not active_supported:
        st.error("❌ At least one supported TI API is required.")
    elif not uploaded_file:
        st.error("❌ Please upload a CSV file.")
    else:
        df = pd.read_csv(uploaded_file, header=None)
        ips = df.iloc[:, 0].astype(str).tolist()

        results = []
        progress = st.progress(0)

        for i, ip in enumerate(ips):
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
                    intel["Abuse Score"] = r.get("data", {}).get("abuseConfidenceScore", 0)
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
            time.sleep(0.05)

        st.session_state.scan_results = pd.DataFrame(results)

# ================= RESULTS =================
if st.session_state.scan_results is not None:
    res = st.session_state.scan_results.copy()
    res.index = res.index + 1
    res.index.name = "S.No"

    st.subheader("📋 Intelligence Report")
    st.dataframe(res.drop(columns=["Lat", "Lon"]), use_container_width=True)

# ================= FOOTER =================
st.markdown("""
<div class="custom-footer">
© 2026 <b>ViperIntel Pro</b> | All Rights Reserved
</div>
""", unsafe_allow_html=True)
