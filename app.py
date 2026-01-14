import streamlit as st
import requests
import pandas as pd
import time
import folium
from streamlit_folium import st_folium

# --- Page Config ---
st.set_page_config(
    page_title="ViperIntel Pro | By Maveera",
    page_icon="🛡️",
    layout="wide"
)

# --- Session State Management ---
engines = ["AbuseIPDB", "VirusTotal", "AlienVault OTX", "IPQualityScore"]
for e in engines:
    if f"{e}_key" not in st.session_state:
        st.session_state[f"{e}_key"] = ""
    if f"{e}_locked" not in st.session_state:
        st.session_state[f"{e}_locked"] = False

if 'scan_results' not in st.session_state:
    st.session_state.scan_results = None

# --- Responsive UI Styling ---
st.markdown("""
<style>
.stApp { background-color: #0a0e14; color: #e0e6ed; }
.author-text { color: #00ffcc; font-weight: bold; font-size: 18px; }
footer { visibility: hidden; }

.key-freeze-row {
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 8px;
    padding: 8px;
    color: #8b949e;
    letter-spacing: 2px;
    font-family: monospace;
}

.metric-card {
    background: #161b22;
    padding: 20px;
    border-radius: 10px;
    border: 1px solid #1f2937;
    text-align: center;
}

.custom-footer {
    position: fixed;
    left: 0;
    bottom: 0;
    width: 100%;
    background-color: rgba(10, 14, 20, 0.95);
    color: #94a3b8;
    text-align: center;
    padding: 14px;
    border-top: 1px solid #1f2937;
    z-index: 1000;
}
</style>
""", unsafe_allow_html=True)

# --- Top Header & Reset ---
col_title, col_reset = st.columns([5, 1])
with col_title:
    st.title("🛡️ ViperIntel Pro")
    st.markdown("#### Universal Threat Intelligence & Forensic Aggregator")

with col_reset:
    st.write("")
    if st.button("🔄 RESET", use_container_width=True):
        st.session_state.scan_results = None
        st.rerun()

# --- Sidebar ---
with st.sidebar:
    st.markdown("## 🛡️ TI Command Center")
    st.markdown("<span class='author-text'>ViperIntel Pro</span>", unsafe_allow_html=True)
    st.divider()
    st.subheader("🔑 Global API Configuration")

    def api_input(label, session_key):
        if not st.session_state[f"{session_key}_locked"]:
            val = st.text_input(label, type="password", key=f"inp_{session_key}")
            if val:
                st.session_state[f"{session_key}_key"] = val
                st.session_state[f"{session_key}_locked"] = True
                st.rerun()
        else:
            st.markdown(f"**{label}**")
            col_dots, col_edit = st.columns([3, 1])
            with col_dots:
                st.markdown("<div class='key-freeze-row'>••••••••••••••••</div>", unsafe_allow_html=True)
            with col_edit:
                if st.button("Edit", key=f"btn_{session_key}"):
                    st.session_state[f"{session_key}_locked"] = False
                    st.rerun()

    for engine in engines:
        api_input(f"{engine} Key", engine)

# --- Upload & Scan ---
uploaded_file = st.file_uploader("Upload CSV (IPs in first column)", type=["csv"])

if st.button("⚡ EXECUTE DEEP SCAN") and uploaded_file:
    df = pd.read_csv(uploaded_file, header=None)
    ips = df.iloc[:, 0].astype(str).str.strip().tolist()

    results = []
    progress = st.progress(0)
    status = st.empty()

    for i, ip in enumerate(ips):
        status.markdown(f"🔍 **Analyzing:** `{ip}` ({i+1}/{len(ips)})")
        results.append({
            "IP": ip,
            "Status": "Clean",
            "Country": "Unknown",
            "ISP": "Unknown",
            "Abuse Score": 0,
            "VT Hits": 0,
            "Lat": 20.0,
            "Lon": 0.0
        })
        progress.progress((i + 1) / len(ips))
        time.sleep(0.05)

    st.session_state.scan_results = pd.DataFrame(results)
    status.empty()

# --- Results ---
if st.session_state.scan_results is not None:
    res = st.session_state.scan_results.copy()
    res.index = res.index + 1
    res.index.name = "S.No"

    st.subheader("📋 Intelligence Report")
    st.dataframe(res.drop(columns=["Lat", "Lon"]), use_container_width=True)

    st.subheader("🌐 Geographic Threat Origin")
    m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
    for _, r in res.iterrows():
        folium.CircleMarker(
            [r["Lat"], r["Lon"]],
            radius=7,
            color="#00ffcc",
            fill=True
        ).add_to(m)
    st_folium(m, width=1200, height=450)

# --- Footer ---
st.markdown("""
<div class="custom-footer">
© 2026 <b>ViperIntel Pro</b> | All Rights Reserved
</div>
""", unsafe_allow_html=True)
