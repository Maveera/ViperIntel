import streamlit as st
import requests
import pandas as pd
import time
import smtplib
import folium
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from io import StringIO
from streamlit_folium import st_folium

# --- Page Config ---
st.set_page_config(page_title="ViperIntel Pro | By Maveera", page_icon="🐍", layout="wide")

# --- Session State Initialization ---
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = None

# --- UI Styling ---
st.markdown("""
    <style>
    .stApp { background-color: #0a0e14; color: #e0e6ed; }
    .author-text { color: #00ffcc; font-weight: bold; font-size: 18px; }
    footer { visibility: hidden; }
    .custom-footer {
        position: fixed; left: 0; bottom: 0; width: 100%;
        background-color: rgba(10, 14, 20, 0.95); color: #94a3b8;
        text-align: center; padding: 15px; border-top: 1px solid #1f2937;
        z-index: 1000;
    }
    .custom-footer a { color: #00ffcc; text-decoration: none; font-weight: bold; }
    
    /* High-Contrast EXECUTE Button */
    div.stButton > button:first-child {
        background-color: #00ffcc !important;
        color: #0a0e14 !important;
        font-weight: bold !important;
        border: none !important;
        width: 100% !important;
        height: 3.8em !important;
        font-size: 18px !important;
        border-radius: 8px !important;
        box-shadow: 0px 4px 15px rgba(0, 255, 204, 0.4);
    }

    /* Reset Button Styling */
    .reset-btn {
        background-color: #ff4b4b !important;
        color: white !important;
    }

    .metric-container { background: #161b22; padding: 20px; border-radius: 10px; border: 1px solid #1f2937; text-align: center; }
    .help-card { background: #161b22; padding: 15px; border-radius: 8px; border-left: 4px solid #00ffcc; margin-bottom: 10px; }
    </style>
    """, unsafe_allow_html=True)

# --- Sidebar ---
with st.sidebar:
    st.markdown("## 🛡️ ViperIntel Pro")
    st.markdown(f"Developed by: <span class='author-text'>Maveera</span>", unsafe_allow_html=True)
    st.markdown("[🌐 Portfolio](https://maveera.tech)")
    st.divider()
    
    st.subheader("🔑 API Key Configuration")
    abuse_api = st.text_input("AbuseIPDB Key", type="password")
    vt_api = st.text_input("VirusTotal Key", type="password")
    otx_api = st.text_input("AlienVault OTX Key", type="password")
    ipqs_api = st.text_input("IPQualityScore Key", type="password")
    
    st.divider()
    st.markdown("### ☕ Support the Project")
    st.markdown('<a href="https://www.buymeacoffee.com/maveera" target="_blank" style="display:block; background:#FFDD00; color:black; padding:12px; border-radius:5px; text-align:center; text-decoration:none; font-weight:bold;">☕ Buy Me a Coffee</a>', unsafe_allow_html=True)

# --- Main Dashboard ---
st.title("🐍 ViperIntel Pro")
st.markdown("#### Universal Threat Intelligence Aggregator")

with st.expander("📘 API Configuration Guide & TI Tutorial"):
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("<div class='help-card'><b>AbuseIPDB:</b> Flags IPs reported for brute-force & spam.</div>", unsafe_allow_html=True)
    with c2:
        st.markdown("<div class='help-card'><b>VirusTotal:</b> Checks 70+ engines for malicious history.</div>", unsafe_allow_html=True)

uploaded_file = st.file_uploader("Upload CSV (IPs in first column)", type=["csv"])

# --- Action Buttons ---
col_exec, col_reset = st.columns([4, 1])

with col_exec:
    exec_btn = st.button("⚡ EXECUTE DEEP SCAN")

with col_reset:
    if st.button("🔄 RESET PAGE"):
        st.session_state.scan_results = None
        st.rerun()

# --- Scan Logic ---
if exec_btn and uploaded_file:
    if not any([abuse_api, vt_api, otx_api, ipqs_api]):
        st.error("❌ Please provide at least one API key.")
    else:
        df_ips = pd.read_csv(uploaded_file)
        ips = df_ips.iloc[:, 0].dropna().unique().tolist()
        results = []
        progress = st.progress(0)
        status_box = st.empty()

        for i, ip in enumerate(ips):
            status_box.markdown(f"🔍 **Scanning:** `{ip}` ({i+1}/{len(ips)})")
            intel = {"IP": ip, "Status": "Clean", "Abuse Score": 0, "VT Hits": 0, "Lat": 20.0, "Lon": 0.0}

            if abuse_api:
                try:
                    r = requests.get("https://api.abuseipdb.com/api/v2/check", headers={"Key": abuse_api, "Accept":"application/json"}, params={"ipAddress": ip}).json()
                    intel["Abuse Score"] = r['data'].get('abuseConfidenceScore', 0)
                    intel["Lat"], intel["Lon"] = r['data'].get('latitude'), r['data'].get('longitude')
                except: pass
            
            if vt_api:
                try:
                    r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey": vt_api}).json()
                    intel["VT Hits"] = r['data']['attributes']['last_analysis_stats'].get('malicious', 0)
                except: pass

            if (intel["Abuse Score"] > 25) or (intel["VT Hits"] > 0):
                intel["Status"] = "🚨 Malicious"
            
            results.append(intel)
            progress.progress((i + 1) / len(ips))
            time.sleep(0.2)

        st.session_state.scan_results = pd.DataFrame(results)
        status_box.empty()

# --- Display Results from Session State ---
if st.session_state.scan_results is not None:
    res_df = st.session_state.scan_results
    malicious_count = len(res_df[res_df["Status"] == "🚨 Malicious"])

    # Metrics
    st.markdown("### 📊 Scan Summary")
    m1, m2, m3 = st.columns(3)
    m1.markdown(f"<div class='metric-container'><b>Total IPs</b><br><h2 style='color:#00ffcc;'>{len(res_df)}</h2></div>", unsafe_allow_html=True)
    m2.markdown(f"<div class='metric-container'><b>Malicious</b><br><h2 style='color:#ff4b4b;'>{malicious_count}</h2></div>", unsafe_allow_html=True)
    m3.markdown(f"<div class='metric-container'><b>Safe</b><br><h2 style='color:#00ffcc;'>{len(res_df) - malicious_count}</h2></div>", unsafe_allow_html=True)

    # Download Button
    csv = res_df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="📥 DOWNLOAD RESULTS (CSV)",
        data=csv,
        file_name="ViperIntel_Report.csv",
        mime="text/csv",
    )

    # Map
    st.subheader("🌐 Geographic Threat Origin")
    m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
    for _, r in res_df.iterrows():
        color = 'red' if r['Status'] == '🚨 Malicious' else '#00ffcc'
        folium.CircleMarker([r['Lat'], r['Lon']], radius=8, color=color, fill=True).add_to(m)
    st_folium(m, width=1200, height=450)

    # Table
    st.subheader("📋 Intelligence Details")
    st.dataframe(res_df.drop(columns=['Lat', 'Lon']), use_container_width=True)

# --- Footer ---
st.markdown(f"""
    <div class="custom-footer">
        © 2026 ViperIntel Pro | Developed by <a href="https://maveera.tech" target="_blank">Maveera</a>
    </div>
    """, unsafe_allow_html=True)
