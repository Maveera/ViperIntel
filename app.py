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

# --- UI Styling (Old Design Restoration) ---
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
    
    /* RESTORED HIGH-CONTRAST EXECUTE BUTTON */
    div.stButton > button:first-child {
        background-color: #00ffcc !important;
        color: #0a0e14 !important;
        font-weight: bold !important;
        border: none !important;
        width: 100% !important;
        height: 3.8em !important;
        font-size: 18px !important;
        border-radius: 8px !important;
        transition: 0.3s;
        box-shadow: 0px 4px 15px rgba(0, 255, 204, 0.4);
        margin-top: 10px;
    }
    div.stButton > button:hover {
        background-color: #00ccaa !important;
        box-shadow: 0px 6px 20px rgba(0, 255, 204, 0.6);
        transform: translateY(-2px);
    }
    .help-card { background: #161b22; padding: 15px; border-radius: 8px; border-left: 4px solid #00ffcc; margin-bottom: 10px; }
    .metric-container { background: #161b22; padding: 20px; border-radius: 10px; border: 1px solid #1f2937; text-align: center; }
    </style>
    """, unsafe_allow_html=True)

# --- Sidebar Configuration ---
with st.sidebar:
    st.markdown("## 🛡️ ViperIntel Pro")
    st.markdown(f"Developed by: <span class='author-text'>Maveera</span>", unsafe_allow_html=True)
    st.markdown("[🌐 Visit Website](https://maveera.tech)")
    st.divider()
    
    st.subheader("🔑 API Configuration")
    abuse_api = st.text_input("AbuseIPDB Key", type="password", help="Required for reputation & geo-data.")
    vt_api = st.text_input("VirusTotal Key", type="password", help="Required for AV engine detection.")
    otx_api = st.text_input("AlienVault OTX Key", type="password")
    ipqs_api = st.text_input("IPQualityScore Key", type="password")
    
    st.divider()
    st.markdown("### ☕ Support Maveera")
    st.markdown('<a href="https://www.buymeacoffee.com/maveera" target="_blank" style="display:block; background:#FFDD00; color:black; padding:12px; border-radius:5px; text-align:center; text-decoration:none; font-weight:bold;">☕ Buy Me a Coffee</a>', unsafe_allow_html=True)

# --- Main Dashboard ---
st.title("🐍 ViperIntel Pro")
st.markdown("#### Universal Threat Intelligence & Reporting Dashboard")

with st.expander("📘 API Configuration Guide (Tutorial)"):
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("<div class='help-card'><b>AbuseIPDB:</b> Detects brute-force/spam. Confidence > 25% is marked high risk.</div>", unsafe_allow_html=True)
        st.markdown("<div class='help-card'><b>VirusTotal:</b> Cross-references 70+ engines. Any 'Hits' indicate malicious history.</div>", unsafe_allow_html=True)
    with c2:
        st.markdown("<div class='help-card'><b>AlienVault OTX:</b> Crowdsourced investigating pulses. Identifies malware campaigns.</div>", unsafe_allow_html=True)
        st.markdown("<div class='help-card'><b>IPQS:</b> Fraud scoring. Detects VPNs, Proxies, and Tor exit nodes.</div>", unsafe_allow_html=True)

uploaded_file = st.file_uploader("Upload CSV (IP addresses in the first column)", type=["csv"])

if st.button("⚡ EXECUTE DEEP SCAN") and uploaded_file:
    if not any([abuse_api, vt_api, otx_api, ipqs_api]):
        st.error("❌ Configuration Error: Please provide at least one API key in the sidebar.")
    else:
        # Load IPs from CSV
        df_ips = pd.read_csv(uploaded_file)
        ips = df_ips.iloc[:, 0].dropna().unique().tolist()
        
        results = []
        progress = st.progress(0)
        status_txt = st.empty()

        for i, ip in enumerate(ips):
            status_txt.markdown(f"🔍 **Scanning:** `{ip}` ({i+1}/{len(ips)})")
            intel = {"IP": ip, "Status": "Clean", "Abuse Score": 0, "VT Hits": 0, "Lat": 20.0, "Lon": 0.0, "Country": "Unknown"}

            # 1. AbuseIPDB Engine
            if abuse_api:
                try:
                    r = requests.get("https://api.abuseipdb.com/api/v2/check", 
                                     headers={"Key": abuse_api, "Accept":"application/json"},
                                     params={"ipAddress": ip}).json()
                    intel["Abuse Score"] = r['data'].get('abuseConfidenceScore', 0)
                    intel["Lat"], intel["Lon"] = r['data'].get('latitude'), r['data'].get('longitude')
                    intel["Country"] = r['data'].get('countryName', "Unknown")
                except: pass

            # 2. VirusTotal Engine
            if vt_api:
                try:
                    r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", 
                                     headers={"x-apikey": vt_api}).json()
                    intel["VT Hits"] = r['data']['attributes']['last_analysis_stats'].get('malicious', 0)
                except: pass

            # Risk Logic
            if (isinstance(intel["Abuse Score"], int) and intel["Abuse Score"] > 25) or (intel["VT Hits"] > 0):
                intel["Status"] = "🚨 Malicious"
            
            results.append(intel)
            progress.progress((i + 1) / len(ips))
            time.sleep(0.3) # Rate limit safety

        # === DISPLAY RESULTS ===
        status_txt.empty()
        res_df = pd.DataFrame(results)
        malicious_count = len(res_df[res_df["Status"] == "🚨 Malicious"])

        # 1. Status Summary Metrics
        st.markdown("### 📊 Scan Summary")
        m1, m2, m3 = st.columns(3)
        with m1:
            st.markdown(f"<div class='metric-container'><b>Total IPs Scanned</b><br><h2 style='color:#00ffcc;'>{len(ips)}</h2></div>", unsafe_allow_html=True)
        with m2:
            color = "#ff4b4b" if malicious_count > 0 else "#00ffcc"
            st.markdown(f"<div class='metric-container'><b>Malicious Detected</b><br><h2 style='color:{color};'>{malicious_count}</h2></div>", unsafe_allow_html=True)
        with m3:
            st.markdown(f"<div class='metric-container'><b>Clean IPs</b><br><h2 style='color:#00ffcc;'>{len(ips) - malicious_count}</h2></div>", unsafe_allow_html=True)

        # 2. Geospatial Map
        st.subheader("🌐 Global Threat Origin Map")
        m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
        for _, r in res_df.iterrows():
            marker_color = 'red' if r['Status'] == '🚨 Malicious' else '#00ffcc'
            folium.CircleMarker(
                location=[r['Lat'], r['Lon']],
                radius=8,
                color=marker_color,
                fill=True,
                fill_opacity=0.7,
                popup=f"IP: {r['IP']}<br>Status: {r['Status']}<br>Score: {r['Abuse Score']}%"
            ).add_to(m)
        st_folium(m, width=1200, height=450)

        # 3. Detailed Table
        st.subheader("📋 Intelligence Report")
        st.dataframe(res_df.drop(columns=['Lat', 'Lon']), use_container_width=True)

        # 4. Download Option
        csv_data = res_df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Download CSV Intelligence Report",
            data=csv_data,
            file_name="ViperIntel_Report.csv",
            mime="text/csv"
        )

# --- Footer ---
st.markdown(f"""
    <div class="custom-footer">
        © 2026 ViperIntel Pro | All Rights Reserved | Developed by <a href="https://maveera.tech" target="_blank">Maveera</a>
    </div>
    """, unsafe_allow_html=True)
