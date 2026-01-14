import streamlit as st
import requests
import pandas as pd
import time
import folium
from streamlit_folium import st_folium

# --- Page Config ---
st.set_page_config(page_title="ViperIntel Pro | By Maveera", page_icon="🐍", layout="wide")

# --- Session State Management ---
# Expanded list to include more major TI engines available globally
engines = [
    "AbuseIPDB", "VirusTotal", "AlienVault OTX", "IPQualityScore", 
    "Shodan", "GreyNoise", "ThreatFox", "CriminalIP"
]

for engine in engines:
    if f"{engine}_key" not in st.session_state:
        st.session_state[f"{engine}_key"] = ""
    if f"{engine}_locked" not in st.session_state:
        st.session_state[f"{engine}_locked"] = False
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = None

# --- UI Styling & Design ---
st.markdown("""
    <style>
    .stApp { background-color: #0a0e14; color: #e0e6ed; }
    .author-text { color: #00ffcc; font-weight: bold; font-size: 18px; }
    footer { visibility: hidden; }
    
    /* Neon EXECUTE Button */
    div.stButton > button:first-child {
        background: #00ffcc !important;
        color: #0a0e14 !important;
        font-weight: bold !important;
        width: 100% !important;
        height: 3.8em !important;
        border-radius: 12px !important;
        text-transform: uppercase;
        letter-spacing: 2px;
    }

    /* Reset Button */
    .stButton > button[kind="secondary"] {
        background-color: transparent !important;
        color: #ff4b4b !important;
        border: 1px solid #ff4b4b !important;
    }

    .metric-card { background: #161b22; padding: 20px; border-radius: 10px; border: 1px solid #1f2937; text-align: center; }
    .custom-footer {
        position: fixed; left: 0; bottom: 0; width: 100%;
        background-color: rgba(10, 14, 20, 0.95); color: #94a3b8;
        text-align: center; padding: 15px; border-top: 1px solid #1f2937;
        z-index: 1000;
    }
    
    /* Locked Status Styling */
    .locked-label { color: #00ffcc; font-weight: bold; margin-top: 5px; }
    </style>
    """, unsafe_allow_html=True)

# --- Top Header & Reset ---
col_title, col_reset = st.columns([5, 1])
with col_title:
    st.title("🐍 ViperIntel Pro")
    st.markdown("#### Universal Threat Intelligence & Forensic Aggregator")

with col_reset:
    st.write(" ")
    if st.button("🔄 RESET", use_container_width=True, type="secondary"):
        st.session_state.scan_results = None
        st.rerun()

# --- Sidebar: TI Command Center ---
with st.sidebar:
    st.markdown("## 🛡️ TI Command Center")
    st.markdown(f"Developed by: <span class='author-text'>Maveera</span>", unsafe_allow_html=True)
    st.divider()
    st.subheader("🔑 Global API Configuration")

    # Feature: Auto-freeze on Enter and Inline Edit Icon
    def api_input(label, session_key):
        if not st.session_state[f"{session_key}_locked"]:
            val = st.text_input(label, type="password", key=f"inp_{session_key}")
            if val: # Triggered when user hits Enter
                st.session_state[f"{session_key}_key"] = val
                st.session_state[f"{session_key}_locked"] = True
                st.rerun()
        else:
            # Layout for Locked state with Edit button next to it to save space
            col_stat, col_ed = st.columns([4, 1])
            col_stat.markdown(f"✅ <span class='locked-label'>{session_key} Locked</span>", unsafe_allow_html=True)
            if col_ed.button("✏️", key=f"edit_{session_key}"):
                st.session_state[f"{session_key}_locked"] = False
                st.rerun()

    for engine in engines:
        api_input(f"{engine} Key", engine)

    st.divider()
    st.markdown('<a href="https://www.buymeacoffee.com/maveera" target="_blank" style="display:block; background:#FFDD00; color:black; padding:10px; border-radius:5px; text-align:center; text-decoration:none; font-weight:bold;">☕ Support Maveera</a>', unsafe_allow_html=True)

# --- Main Scan Engine ---
uploaded_file = st.file_uploader("Upload CSV (IPs in first column)", type=["csv"])

if st.button("⚡ EXECUTE DEEP SCAN") and uploaded_file:
    if not any([st.session_state[f"{e}_key"] for e in engines]):
        st.error("❌ Please enter and hit 'Enter' on at least one API key in the sidebar.")
    else:
        # header=None ensures the first row (e.g., 8.8.8.8) is scanned
        df_input = pd.read_csv(uploaded_file, header=None) 
        ips = df_input.iloc[:, 0].astype(str).str.strip().tolist()
        
        results = []
        progress = st.progress(0)
        status = st.empty()

        for i, ip in enumerate(ips):
            clean_ip = ip.replace('"', '').replace("'", "")
            status.markdown(f"🔍 **Analyzing:** `{clean_ip}` ({i+1}/{len(ips)})")
            
            intel = {
                "IP": clean_ip, "Status": "Clean", "Country": "Unknown", "ISP": "Unknown",
                "Network": "N/A", "AS Number": "N/A", "Abuse Score": 0, "VT Hits": 0,
                "OTX Pulses": 0, "Proxy/VPN": "No", "Domain": "N/A", "Last Analysis": "N/A",
                "Lat": 20.0, "Lon": 0.0
            }

            # 1. AbuseIPDB Forensics
            if st.session_state["AbuseIPDB_key"]:
                try:
                    r = requests.get("https://api.abuseipdb.com/api/v2/check", 
                                     headers={"Key": st.session_state["AbuseIPDB_key"], "Accept":"application/json"},
                                     params={"ipAddress": clean_ip}).json()
                    data = r.get('data', {})
                    intel["Abuse Score"] = data.get('abuseConfidenceScore', 0)
                    intel["ISP"] = data.get('isp', 'Unknown')
                    intel["Domain"] = data.get('domain', 'N/A')
                    intel["Country"] = data.get('countryName', 'Unknown')
                    intel["Lat"], intel["Lon"] = data.get('latitude'), data.get('longitude')
                except: pass

            # 2. VirusTotal Forensics
            if st.session_state["VirusTotal_key"]:
                try:
                    r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{clean_ip}", 
                                     headers={"x-apikey": st.session_state["VirusTotal_key"]}).json()
                    attr = r['data']['attributes']
                    intel["VT Hits"] = attr['last_analysis_stats'].get('malicious', 0)
                    intel["Network"] = attr.get('network', 'N/A')
                    intel["AS Number"] = f"AS {attr.get('asn', 'N/A')}"
                    last_ts = attr.get('last_analysis_date', 0)
                    intel["Last Analysis"] = time.strftime('%Y-%m-%d %H:%M', time.gmtime(last_ts)) if last_ts else "N/A"
                except: pass

            # 3. AlienVault OTX
            if st.session_state["AlienVault OTX_key"]:
                try:
                    r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{clean_ip}/general", 
                                     headers={"X-OTX-API-KEY": st.session_state["AlienVault OTX_key"]}).json()
                    intel["OTX Pulses"] = r.get('pulse_info', {}).get('count', 0)
                except: pass

            # 4. IPQualityScore
            if st.session_state["IPQualityScore_key"]:
                try:
                    r = requests.get(f"https://www.ipqualityscore.com/api/json/ip/{st.session_state['IPQualityScore_key']}/{clean_ip}").json()
                    intel["Proxy/VPN"] = "Yes" if r.get('proxy') or r.get('vpn') else "No"
                except: pass

            # Global Malicious Logic
            if intel["Abuse Score"] > 25 or intel["VT Hits"] > 0 or intel["OTX Pulses"] > 5:
                intel["Status"] = "🚨 Malicious"
            
            results.append(intel)
            progress.progress((i + 1) / len(ips))
            time.sleep(0.1)

        st.session_state.scan_results = pd.DataFrame(results)
        status.empty()

# --- Outputs ---
if st.session_state.scan_results is not None:
    res = st.session_state.scan_results
    res.index = res.index + 1 # S.No starts from 1
    res.index.name = "S.No"

    # Summary Metrics
    m1, m2, m3 = st.columns(3)
    m1.markdown(f"<div class='metric-card'><b>Total IPs Scanned</b><br><h2 style='color:#00ffcc;'>{len(res)}</h2></div>", unsafe_allow_html=True)
    m2.markdown(f"<div class='metric-card'><b>Malicious Found</b><br><h2 style='color:#ff4b4b;'>{len(res[res['Status'] != 'Clean'])}</h2></div>", unsafe_allow_html=True)
    m3.markdown(f"<div class='metric-card'><b>Safe Results</b><br><h2 style='color:#00ffcc;'>{len(res[res['Status'] == 'Clean'])}</h2></div>", unsafe_allow_html=True)

    # Geographic Threat Origin
    st.subheader("🌐 Geographic Threat Origin")
    m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
    for _, r in res.iterrows():
        color = 'red' if r['Status'] != 'Clean' else '#00ffcc'
        folium.CircleMarker([r['Lat'], r['Lon']], radius=8, color=color, fill=True).add_to(m)
    st_folium(m, width=1200, height=500)

    # Detailed Intelligence Report
    st.subheader("📋 Forensic Intelligence Report")
    st.dataframe(res.drop(columns=['Lat', 'Lon']), use_container_width=True)
    st.download_button("📥 DOWNLOAD CSV", data=res.to_csv(index=True).encode('utf-8'), file_name="ViperIntel_Report.csv", mime="text/csv")

st.markdown(f"""<div class="custom-footer">© 2026 ViperIntel Pro | Developed by <a href="https://maveera.tech" target="_blank" style="color:#00ffcc; text-decoration:none;">Maveera</a></div>""", unsafe_allow_html=True)
