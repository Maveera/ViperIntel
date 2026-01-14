import streamlit as st
import requests
import pandas as pd
import time
import folium
from streamlit_folium import st_folium

# --- Page Config ---
st.set_page_config(page_title="ViperIntel Pro | By Maveera", page_icon="🛡️", layout="wide")

# --- Session State Management ---
# Handles persistent API locking and UI state
engines = ["AbuseIPDB", "VirusTotal", "AlienVault OTX", "IPQualityScore", "ThreatFox", "Shodan", "GreyNoise", "CriminalIP"]
for e in engines:
    if f"{e}_key" not in st.session_state: st.session_state[f"{e}_key"] = ""
    if f"{e}_locked" not in st.session_state: st.session_state[f"{e}_locked"] = False
if 'scan_results' not in st.session_state: st.session_state.scan_results = None

# --- UI Styling ---
st.markdown("""
    <style>
    .stApp { background-color: #0a0e14; color: #e0e6ed; }
    .author-text { color: #00ffcc; font-weight: bold; font-size: 18px; }
    footer { visibility: hidden; }
    
    /* Neon EXECUTE Button Design */
    div.stButton > button:first-child {
        background-color: #00ffcc !important;
        color: #0a0e14 !important;
        font-weight: bold !important;
        width: 100% !important;
        height: 3.8em !important;
        border-radius: 10px !important;
        border: none !important;
        box-shadow: 0px 0px 15px #00ffcc;
    }
    
    /* Inline Locked Label Styling */
    .locked-label { color: #00ffcc; font-weight: bold; }
    </style>
    """, unsafe_allow_html=True)

# --- Top Header & Reset ---
col_title, col_reset = st.columns([5, 1])
with col_title:
    st.title("🛡️ SOC Intelligence Console")
    st.markdown("#### Universal Threat Intelligence & Forensic Aggregator")

with col_reset:
    if st.button("🔄 Reset Console", type="secondary"):
        st.session_state.scan_results = None
        st.rerun()

# --- Sidebar: TI Command Center ---
with st.sidebar:
    st.markdown("## 🛡️ TI Command Center")
    st.markdown(f"Developed by: <span class='author-text'>Maveera</span>", unsafe_allow_html=True)
    st.divider()
    st.subheader("🔑 Global API Configuration")

    # Fixed: Inline Status and Edit button on the same row
    def api_input(label, session_key):
        if not st.session_state[f"{session_key}_locked"]:
            # Logic: If user types and hits enter, it freezes
            val = st.text_input(label, type="password", key=f"inp_{session_key}")
            if val:
                st.session_state[f"{session_key}_key"] = val
                st.session_state[f"{session_key}_locked"] = True
                st.rerun()
        else:
            # Display inline: Success message + Edit button side-by-side
            c_label, c_btn = st.columns([4, 1])
            c_label.markdown(f"✅ <span class='locked-label'>{session_key} Locked</span>", unsafe_allow_html=True)
            if c_btn.button("✏️", key=f"edit_{session_key}"):
                st.session_state[f"{session_key}_locked"] = False
                st.rerun()

    for engine in engines:
        api_input(f"{engine} Key", engine)

    st.divider()
    st.markdown('<a href="https://www.buymeacoffee.com/maveera" target="_blank" style="display:block; background:#FFDD00; color:black; padding:10px; border-radius:5px; text-align:center; text-decoration:none; font-weight:bold;">☕ Support Maveera</a>', unsafe_allow_html=True)

# --- Main Scan Logic ---
uploaded_file = st.file_uploader("Upload CSV (IPs in first column)", type=["csv"])

if st.button("⚡ EXECUTE DEEP SCAN") and uploaded_file:
    active_keys = [st.session_state[f"{e}_key"] for e in engines]
    if not any(active_keys):
        st.error("❌ Configuration Error: Please lock at least one API key in the sidebar.")
    else:
        # Load IPs (header=None ensuring first row 8.8.8.8 is scanned)
        df_in = pd.read_csv(uploaded_file, header=None)
        ips = df_in.iloc[:, 0].astype(str).str.strip().tolist()
        
        results = []
        progress = st.progress(0)
        status_box = st.empty()

        for i, ip in enumerate(ips):
            status_box.markdown(f"🔍 **Scanning:** `{ip}` ({i+1}/{len(ips)})")
            # Aggregating all forensic info into one record
            intel = {
                "IP": ip, "Status": "Clean", "Abuse Score": 0, "VT Hits": 0,
                "ISP": "Unknown", "ASN": "N/A", "Network": "N/A", "Reputation": 0,
                "Last Analysis": "Never", "Lat": 20.0, "Lon": 0.0
            }

            # 1. AbuseIPDB
            if st.session_state["AbuseIPDB_key"]:
                try:
                    r = requests.get("https://api.abuseipdb.com/api/v2/check", headers={"Key": st.session_state["AbuseIPDB_key"], "Accept":"application/json"}, params={"ipAddress": ip}).json()
                    intel["Abuse Score"] = r['data'].get('abuseConfidenceScore', 0)
                    intel["ISP"] = r['data'].get('isp', 'Unknown')
                    intel["Lat"], intel["Lon"] = r['data'].get('latitude'), r['data'].get('longitude')
                except: pass

            # 2. VirusTotal
            if st.session_state["VirusTotal_key"]:
                try:
                    r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey": st.session_state["VirusTotal_key"]}).json()
                    attr = r['data']['attributes']
                    intel["VT Hits"] = attr['last_analysis_stats'].get('malicious', 0)
                    intel["ASN"] = f"AS{attr.get('asn', 'N/A')}"
                    intel["Network"] = attr.get('network', 'N/A')
                    intel["Reputation"] = attr.get('reputation', 0)
                except: pass

            if intel["Abuse Score"] > 25 or intel["VT Hits"] > 0: intel["Status"] = "🚨 Malicious"
            results.append(intel)
            progress.progress((i + 1) / len(ips))
            time.sleep(0.1)

        st.session_state.scan_results = pd.DataFrame(results)
        status_box.empty()

# --- Outputs & Reports ---
if st.session_state.scan_results is not None:
    res = st.session_state.scan_results
    res.index = res.index + 1
    res.index.name = "S.No"

    # Summary Metrics
    m1, m2, m3 = st.columns(3)
    m1.metric("Total IPs", len(res))
    m2.metric("Malicious Found", len(res[res['Status'] != 'Clean']))
    m3.metric("Safe Results", len(res[res['Status'] == 'Clean']))

    # Threat Origin Map
    st.subheader("🌐 Geographic Threat Origin")
    m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
    for _, r in res.iterrows():
        folium.CircleMarker([r['Lat'], r['Lon']], radius=8, color='red' if r['Status'] != 'Clean' else '#00ffcc', fill=True).add_to(m)
    st_folium(m, width=1200, height=500)

    # Intelligence Report
    st.subheader("📋 Forensic Intelligence Report")
    st.dataframe(res.drop(columns=['Lat', 'Lon']), use_container_width=True)
    st.download_button("📥 DOWNLOAD REPORT", data=res.to_csv(index=True).encode('utf-8'), file_name="ViperIntel_Report.csv", mime="text/csv")

st.markdown(f"""<div style="text-align: center; padding: 20px; color: #666;">© 2026 ViperIntel Pro | Developed by <a href="https://maveera.tech" target="_blank" style="color:#00ffcc; text-decoration:none;">Maveera</a></div>""", unsafe_allow_html=True)
