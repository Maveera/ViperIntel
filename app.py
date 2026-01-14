import streamlit as st
import requests
import pandas as pd
import time
import folium
from streamlit_folium import st_folium

# --- Page Config ---
st.set_page_config(page_title="ViperIntel Pro | By Maveera", page_icon="🐍", layout="wide")

# --- Session State for Advanced API Locking ---
# This ensures keys freeze upon hitting Enter
engines = ["AbuseIPDB", "VirusTotal", "AlienVault OTX", "IPQualityScore", "Shodan", "GreyNoise", "Cisco Talos"]
for engine in engines:
    if f"{engine}_key" not in st.session_state:
        st.session_state[f"{engine}_key"] = ""
    if f"{engine}_locked" not in st.session_state:
        st.session_state[f"{engine}_locked"] = False
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = None

# --- UI Styling & Neon Design ---
st.markdown("""
    <style>
    .stApp { background-color: #0a0e14; color: #e0e6ed; }
    .author-text { color: #00ffcc; font-weight: bold; font-size: 18px; }
    footer { visibility: hidden; }
    
    /* Neon EXECUTE Button Design */
    div.stButton > button:first-child {
        background: transparent !important;
        color: #00ffcc !important;
        border: 2px solid #00ffcc !important;
        font-weight: bold !important;
        width: 100% !important;
        height: 3.8em !important;
        border-radius: 12px !important;
        transition: all 0.3s ease;
        text-transform: uppercase;
        letter-spacing: 2px;
    }
    div.stButton > button:first-child:hover {
        background: #00ffcc !important;
        color: #0a0e14 !important;
        box-shadow: 0px 0px 20px #00ffcc;
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
    </style>
    """, unsafe_allow_html=True)

# --- Top Header & Reset ---
col_title, col_reset = st.columns([5, 1])
with col_title:
    st.title("🐍 ViperIntel Pro")
    st.markdown("#### Universal Threat Intelligence Aggregator")

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

    # Dynamic API Key Input with Automatic Freeze
    def api_input(label, session_key):
        if not st.session_state[f"{session_key}_locked"]:
            val = st.text_input(label, type="password", key=f"inp_{session_key}")
            if val: # If user hits Enter
                st.session_state[f"{session_key}_key"] = val
                st.session_state[f"{session_key}_locked"] = True
                st.rerun()
        else:
            col1, col2 = st.columns([4, 1])
            col1.info(f"✅ {label} Locked")
            if col2.button("✏️", key=f"edit_{session_key}"):
                st.session_state[f"{session_key}_locked"] = False
                st.rerun()

    # Expandable Support for all major TI engines
    api_input("AbuseIPDB Key", "AbuseIPDB")
    api_input("VirusTotal Key", "VirusTotal")
    api_input("AlienVault OTX Key", "AlienVault OTX")
    api_input("IPQualityScore Key", "IPQualityScore")
    
    with st.expander("More Engines (Enterprise)"):
        api_input("Shodan Key", "Shodan")
        api_input("GreyNoise Key", "GreyNoise")
        api_input("Cisco Talos Key", "Cisco Talos")

    st.divider()
    st.markdown('<a href="https://www.buymeacoffee.com/maveera" target="_blank" style="display:block; background:#FFDD00; color:black; padding:10px; border-radius:5px; text-align:center; text-decoration:none; font-weight:bold;">☕ Support Maveera</a>', unsafe_allow_html=True)

# --- Main Scan Logic ---
uploaded_file = st.file_uploader("Upload CSV (IPs in first column)", type=["csv"])

if st.button("⚡ EXECUTE DEEP SCAN") and uploaded_file:
    # Check if at least one key is active
    if not any([st.session_state[f"{e}_key"] for e in engines]):
        st.error("❌ Please enter and hit 'Enter' on at least one API key.")
    else:
        df = pd.read_csv(uploaded_file)
        ips = df.iloc[:, 0].dropna().tolist() # Processes all rows
        
        results = []
        progress = st.progress(0)
        status = st.empty()

        for i, ip in enumerate(ips):
            status.markdown(f"🔍 **Analyzing:** `{ip}` ({i+1}/{len(ips)})")
            intel = {"IP": ip, "Status": "Clean", "Lat": 20.0, "Lon": 0.0}

            # 1. AbuseIPDB
            if st.session_state["AbuseIPDB_key"]:
                try:
                    r = requests.get("https://api.abuseipdb.com/api/v2/check", 
                                     headers={"Key": st.session_state["AbuseIPDB_key"], "Accept":"application/json"},
                                     params={"ipAddress": ip}).json()
                    intel["Abuse Score"] = r['data'].get('abuseConfidenceScore', 0)
                    intel["Lat"], intel["Lon"] = r['data'].get('latitude'), r['data'].get('longitude')
                except: intel["Abuse Score"] = 0

            # 2. VirusTotal
            if st.session_state["VirusTotal_key"]:
                try:
                    r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", 
                                     headers={"x-apikey": st.session_state["VirusTotal_key"]}).json()
                    vt_hits = r['data']['attributes']['last_analysis_stats'].get('malicious', 0)
                    intel["VT Hits"] = vt_hits
                    if vt_hits > 0: intel["Status"] = "🚨 Malicious"
                except: intel["VT Hits"] = 0

            # Logic check
            if intel.get("Abuse Score", 0) > 25: intel["Status"] = "🚨 Malicious"
            
            results.append(intel)
            progress.progress((i + 1) / len(ips))
            time.sleep(0.1)

        st.session_state.scan_results = pd.DataFrame(results)
        status.empty()

# --- Outputs ---
if st.session_state.scan_results is not None:
    res = st.session_state.scan_results
    mal = len(res[res["Status"] == "🚨 Malicious"])

    m1, m2, m3 = st.columns(3)
    m1.markdown(f"<div class='metric-card'><b>Total IPs Scanned</b><br><h2 style='color:#00ffcc;'>{len(res)}</h2></div>", unsafe_allow_html=True)
    m2.markdown(f"<div class='metric-card'><b>Malicious Detected</b><br><h2 style='color:#ff4b4b;'>{mal}</h2></div>", unsafe_allow_html=True)
    m3.markdown(f"<div class='metric-card'><b>Safe Results</b><br><h2 style='color:#00ffcc;'>{len(res)-mal}</h2></div>", unsafe_allow_html=True)

    st.subheader("🌐 Geographic Threat Origin")
    m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
    for _, r in res.iterrows():
        color = 'red' if r['Status'] == '🚨 Malicious' else '#00ffcc'
        folium.CircleMarker([r['Lat'], r['Lon']], radius=8, color=color, fill=True).add_to(m)
    st_folium(m, width=1200, height=500)

    st.subheader("📋 Intelligence Report")
    st.dataframe(res.drop(columns=['Lat', 'Lon']), use_container_width=True)
    st.download_button("📥 DOWNLOAD CSV", data=res.to_csv(index=False).encode('utf-8'), file_name="ViperIntel_Report.csv", mime="text/csv")

st.markdown(f"""<div class="custom-footer">© 2026 ViperIntel Pro | Developed by <a href="https://maveera.tech" target="_blank" style="color:#00ffcc;">Maveera</a></div>""", unsafe_allow_html=True)
