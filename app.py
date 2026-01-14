import streamlit as st
import requests
import pandas as pd
import time
import folium
from streamlit_folium import st_folium

# --- Page Config ---
st.set_page_config(page_title="ViperIntel Pro | By Maveera", page_icon="🐍", layout="wide")

# --- Session State Management ---
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = None
if 'abuse_frozen' not in st.session_state:
    st.session_state.abuse_frozen = False
if 'vt_frozen' not in st.session_state:
    st.session_state.vt_frozen = False

# --- UI Styling ---
st.markdown("""
    <style>
    .stApp { background-color: #0a0e14; color: #e0e6ed; }
    .author-text { color: #00ffcc; font-weight: bold; font-size: 18px; }
    footer { visibility: hidden; }
    
    /* New Execute Button: Neon Border & Glow */
    div.stButton > button:first-child {
        background: transparent !important;
        color: #00ffcc !important;
        border: 2px solid #00ffcc !important;
        font-weight: bold !important;
        width: 100% !important;
        height: 3.8em !important;
        border-radius: 12px !important;
        transition: all 0.3s ease-in-out;
        text-transform: uppercase;
        letter-spacing: 2px;
    }
    div.stButton > button:first-child:hover {
        background: #00ffcc !important;
        color: #0a0e14 !important;
        box-shadow: 0px 0px 20px #00ffcc;
    }

    /* New Reset Button: Minimalist Red */
    .stButton > button[kind="secondary"] {
        background-color: transparent !important;
        color: #ff4b4b !important;
        border: 1px solid #ff4b4b !important;
        border-radius: 8px !important;
    }
    .stButton > button[kind="secondary"]:hover {
        background-color: #ff4b4b !important;
        color: white !important;
    }

    .metric-container { background: #161b22; padding: 20px; border-radius: 10px; border: 1px solid #1f2937; text-align: center; }
    .custom-footer {
        position: fixed; left: 0; bottom: 0; width: 100%;
        background-color: rgba(10, 14, 20, 0.95); color: #94a3b8;
        text-align: center; padding: 15px; border-top: 1px solid #1f2937;
        z-index: 1000;
    }
    .custom-footer a { color: #00ffcc; text-decoration: none; }
    </style>
    """, unsafe_allow_html=True)

# --- Top Header ---
col_title, col_reset = st.columns([5, 1])
with col_title:
    st.title("🐍 ViperIntel Pro")
    st.markdown("#### Universal Threat Intelligence & Geospatial Analytics")

with col_reset:
    st.write(" ") 
    if st.button("🔄 RESET", use_container_width=True, type="secondary"):
        st.session_state.scan_results = None
        st.rerun()

# --- Sidebar ---
with st.sidebar:
    st.markdown("## 🛡️ TI Command Center")
    st.markdown(f"Developed by: <span class='author-text'>Maveera</span>", unsafe_allow_html=True)
    st.divider()
    
    st.subheader("🔑 API Key Configuration")
    
    # AbuseIPDB Freeze/Edit Logic
    if not st.session_state.abuse_frozen:
        abuse_api = st.text_input("AbuseIPDB Key", type="password", key="abuse_input")
        if st.button("Freeze AbuseIPDB"):
            st.session_state.abuse_api_val = abuse_api
            st.session_state.abuse_frozen = True
            st.rerun()
    else:
        st.success("AbuseIPDB Key Locked")
        if st.button("Edit AbuseIPDB"):
            st.session_state.abuse_frozen = False
            st.rerun()
        abuse_api = st.session_state.abuse_api_val

    # VirusTotal Freeze/Edit Logic
    if not st.session_state.vt_frozen:
        vt_api = st.text_input("VirusTotal Key", type="password", key="vt_input")
        if st.button("Freeze VirusTotal"):
            st.session_state.vt_api_val = vt_api
            st.session_state.vt_frozen = True
            st.rerun()
    else:
        st.success("VirusTotal Key Locked")
        if st.button("Edit VirusTotal"):
            st.session_state.vt_frozen = False
            st.rerun()
        vt_api = st.session_state.vt_api_val

    st.divider()
    st.markdown('<a href="https://www.buymeacoffee.com/maveera" target="_blank" style="display:block; background:#FFDD00; color:black; padding:12px; border-radius:5px; text-align:center; text-decoration:none; font-weight:bold;">☕ Support Maveera</a>', unsafe_allow_html=True)

# --- Upload & Scan ---
uploaded_file = st.file_uploader("Upload CSV (IPs in first column)", type=["csv"])

if st.button("⚡ EXECUTE DEEP SCAN") and uploaded_file:
    if not any([abuse_api, vt_api]):
        st.error("❌ Please provide at least one API key.")
    else:
        df_ips = pd.read_csv(uploaded_file)
        # CHANGED: Removed .unique() to ensure all rows are scanned
        ips = df_ips.iloc[:, 0].dropna().tolist()
        
        results = []
        progress = st.progress(0)
        status_box = st.empty()

        for i, ip in enumerate(ips):
            status_box.markdown(f"🔍 **Scanning:** `{ip}` ({i+1}/{len(ips)})")
            intel = {"IP": ip, "Status": "Clean", "Score": 0, "Lat": 20.0, "Lon": 0.0, "Country": "Unknown"}

            if abuse_api:
                try:
                    r = requests.get("https://api.abuseipdb.com/api/v2/check", 
                                     headers={"Key": abuse_api, "Accept":"application/json"},
                                     params={"ipAddress": ip}).json()
                    intel["Score"] = r['data'].get('abuseConfidenceScore', 0)
                    intel["Lat"], intel["Lon"] = r['data'].get('latitude'), r['data'].get('longitude')
                    intel["Country"] = r['data'].get('countryName', "Unknown")
                except: pass

            if vt_api:
                try:
                    r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", 
                                     headers={"x-apikey": vt_api}).json()
                    vt_mal = r['data']['attributes']['last_analysis_stats'].get('malicious', 0)
                    if vt_mal > 0: intel["Status"] = "🚨 Malicious"
                except: pass

            if intel["Score"] > 25:
                intel["Status"] = "🚨 Malicious"
            
            results.append(intel)
            progress.progress((i + 1) / len(ips))
            time.sleep(0.2)

        st.session_state.scan_results = pd.DataFrame(results)
        status_box.empty()

# --- Results ---
if st.session_state.scan_results is not None:
    res_df = st.session_state.scan_results
    mal_count = len(res_df[res_df["Status"] == "🚨 Malicious"])

    m1, m2, m3 = st.columns(3)
    m1.markdown(f"<div class='metric-container'><b>Total Rows Scanned</b><br><h2 style='color:#00ffcc;'>{len(res_df)}</h2></div>", unsafe_allow_html=True)
    m2.markdown(f"<div class='metric-container'><b>Malicious Found</b><br><h2 style='color:#ff4b4b;'>{mal_count}</h2></div>", unsafe_allow_html=True)
    m3.markdown(f"<div class='metric-container'><b>Safe Results</b><br><h2 style='color:#00ffcc;'>{len(res_df) - mal_count}</h2></div>", unsafe_allow_html=True)

    csv = res_df.to_csv(index=False).encode('utf-8')
    st.download_button("📥 DOWNLOAD REPORT (CSV)", data=csv, file_name="ViperIntel_Report.csv", mime="text/csv")

    st.subheader("🌐 Geographic Threat Origin")
    m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
    for _, r in res_df.iterrows():
        color = 'red' if r['Status'] == '🚨 Malicious' else '#00ffcc'
        folium.CircleMarker([r['Lat'], r['Lon']], radius=8, color=color, fill=True, popup=r['IP']).add_to(m)
    st_folium(m, width=1200, height=500)

    st.subheader("📋 Detailed Intelligence Report")
    st.dataframe(res_df.drop(columns=['Lat', 'Lon']), use_container_width=True)

st.markdown(f"""
    <div class="custom-footer">
        © 2026 ViperIntel Pro | Developed by <a href="https://maveera.tech" target="_blank">Maveera</a>
    </div>
    """, unsafe_allow_html=True)
