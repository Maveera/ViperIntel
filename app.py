import streamlit as st
import requests
import pandas as pd
import time
import folium
from streamlit_folium import st_folium

# --- Page Config ---
st.set_page_config(page_title="ViperIntel Pro | By Maveera", page_icon="🛡️", layout="wide")

# --- Session State Management ---
primary_engines = ["AbuseIPDB", "VirusTotal", "AlienVault OTX"]
extended_engines = ["IPQualityScore", "ThreatFox", "Shodan", "GreyNoise", "CriminalIP"]
all_engines = primary_engines + extended_engines

for e in all_engines:
    if f"{e}_key" not in st.session_state: st.session_state[f"{e}_key"] = ""
    if f"{e}_locked" not in st.session_state: st.session_state[f"{e}_locked"] = False
if 'scan_results' not in st.session_state: st.session_state.scan_results = None

# --- UI Styling & Design ---
st.markdown("""
    <style>
    .stApp { background-color: #0a0e14; color: #e0e6ed; }
    .author-text { color: #00ffcc; font-weight: bold; font-size: 18px; }
    footer { visibility: hidden; }
    
    /* Neon EXECUTE Button */
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

    /* Fixed Live Key Freeze Row Styling */
    .key-freeze-row {
        background-color: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        padding: 8px 15px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 12px;
        width: 100%;
    }
    .dots-mask { color: #8b949e; font-size: 18px; letter-spacing: 2px; line-height: 1; }
    .edit-trigger { color: #58a6ff; font-weight: bold; cursor: pointer; font-size: 14px; border: none; background: none; }
    
    .metric-card { background: #161b22; padding: 20px; border-radius: 10px; border: 1px solid #1f2937; text-align: center; }
    </style>
    """, unsafe_allow_html=True)

# --- Top Header & Reset Console ---
col_title, col_reset = st.columns([5, 1])
with col_title:
    st.title("🛡️ SOC Intelligence Console")
    st.markdown("#### Universal Threat Intelligence & Forensic Aggregator")

with col_reset:
    st.write("") 
    if st.button("🔄 Reset Console", type="secondary"):
        st.session_state.scan_results = None
        st.rerun()

# --- Sidebar: TI Command Center ---
with st.sidebar:
    st.markdown("## 🛡️ TI Command Center")
    st.markdown(f"Developed by: <span class='author-text'>Maveera</span>", unsafe_allow_html=True)
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
            # Layout Fix: Forced Single Line with Flexbox
            st.markdown(f"**{label}**")
            # We use a custom HTML container and a small streamlit button side-by-side
            col_dots, col_edit = st.columns([4, 1.2])
            with col_dots:
                st.markdown("""<div style="background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.1); border-radius:10px; padding:9px; color:#8b949e; letter-spacing:2px; overflow:hidden;">••••••••••••••••</div>""", unsafe_allow_html=True)
            with col_edit:
                if st.button("Edit", key=f"btn_{session_key}"):
                    st.session_state[f"{session_key}_locked"] = False
                    st.rerun()

    # Show primary 3
    for engine in primary_engines:
        api_input(f"{engine} Key", engine)
    
    # Hide others in search dropdown
    with st.expander("🔍 Search More Engines"):
        search_engine = st.selectbox("Select Provider", [""] + extended_engines)
        if search_engine:
            api_input(f"{search_engine} Key", search_engine)

    st.divider()
    st.markdown('<a href="https://www.buymeacoffee.com/maveera" target="_blank" style="display:block; background:#FFDD00; color:black; padding:10px; border-radius:5px; text-align:center; text-decoration:none; font-weight:bold;">☕ Support Maveera</a>', unsafe_allow_html=True)

# --- Main Scan Engine ---
uploaded_file = st.file_uploader("Upload CSV (IPs in first column)", type=["csv"])

if st.button("⚡ EXECUTE DEEP SCAN") and uploaded_file:
    # Read CSV without header to scan Row 1 (e.g., 8.8.8.8)
    df_raw = pd.read_csv(uploaded_file, header=None)
    ips = df_raw.iloc[:, 0].astype(str).str.strip().tolist()
    
    results = []
    progress = st.progress(0)
    status_msg = st.empty()

    for i, ip in enumerate(ips):
        status_msg.markdown(f"🔍 **Analyzing:** `{ip}` ({i+1}/{len(ips)})")
        
        # Comprehensive forensics
        intel = {
            "IP": ip, "Status": "Clean", "Country": "Unknown", "ISP": "Unknown",
            "ASN": "N/A", "Network": "N/A", "Reputation": 0,
            "Last Analysis": "Never", "Abuse Score": 0, "VT Hits": 0, "Lat": 20.0, "Lon": 0.0
        }

        # AbuseIPDB API
        if st.session_state["AbuseIPDB_key"]:
            try:
                r = requests.get("https://api.abuseipdb.com/api/v2/check", headers={"Key": st.session_state["AbuseIPDB_key"], "Accept":"application/json"}, params={"ipAddress": ip}).json()
                data = r.get('data', {})
                intel["Abuse Score"] = data.get('abuseConfidenceScore', 0)
                intel["ISP"] = data.get('isp', 'Unknown')
                intel["Country"] = data.get('countryName', 'Unknown')
                intel["Lat"], intel["Lon"] = data.get('latitude'), data.get('longitude')
            except: pass

        # VirusTotal API
        if st.session_state["VirusTotal_key"]:
            try:
                r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey": st.session_state["VirusTotal_key"]}).json()
                attr = r['data']['attributes']
                intel["VT Hits"] = attr['last_analysis_stats'].get('malicious', 0)
                intel["ASN"] = f"AS {attr.get('asn', 'N/A')}"
                intel["Network"] = attr.get('network', 'N/A')
                intel["Reputation"] = attr.get('reputation', 0)
                last_ts = attr.get('last_analysis_date', 0)
                intel["Last Analysis"] = time.strftime('%Y-%m-%d %H:%M', time.gmtime(last_ts)) if last_ts else "Never"
            except: pass

        if intel["Abuse Score"] > 25 or intel["VT Hits"] > 0:
            intel["Status"] = "🚨 Malicious"
        
        results.append(intel)
        progress.progress((i + 1) / len(ips))
        time.sleep(0.1)

    st.session_state.scan_results = pd.DataFrame(results)
    status_msg.empty()

# --- Display Results ---
if st.session_state.scan_results is not None:
    res = st.session_state.scan_results
    res.index = res.index + 1
    res.index.name = "S.No"

    m1, m2, m3 = st.columns(3)
    m1.markdown(f"<div class='metric-card'><b>Total IPs</b><br><h2>{len(res)}</h2></div>", unsafe_allow_html=True)
    m2.markdown(f"<div class='metric-card'><b>Malicious</b><br><h2 style='color:#ff4b4b;'>{len(res[res['Status'] != 'Clean'])}</h2></div>", unsafe_allow_html=True)
    m3.markdown(f"<div class='metric-card'><b>Clean</b><br><h2>{len(res[res['Status'] == 'Clean'])}</h2></div>", unsafe_allow_html=True)

    st.subheader("🌐 Geographic Threat Origin")
    m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
    for _, r in res.iterrows():
        color = 'red' if r['Status'] != 'Clean' else '#00ffcc'
        folium.CircleMarker([r['Lat'], r['Lon']], radius=8, color=color, fill=True).add_to(m)
    st_folium(m, width=1200, height=500)

    st.subheader("📋 Detailed Intelligence Report")
    st.dataframe(res.drop(columns=['Lat', 'Lon']), use_container_width=True)
    st.download_button("📥 DOWNLOAD CSV", data=res.to_csv(index=True).encode('utf-8'), file_name="ViperIntel_Report.csv", mime="text/csv")

st.markdown(f"""<div style="text-align: center; padding: 20px; color: #666;">© 2026 ViperIntel Pro | Developed by <a href="https://maveera.tech" target="_blank" style="color:#00ffcc; text-decoration:none;">Maveera</a></div>""", unsafe_allow_html=True)
