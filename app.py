import streamlit as st
import requests
import pandas as pd
import time
import folium
from streamlit_folium import st_folium

# --- Page Config ---
st.set_page_config(page_title="ViperIntel Pro | By Maveera", page_icon="🐍", layout="wide")

# --- Session State Management ---
# Ensures results stay on screen and prevents auto-refresh loss
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = None

# --- UI Styling ---
st.markdown("""
    <style>
    .stApp { background-color: #0a0e14; color: #e0e6ed; }
    .author-text { color: #00ffcc; font-weight: bold; font-size: 18px; }
    footer { visibility: hidden; }
    
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

    /* Top-Right Reset Button Styling */
    .stButton > button[kind="secondary"] {
        background-color: #ff4b4b !important;
        color: white !important;
        border: none !important;
        font-weight: bold !important;
    }

    .metric-container { background: #161b22; padding: 20px; border-radius: 10px; border: 1px solid #1f2937; text-align: center; }
    
    .custom-footer {
        position: fixed; left: 0; bottom: 0; width: 100%;
        background-color: rgba(10, 14, 20, 0.95); color: #94a3b8;
        text-align: center; padding: 15px; border-top: 1px solid #1f2937;
        z-index: 1000;
    }
    .custom-footer a { color: #00ffcc; text-decoration: none; font-weight: bold; }
    </style>
    """, unsafe_allow_html=True)

# --- Top Layout Header ---
# Positioning title and Reset button at the top-right
col_title, col_reset = st.columns([5, 1])
with col_title:
    st.title("🐍 ViperIntel Pro")
    st.markdown("#### Universal Threat Intelligence & Geospatial Analytics")

with col_reset:
    st.write(" ") # Padding
    if st.button("🔄 RESET PAGE", use_container_width=True, type="secondary"):
        st.session_state.scan_results = None
        st.rerun() # Forces page to clear and refresh

# --- Sidebar ---
with st.sidebar:
    st.markdown("## 🛡️ TI Command Center")
    st.markdown(f"Developed by: <span class='author-text'>Maveera</span>", unsafe_allow_html=True)
    st.divider()
    
    st.subheader("🔑 API Key Configuration")
    abuse_api = st.text_input("AbuseIPDB Key", type="password")
    vt_api = st.text_input("VirusTotal Key", type="password")
    
    st.divider()
    st.markdown("### ☕ Support Maveera")
    st.markdown('<a href="https://www.buymeacoffee.com/maveera" target="_blank" style="display:block; background:#FFDD00; color:black; padding:12px; border-radius:5px; text-align:center; text-decoration:none; font-weight:bold;">☕ Buy Me a Coffee</a>', unsafe_allow_html=True)

# --- Upload & Scan Section ---
uploaded_file = st.file_uploader("Upload CSV (IPs in first column)", type=["csv"])

if st.button("⚡ EXECUTE DEEP SCAN") and uploaded_file:
    if not any([abuse_api, vt_api]):
        st.error("❌ Error: Provide at least one API key in the sidebar.")
    else:
        # Load IPs
        df_ips = pd.read_csv(uploaded_file)
        ips = df_ips.iloc[:, 0].dropna().unique().tolist()
        
        results = []
        progress = st.progress(0)
        status_box = st.empty()

        for i, ip in enumerate(ips):
            status_box.markdown(f"🔍 **Scanning:** `{ip}` ({i+1}/{len(ips)})")
            intel = {"IP": ip, "Status": "Clean", "Abuse Score": 0, "VT Hits": 0, "Lat": 20.0, "Lon": 0.0, "Country": "Unknown"}

            # Engine 1: AbuseIPDB
            if abuse_api:
                try:
                    r = requests.get("https://api.abuseipdb.com/api/v2/check", 
                                     headers={"Key": abuse_api, "Accept":"application/json"},
                                     params={"ipAddress": ip}).json()
                    intel["Abuse Score"] = r['data'].get('abuseConfidenceScore', 0)
                    intel["Lat"], intel["Lon"] = r['data'].get('latitude'), r['data'].get('longitude')
                    intel["Country"] = r['data'].get('countryName', "Unknown")
                except: pass

            # Engine 2: VirusTotal
            if vt_api:
                try:
                    r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", 
                                     headers={"x-apikey": vt_api}).json()
                    intel["VT Hits"] = r['data']['attributes']['last_analysis_stats'].get('malicious', 0)
                except: pass

            # Risk Logic
            if intel["Abuse Score"] > 25 or intel["VT Hits"] > 0:
                intel["Status"] = "🚨 Malicious"
            
            results.append(intel)
            progress.progress((i + 1) / len(ips))
            time.sleep(0.2)

        # Store in session state to stop auto-refresh loss
        st.session_state.scan_results = pd.DataFrame(results)
        status_box.empty()

# --- Result Output Section ---
if st.session_state.scan_results is not None:
    res_df = st.session_state.scan_results
    mal_count = len(res_df[res_df["Status"] == "🚨 Malicious"])

    # 📊 Scan Summary Metrics
    st.markdown("### 📊 Real-Time Metrics")
    m1, m2, m3 = st.columns(3)
    m1.markdown(f"<div class='metric-container'><b>Total IPs Scanned</b><br><h2 style='color:#00ffcc;'>{len(res_df)}</h2></div>", unsafe_allow_html=True)
    m2.markdown(f"<div class='metric-container'><b>Malicious Detected</b><br><h2 style='color:#ff4b4b;'>{mal_count}</h2></div>", unsafe_allow_html=True)
    m3.markdown(f"<div class='metric-container'><b>Clean Results</b><br><h2 style='color:#00ffcc;'>{len(res_df) - mal_count}</h2></div>", unsafe_allow_html=True)

    # 📥 Download Results
    csv_file = res_df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="📥 DOWNLOAD INTELLIGENCE REPORT (CSV)",
        data=csv_file,
        file_name="ViperIntel_Report.csv",
        mime="text/csv",
    )

    # 🌐 Geographic Threat Origin Graph
    st.subheader("🌐 Geographic Threat Origin")
    st.info("Map plots malicious activity in Red and clean traffic in Cyan.")
    
    m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
    for _, row in res_df.iterrows():
        # Highlighting malicious vs clean points on the graph
        marker_color = 'red' if row['Status'] == '🚨 Malicious' else '#00ffcc'
        folium.CircleMarker(
            location=[row['Lat'], row['Lon']],
            radius=9,
            color=marker_color,
            fill=True,
            fill_opacity=0.8,
            popup=f"IP: {row['IP']}<br>Status: {row['Status']}<br>Abuse Score: {row['Abuse Score']}%"
        ).add_to(m)
    st_folium(m, width=1200, height=500)

    # 📋 Intelligence Table
    st.subheader("📋 Detailed Intelligence Data")
    st.dataframe(res_df.drop(columns=['Lat', 'Lon']), use_container_width=True)

# --- Footer ---
st.markdown(f"""
    <div class="custom-footer">
        © 2026 ViperIntel Pro | Developed by <a href="https://maveera.tech" target="_blank">Maveera</a>
    </div>
    """, unsafe_allow_html=True)
