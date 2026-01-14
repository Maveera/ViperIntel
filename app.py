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

# --- Responsive UI Styling & Layout Fix ---
st.markdown("""
    <style>
    /* Flexible Base Layout for all devices */
    .stApp { background-color: #0a0e14; color: #e0e6ed; }
    
    @media (max-width: 768px) {
        .main .block-container { padding: 1rem; }
    }

    /* Neon EXECUTE Button Styling */
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

    /* Top Navigation Bar Styling */
    .top-nav {
        display: flex; justify-content: space-between; align-items: center;
        padding: 10px 0px; margin-bottom: 20px; border-bottom: 1px solid #1f2937;
    }

    /* Fixed Sidebar Row: Masked Dots and Edit Button on same line */
    .key-freeze-row {
        display: flex;
        align-items: center;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 8px;
        padding: 2px 10px;
        height: 45px;
        margin-bottom: 10px;
    }
    
    .dots-mask { 
        flex-grow: 1;
        color: #8b949e; 
        font-size: 18px; 
        letter-spacing: 2px; 
        white-space: nowrap;
        overflow: hidden;
    }
    
    .metric-card { background: #161b22; padding: 20px; border-radius: 10px; border: 1px solid #1f2937; text-align: center; }
    </style>
    """, unsafe_allow_html=True)

# --- Top Navigation Bar ---
t_col1, t_col2 = st.columns([5, 1])
with t_col1:
    st.title("🛡️ SOC Intelligence Console")
with t_col2:
    st.write("") # Padding
    if st.button("🔄 Reset Console", type="secondary"):
        st.session_state.scan_results = None
        st.rerun()

# --- Sidebar: TI Command Center ---
with st.sidebar:
    st.markdown("## 🛡️ TI Command Center")
    st.markdown(f"Developed by: **Maveera**")
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
            # The Fix: Single line layout using columns inside the sidebar
            st.markdown(f"**{label}**")
            col_dots, col_btn = st.columns([3, 1])
            with col_dots:
                st.markdown("""<div style="background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.1); border-radius:8px; padding:8px; color:#8b949e; letter-spacing:2px; height:40px; line-height:24px; overflow:hidden;">••••••••••••</div>""", unsafe_allow_html=True)
            with col_btn:
                # Custom Edit button styling to fit the row
                if st.button("Edit", key=f"btn_{session_key}"):
                    st.session_state[f"{session_key}_locked"] = False
                    st.rerun()

    # Primary 3 Engines
    for engine in primary_engines:
        api_input(f"{engine} Key", engine)
    
    # Expandable search for more
    with st.expander("🔍 Search More Engines"):
        search_engine = st.selectbox("Select Provider", [""] + extended_engines)
        if search_engine:
            api_input(f"{search_engine} Key", search_engine)

# --- Main Scan Engine ---
uploaded_file = st.file_uploader("Upload CSV (IPs in first column)", type=["csv"])

if st.button("⚡ EXECUTE DEEP SCAN") and uploaded_file:
    # Read CSV without header to scan Row 1 (e.g., 8.8.8.8)
    df_raw = pd.read_csv(uploaded_file, header=None)
    ips = df_raw.iloc[:, 0].astype(str).str.strip().tolist()
    
    results = []
    progress = st.progress(0)
    for i, ip in enumerate(ips):
        # Forensic placeholders based on Image 2
        intel = {
            "IP": ip, "Status": "Clean", "AS Number": "N/A", "Last Analysis": "N/A",
            "Lat": 20.0, "Lon": 0.0
        }
        # Simulate Analysis
        results.append(intel)
        progress.progress((i + 1) / len(ips))

    st.session_state.scan_results = pd.DataFrame(results)

# --- Display Results ---
if st.session_state.scan_results is not None:
    res = st.session_state.scan_results
    res.index = res.index + 1 # S.No starts from 1
    
    st.subheader("📋 Intelligence Report")
    st.dataframe(res.drop(columns=['Lat', 'Lon']), use_container_width=True)
    st.download_button("📥 DOWNLOAD CSV", data=res.to_csv(index=True).encode('utf-8'), file_name="ViperIntel_Report.csv")

st.markdown("""<div style="text-align: center; padding: 20px; color: #666;">© 2026 ViperIntel Pro | Developed by Maveera</div>""", unsafe_allow_html=True)
