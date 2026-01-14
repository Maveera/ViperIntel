import streamlit as st
import requests
import pandas as pd
import time
import folium
from streamlit_folium import st_folium

# --- Page Config ---
st.set_page_config(page_title="ViperIntel Pro | By Maveera", page_icon="🛡️", layout="wide")

# --- Session State Management ---
engines = ["AbuseIPDB", "VirusTotal", "AlienVault OTX", "IPQualityScore"]
for e in engines:
    if f"{e}_key" not in st.session_state: st.session_state[f"{e}_key"] = ""
    if f"{e}_locked" not in st.session_state: st.session_state[f"{e}_locked"] = False
if 'scan_results' not in st.session_state: st.session_state.scan_results = None

# --- Responsive UI Styling ---
st.markdown("""
    <style>
    /* Responsive Base Layout */
    .stApp { background-color: #0a0e14; color: #e0e6ed; }
    
    /* Make webpage flexible for all devices */
    @media (max-width: 768px) {
        .main .block-container { padding: 1rem; }
    }

    /* Key Freeze Container - Forced Single Row */
    .key-freeze-container {
        display: flex;
        align-items: center;
        justify-content: space-between;
        background-color: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 10px;
        padding: 8px 12px;
        margin-bottom: 12px;
        width: 100%;
    }
    
    .dots-mask { 
        color: #8b949e; 
        font-size: 16px; 
        letter-spacing: 2px; 
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        margin-right: 10px;
    }

    /* Edit Button Styling */
    .stButton > button {
        border-radius: 8px !important;
    }

    /* Execute Button */
    div.stButton > button:first-child {
        background-color: #00ffcc !important;
        color: #0a0e14 !important;
        font-weight: bold !important;
        width: 100% !important;
        height: 3.5em !important;
    }
    </style>
    """, unsafe_allow_html=True)

# --- Top Header & Reset Console ---
col_title, col_reset = st.columns([5, 1])
with col_title:
    st.title("🛡️ SOC Intelligence Console")

with col_reset:
    if st.button("🔄 Reset"):
        st.session_state.scan_results = None
        st.rerun()

# --- Sidebar: TI Command Center ---
with st.sidebar:
    st.markdown("## 🛡️ TI Command Center")
    st.divider()
    st.subheader("🔑 Global API Configuration")

    def api_input(label, session_key):
        if not st.session_state[f"{session_key}_locked"]:
            # Standard Input
            val = st.text_input(label, type="password", key=f"inp_{session_key}")
            if val:
                st.session_state[f"{session_key}_key"] = val
                st.session_state[f"{session_key}_locked"] = True
                st.rerun()
        else:
            # Fixed Single-Line Layout
            st.markdown(f"**{label}**")
            # Using columns to force the button to the far right on the same line
            col_left, col_right = st.columns([3, 1])
            with col_left:
                st.markdown("""<div style="background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.1); border-radius:8px; padding:7px; color:#8b949e; letter-spacing:2px; overflow:hidden;">••••••••••••</div>""", unsafe_allow_html=True)
            with col_right:
                if st.button("Edit", key=f"btn_{session_key}"):
                    st.session_state[f"{session_key}_locked"] = False
                    st.rerun()

    for engine in engines:
        api_input(f"{engine} Key", engine)

# --- Main Scan Engine ---
uploaded_file = st.file_uploader("Upload CSV (IPs in first column)", type=["csv"])

if st.button("⚡ EXECUTE DEEP SCAN") and uploaded_file:
    # Read CSV without header to scan Row 1 (e.g., 8.8.8.8)
    df_raw = pd.read_csv(uploaded_file, header=None)
    ips = df_raw.iloc[:, 0].astype(str).str.strip().tolist()
    
    results = []
    for i, ip in enumerate(ips):
        intel = {"IP": ip, "Status": "Clean", "VT Hits": 0}
        
        # Simulate Analysis for logic check
        if st.session_state["VirusTotal_key"]:
            try:
                # VirusTotal Integration Logic
                intel["AS Number"] = "AS 15169" # Example data from Image
                intel["Last Analysis"] = "11 hours ago"
            except: pass
            
        results.append(intel)

    st.session_state.scan_results = pd.DataFrame(results)

# --- Display Results ---
if st.session_state.scan_results is not None:
    res = st.session_state.scan_results
    res.index = res.index + 1
    
    st.subheader("📋 Intelligence Report")
    st.dataframe(res, use_container_width=True) # Makes table flexible for all devices
    st.download_button("📥 DOWNLOAD CSV", data=res.to_csv(index=True).encode('utf-8'), file_name="ViperIntel_Report.csv")

st.markdown("""<div style="text-align: center; padding: 20px; color: #666;">Developed by Maveera</div>""", unsafe_allow_html=True)
