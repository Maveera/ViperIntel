import streamlit as st
import requests
import pandas as pd
import time
import folium
from streamlit_folium import st_folium

# --- Page Config ---
st.set_page_config(
    page_title="ViperIntel Pro | By Maveera",
    page_icon="🛡️",
    layout="wide"
)

# --- Session State Management ---
engines = ["AbuseIPDB", "VirusTotal", "AlienVault OTX", "IPQualityScore"]
for e in engines:
    if f"{e}_key" not in st.session_state:
        st.session_state[f"{e}_key"] = ""
    if f"{e}_locked" not in st.session_state:
        st.session_state[f"{e}_locked"] = False

if "scan_results" not in st.session_state:
    st.session_state.scan_results = None

# --- Styling ---
st.markdown("""
<style>
.stApp { background-color: #0a0e14; color: #e0e6ed; }
.author-text { color: #00ffcc; font-weight: bold; font-size: 18px; }
footer { visibility: hidden; }

.key-freeze-row {
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 8px;
    padding: 8px;
    color: #8b949e;
    letter-spacing: 2px;
    font-family: monospace;
}

.metric-card {
    background: #161b22;
    padding: 20px;
    border-radius: 10px;
    border: 1px solid #1f2937;
    text-align: center;
}

.custom-footer {
    position: fixed;
    left: 0;
    bottom: 0;
    width: 100%;
    background-color: rgba(10,14,20,0.95);
    color: #94a3b8;
    text-align: center;
    padding: 14px;
    border-top: 1px solid #1f2937;
    z-index: 1000;
}
</style>
""", unsafe_allow_html=True)

# --- Header ---
st.title("🛡️ ViperIntel Pro")
st.markdown("#### Universal Threat Intelligence & Forensic Aggregator")

# --- Sidebar ---
with st.sidebar:
    st.markdown("## 🛡️ TI Command Center")
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
            st.markdown(f"**{label}**")
            col_dots, col_edit = st.columns([3, 1])
            with col_dots:
                st.markdown("<div class='key-freeze-row'>••••••••••••••••</div>", unsafe_allow_html=True)
            with col_edit:
                if st.button("Edit", key=f"btn_{session_key}"):
                    st.session_state[f"{session_key}_locked"] = False
                    st.rerun()

    for engine in engines:
        api_input(f"{engine} Key", engine)

# --- Upload ---
uploaded_file = st.file_uploader("Upload CSV (IPs in first column)", type=["csv"])

# --- Execute Scan (API REQUIRED) ---
if st.button("⚡ EXECUTE DEEP SCAN"):

    # 🔒 HARD GATE: API REQUIRED
    if not any([st.session_state[f"{e}_key"] for e in engines]):
        st.error("❌ No API key configured. Please add at least one Threat Intelligence API to execute scan.")
    
    elif not uploaded_file:
        st.error("❌ Please upload a CSV file containing IP addresses.")

    else:
        df_raw = pd.read_csv(uploaded_file, header=None)
        ips = df_raw.iloc[:, 0].astype(str).str.strip().tolist()

        results = []
        progress = st.progress(0)
        status_msg = st.empty()

        for i, ip in enumerate(ips):
            status_msg.markdown(f"🔍 **Analyzing:** `{ip}` ({i+1}/{len(ips)})")

            intel = {
                "IP": ip,
                "Status": "Clean",
                "Country": "Unknown",
                "ISP": "Unknown",
                "Abuse Score": 0,
                "VT Hits": 0,
                "Lat": None,
                "Lon": None
            }

            # --- AbuseIPDB ---
            if st.session_state["AbuseIPDB_key"]:
                try:
                    r = requests.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        headers={
                            "Key": st.session_state["AbuseIPDB_key"],
                            "Accept": "application/json"
                        },
                        params={"ipAddress": ip},
                        timeout=10
                    ).json()

                    data = r.get("data", {})
                    intel["Abuse Score"] = data.get("abuseConfidenceScore", 0)
                    intel["Country"] = data.get("countryName", "Unknown")
                    intel["ISP"] = data.get("isp", "Unknown")
                    intel["Lat"] = data.get("latitude")
                    intel["Lon"] = data.get("longitude")
                except:
                    pass

            # --- VirusTotal ---
            if st.session_state["VirusTotal_key"]:
                try:
                    r = requests.get(
                        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                        headers={"x-apikey": st.session_state["VirusTotal_key"]},
                        timeout=10
                    ).json()

                    attr = r["data"]["attributes"]
                    intel["VT Hits"] = attr["last_analysis_stats"].get("malicious", 0)
                except:
                    pass

            # --- Final Status ---
            if intel["Abuse Score"] > 25 or intel["VT Hits"] > 0:
                intel["Status"] = "🚨 Malicious"

            results.append(intel)
            progress.progress((i + 1) / len(ips))
            time.sleep(0.1)

        st.session_state.scan_results = pd.DataFrame(results)
        status_msg.empty()

# --- Results ---
if st.session_state.scan_results is not None:
    res = st.session_state.scan_results.copy()
    res.index = res.index + 1
    res.index.name = "S.No"

    st.subheader("📋 Intelligence Report")
    st.dataframe(res.drop(columns=["Lat", "Lon"]), use_container_width=True)

    st.subheader("🌍 Geographic Threat Origin")
    m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
    for _, r in res.iterrows():
        if r["Lat"] and r["Lon"]:
            folium.CircleMarker(
                [r["Lat"], r["Lon"]],
                radius=7,
                color="red" if r["Status"] != "Clean" else "#00ffcc",
                fill=True
            ).add_to(m)
    st_folium(m, width=1200, height=450)

# --- Footer ---
st.markdown("""
<div class="custom-footer">
© 2026 <b>ViperIntel Pro</b> | All Rights Reserved
</div>
""", unsafe_allow_html=True)
