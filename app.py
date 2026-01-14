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
st.markdown("""<style> /* unchanged */ </style>""", unsafe_allow_html=True)

# --- Header & Reset ---
col_title, col_reset = st.columns([5, 1])
with col_title:
    st.title("🛡️ SOC Intelligence Console")
    st.markdown("#### Universal Threat Intelligence & Forensic Aggregator")
with col_reset:
    st.write("") 
    if st.button("🔄 RESET", use_container_width=True, type="secondary"):
        st.session_state.scan_results = None
        st.rerun()

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
                st.markdown("""<div class="key-freeze-row">••••••••••••••••</div>""", unsafe_allow_html=True)
            with col_edit:
                if st.button("Edit", key=f"btn_{session_key}"):
                    st.session_state[f"{session_key}_locked"] = False
                    st.rerun()

    for engine in engines:
        api_input(f"{engine} Key", engine)

# --- Upload ---
uploaded_file = st.file_uploader("Upload CSV (IPs in first column)", type=["csv"])

if st.button("⚡ EXECUTE DEEP SCAN") and uploaded_file:
    if not any([st.session_state[f"{e}_key"] for e in engines]):
        st.error("❌ Please configure at least one API key.")
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
                "AS Number": "N/A",
                "Network": "N/A",
                "Last Analysis": "N/A",
                "Abuse Score": 0,
                "VT Hits": 0,
                "Lat": 20.0,
                "Lon": 0.0,

                # 🔹 ADDED
                "Risk Score": 0,
                "Correlation": "None"
            }

            engines_hit = 0  # 🔹 ADDED

            if st.session_state["AbuseIPDB_key"]:
                try:
                    r = requests.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        headers={"Key": st.session_state["AbuseIPDB_key"], "Accept":"application/json"},
                        params={"ipAddress": ip}
                    ).json()
                    data = r.get('data', {})
                    intel["Abuse Score"] = data.get('abuseConfidenceScore', 0)
                    intel["ISP"] = data.get('isp', 'Unknown')
                    intel["Country"] = data.get('countryName', 'Unknown')
                    intel["Lat"], intel["Lon"] = data.get('latitude'), data.get('longitude')
                    if intel["Abuse Score"] > 0:
                        engines_hit += 1
                except:
                    pass

            if st.session_state["VirusTotal_key"]:
                try:
                    r = requests.get(
                        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                        headers={"x-apikey": st.session_state["VirusTotal_key"]}
                    ).json()
                    attr = r['data']['attributes']
                    intel["VT Hits"] = attr['last_analysis_stats'].get('malicious', 0)
                    intel["AS Number"] = f"AS {attr.get('asn', 'N/A')}"
                    intel["Network"] = attr.get('network', 'N/A')
                    last_ts = attr.get('last_analysis_date', 0)
                    intel["Last Analysis"] = time.strftime('%Y-%m-%d %H:%M', time.gmtime(last_ts)) if last_ts else "Never"
                    if intel["VT Hits"] > 0:
                        engines_hit += 1
                except:
                    pass

            # 🔹 ADDED: Risk score calculation
            intel["Risk Score"] = min(
                (intel["Abuse Score"] * 0.6) + (intel["VT Hits"] * 40),
                100
            )

            # 🔹 ADDED: Correlation
            if engines_hit == 1:
                intel["Correlation"] = "Low"
            elif engines_hit == 2:
                intel["Correlation"] = "Medium"

            # 🔹 UPDATED status logic (additive)
            if intel["Risk Score"] >= 50:
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

    # 🔹 ADDED: Engine-aware column filtering
    show_cols = ["IP", "Status", "Risk Score", "Correlation"]

    if st.session_state["AbuseIPDB_key"]:
        show_cols.append("Abuse Score")
    if st.session_state["VirusTotal_key"]:
        show_cols.append("VT Hits")

    st.dataframe(res[show_cols], use_container_width=True)

    st.download_button(
        "📥 DOWNLOAD CSV",
        data=res[show_cols].to_csv(index=True).encode("utf-8"),
        file_name="ViperIntel_Report.csv",
        mime="text/csv"
    )
