import streamlit as st
import requests
import pandas as pd
import time
import folium
from streamlit_folium import st_folium

# ================= PAGE CONFIG =================
st.set_page_config(
    page_title="ViperIntel Pro",
    page_icon="🛡️",
    layout="wide"
)

# ================= GLOBAL TI CATALOG =================
ALL_TI_ENGINES = [
    "AbuseIPDB",
    "VirusTotal",
    "AlienVault OTX",
    "IPQualityScore",
    "GreyNoise",
    "Spamhaus",
    "Recorded Future",
    "Cisco Talos",
    "IBM X-Force"
]

# Only these are actually queried
SUPPORTED_TI = ["AbuseIPDB", "VirusTotal"]

# ================= SESSION STATE =================
st.session_state.setdefault("active_ti", ALL_TI_ENGINES[:3])
st.session_state.setdefault("inactive_ti", ALL_TI_ENGINES[3:])

for ti in ALL_TI_ENGINES:
    st.session_state.setdefault(f"{ti}_key", "")
    st.session_state.setdefault(f"{ti}_locked", False)

st.session_state.setdefault("scan_results", None)

# ================= STYLES =================
st.markdown("""
<style>
.stApp { background-color: #0a0e14; color: #e0e6ed; }
footer { visibility: hidden; }

.key-box {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 10px;
    padding: 12px;
    margin-bottom: 12px;
}

.key-mask {
    font-family: monospace;
    letter-spacing: 3px;
    color: #9aa4b2;
    margin-bottom: 8px;
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

# ================= HEADER =================
st.title("🛡️ ViperIntel Pro")
st.markdown("#### Universal Threat Intelligence & Forensic Aggregator")

# ================= SIDEBAR =================
with st.sidebar:
    st.subheader("🔑 Global API Configuration")

    def ti_block(ti):
        with st.container():
            st.markdown('<div class="key-box">', unsafe_allow_html=True)

            # ✅ TI NAME ALWAYS VISIBLE
            st.markdown(f"### {ti}")

            # ---------- EDIT MODE ----------
            if not st.session_state[f"{ti}_locked"]:
                val = st.text_input(
                    "",
                    type="password",
                    key=f"input_{ti}",
                    placeholder=f"Enter {ti} API Key",
                    label_visibility="collapsed"
                )
                if val:
                    st.session_state[f"{ti}_key"] = val
                    st.session_state[f"{ti}_locked"] = True
                    st.rerun()

            # ---------- LOCKED MODE ----------
            else:
                st.markdown(
                    '<div class="key-mask">••••••••••••••••</div>',
                    unsafe_allow_html=True
                )

                if st.button("Edit", key=f"edit_{ti}"):
                    st.session_state[f"{ti}_locked"] = False
                    st.rerun()

            # ---------- REMOVE TI ----------
            if st.button("Remove", key=f"remove_{ti}"):
                st.session_state.active_ti.remove(ti)
                st.session_state.inactive_ti.append(ti)
                st.rerun()

            st.markdown('</div>', unsafe_allow_html=True)

    # ----- ACTIVE TI -----
    for ti in st.session_state.active_ti:
        ti_block(ti)

    # ----- ADD TI BACK -----
    if st.session_state.inactive_ti:
        st.divider()
        add_ti = st.selectbox(
            "➕ Add Threat Intelligence Source",
            ["Select TI"] + st.session_state.inactive_ti
        )
        if add_ti != "Select TI":
            st.session_state.inactive_ti.remove(add_ti)
            st.session_state.active_ti.append(add_ti)
            st.rerun()

# ================= FILE UPLOAD =================
uploaded_file = st.file_uploader("Upload CSV (IPs in first column)", type=["csv"])

# ================= EXECUTE SCAN =================
if st.button("⚡ EXECUTE DEEP SCAN"):
    active_supported = [
        ti for ti in st.session_state.active_ti
        if ti in SUPPORTED_TI and st.session_state[f"{ti}_key"]
    ]

    if not active_supported:
        st.error("❌ At least one supported TI API (AbuseIPDB or VirusTotal) is required.")
    elif not uploaded_file:
        st.error("❌ Please upload a CSV file.")
    else:
        df = pd.read_csv(uploaded_file, header=None)
        ips = df.iloc[:, 0].astype(str).tolist()

        results = []
        progress = st.progress(0)

        for i, ip in enumerate(ips):
            intel = {
                "IP": ip,
                "Status": "Clean",
                "Abuse Score": 0,
                "VT Hits": 0,
                "Lat": None,
                "Lon": None
            }

            if "AbuseIPDB" in active_supported:
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
                    intel["Lat"] = data.get("latitude")
                    intel["Lon"] = data.get("longitude")
                except:
                    pass

            if "VirusTotal" in active_supported:
                try:
                    r = requests.get(
                        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                        headers={"x-apikey": st.session_state["VirusTotal_key"]},
                        timeout=10
                    ).json()
                    intel["VT Hits"] = r["data"]["attributes"]["last_analysis_stats"].get("malicious", 0)
                except:
                    pass

            if intel["Abuse Score"] > 25 or intel["VT Hits"] > 0:
                intel["Status"] = "🚨 Malicious"

            results.append(intel)
            progress.progress((i + 1) / len(ips))
            time.sleep(0.05)

        st.session_state.scan_results = pd.DataFrame(results)

# ================= RESULTS =================
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

# ================= FOOTER =================
st.markdown("""
<div class="custom-footer">
© 2026 <b>ViperIntel Pro</b> | All Rights Reserved
</div>
""", unsafe_allow_html=True)
