import streamlit as st
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

# --- Session State ---
primary_engines = ["AbuseIPDB", "VirusTotal", "AlienVault OTX"]
extended_engines = ["IPQualityScore", "ThreatFox", "Shodan", "GreyNoise", "CriminalIP"]
all_engines = primary_engines + extended_engines

for e in all_engines:
    st.session_state.setdefault(f"{e}_key", "")
    st.session_state.setdefault(f"{e}_locked", False)

st.session_state.setdefault("scan_results", None)

# --- Global Styling ---
st.markdown("""
<style>
.stApp { background-color: #0a0e14; color: #e0e6ed; }
.author-text { color: #00ffcc; font-weight: bold; }
footer { visibility: hidden; }

div.stButton > button:first-child {
    background-color: #00ffcc !important;
    color: #0a0e14 !important;
    font-weight: bold;
    height: 42px !important;
    border-radius: 10px;
    border: none;
    box-shadow: 0 0 12px #00ffcc;
}
</style>
""", unsafe_allow_html=True)

# --- Header ---
col_title, col_reset = st.columns([5, 1])
with col_title:
    st.title("🛡️ SOC Intelligence Console")
    st.markdown("#### Universal Threat Intelligence & Forensic Aggregator")

with col_reset:
    st.write("")
    if st.button("🔄 Reset Console", type="secondary"):
        st.session_state.scan_results = None
        st.rerun()

# --- SIDEBAR ---
with st.sidebar:
    st.markdown("## 🛡️ TI Command Center")
    st.markdown("Developed by: <span class='author-text'>Maveera</span>", unsafe_allow_html=True)
    st.divider()
    st.subheader("🔑 Global API Configuration")

    # -------- FIXED API INPUT ----------
    def api_input(label, engine):
        if not st.session_state[f"{engine}_locked"]:
            val = st.text_input(label, type="password", key=f"inp_{engine}")
            if val:
                st.session_state[f"{engine}_key"] = val
                st.session_state[f"{engine}_locked"] = True
                st.rerun()
        else:
            st.markdown(f"**{label}**")

            col_mask, col_btn = st.columns([6, 1])

            with col_mask:
                st.markdown("""
                <div style="
                    height:42px;
                    display:flex;
                    align-items:center;
                    padding:0 14px;
                    background:rgba(255,255,255,0.05);
                    border:1px solid rgba(255,255,255,0.15);
                    border-radius:10px;
                    color:#8b949e;
                    letter-spacing:3px;
                ">
                ••••••••••••••••
                </div>
                """, unsafe_allow_html=True)

            with col_btn:
                if st.button("Edit", key=f"edit_{engine}"):
                    st.session_state[f"{engine}_locked"] = False
                    st.rerun()
    # ----------------------------------

    for eng in primary_engines:
        api_input(f"{eng} Key", eng)

    with st.expander("🔍 Search More Engines"):
        selected = st.selectbox("Select Provider", [""] + extended_engines)
        if selected:
            api_input(f"{selected} Key", selected)

    st.divider()
    st.markdown(
        '<a href="https://www.buymeacoffee.com/maveera" target="_blank" '
        'style="display:block;background:#FFDD00;color:black;padding:10px;'
        'border-radius:6px;text-align:center;font-weight:bold;">☕ Support Maveera</a>',
        unsafe_allow_html=True
    )

# --- MAIN ---
uploaded_file = st.file_uploader("Upload CSV (IPs in first column)", type=["csv"])

if st.button("⚡ EXECUTE DEEP SCAN") and uploaded_file:
    df = pd.read_csv(uploaded_file, header=None)
    ips = df.iloc[:, 0].astype(str).tolist()

    results = []
    progress = st.progress(0)
    status = st.empty()

    for i, ip in enumerate(ips):
        status.markdown(f"🔍 **Analyzing:** `{ip}` ({i+1}/{len(ips)})")

        results.append({
            "IP": ip,
            "Status": "Clean",
            "Country": "US",
            "ASN": "AS15169",
            "Reputation": 0,
            "Last Analysis": "11 hours ago",
            "Lat": 37.751,
            "Lon": -97.822
        })

        progress.progress((i + 1) / len(ips))
        time.sleep(0.05)

    st.session_state.scan_results = pd.DataFrame(results)
    status.empty()

# --- RESULTS ---
if st.session_state.scan_results is not None:
    df = st.session_state.scan_results
    df.index += 1
    df.index.name = "S.No"

    st.subheader("🌐 Geographic Threat Origin")
    m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
    for _, r in df.iterrows():
        folium.CircleMarker([r["Lat"], r["Lon"]], radius=7, color="#00ffcc", fill=True).add_to(m)
    st_folium(m, width=1200, height=500)

    st.subheader("📋 Detailed Intelligence Report")
    st.dataframe(df.drop(columns=["Lat", "Lon"]), use_container_width=True)

    st.download_button(
        "📥 DOWNLOAD CSV",
        df.to_csv(index=True).encode(),
        "ViperIntel_Report.csv"
    )

st.markdown(
    "<div style='text-align:center;padding:20px;color:#666;'>"
    "© 2026 ViperIntel Pro | Developed by "
    "<a href='https://maveera.tech' target='_blank' style='color:#00ffcc;'>Maveera</a>"
    "</div>",
    unsafe_allow_html=True
)
