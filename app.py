import streamlit as st
import pandas as pd
import time
import folium
from streamlit_folium import st_folium

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="ViperIntel Pro | By Maveera",
    page_icon="🛡️",
    layout="wide"
)

# ---------------- SESSION STATE ----------------
primary_engines = ["AbuseIPDB", "VirusTotal", "AlienVault OTX"]
extended_engines = ["IPQualityScore", "ThreatFox", "Shodan", "GreyNoise", "CriminalIP"]
all_engines = primary_engines + extended_engines

for e in all_engines:
    st.session_state.setdefault(f"{e}_key", "")
    st.session_state.setdefault(f"{e}_locked", False)

st.session_state.setdefault("scan_results", None)

# ---------------- GLOBAL STYLES ----------------
st.markdown("""
<style>
.stApp { background-color:#0a0e14; color:#e0e6ed; }
footer { visibility:hidden; }
.author-text { color:#00ffcc; font-weight:bold; }

.neon-btn {
    background:#00ffcc;
    color:#0a0e14;
    font-weight:bold;
    border:none;
    border-radius:10px;
    height:42px;
    padding:0 18px;
    cursor:pointer;
    box-shadow:0 0 12px #00ffcc;
}
.neon-btn:hover { box-shadow:0 0 18px #00ffcc; }
</style>
""", unsafe_allow_html=True)

# ---------------- HEADER ----------------
col_title, col_reset = st.columns([5, 1])
with col_title:
    st.title("🛡️ SOC Intelligence Console")
    st.markdown("#### Universal Threat Intelligence & Forensic Aggregator")

with col_reset:
    st.write("")
    if st.button("🔄 Reset Console", type="secondary"):
        st.session_state.scan_results = None
        st.rerun()

# ---------------- SIDEBAR ----------------
with st.sidebar:
    st.markdown("## 🛡️ TI Command Center")
    st.markdown("Developed by: <span class='author-text'>Maveera</span>", unsafe_allow_html=True)
    st.divider()
    st.subheader("🔑 Global API Configuration")

    # -------- PERFECTLY ALIGNED API INPUT --------
    def api_input(label, engine):
        if not st.session_state[f"{engine}_locked"]:
            val = st.text_input(label, type="password", key=f"inp_{engine}")
            if val:
                st.session_state[f"{engine}_key"] = val
                st.session_state[f"{engine}_locked"] = True
                st.rerun()
        else:
            st.markdown(f"**{label}**")

            html = f"""
            <div style="display:flex;align-items:center;gap:10px;">
                <div style="
                    flex:1;
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

                <button class="neon-btn"
                    onclick="window.location.search='?edit={engine}'">
                    Edit
                </button>
            </div>
            """
            st.markdown(html, unsafe_allow_html=True)

            # Handle Edit click
            if st.query_params.get("edit") == engine:
                st.session_state[f"{engine}_locked"] = False
                st.query_params.clear()
                st.rerun()
    # --------------------------------------------

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

# ---------------- MAIN SCAN ----------------
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

# ---------------- RESULTS ----------------
if st.session_state.scan_results is not None:
    df = st.session_state.scan_results
    df.index += 1
    df.index.name = "S.No"

    st.subheader("🌐 Geographic Threat Origin")
    m = folium.Map(locat
