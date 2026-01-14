import streamlit as st
import pandas as pd
import time
import folium
from streamlit_folium import st_folium

# -------------------------------------------------
# PAGE CONFIG
# -------------------------------------------------
st.set_page_config(
    page_title="ViperIntel Pro | By Maveera",
    page_icon="🛡️",
    layout="wide"
)

# -------------------------------------------------
# SESSION STATE INIT
# -------------------------------------------------
ENGINES = ["AbuseIPDB", "VirusTotal", "AlienVault OTX"]

for e in ENGINES:
    st.session_state.setdefault(f"{e}_key", "")
    st.session_state.setdefault(f"{e}_locked", False)
    st.session_state.setdefault(f"{e}_tmp", "")

st.session_state.setdefault("scan_results", None)

# -------------------------------------------------
# GLOBAL STYLES
# -------------------------------------------------
st.markdown("""
<style>
.stApp { background-color: #0a0e14; color: #e0e6ed; }
footer { visibility: hidden; }

.api-box {
    width: 100%;
    height: 48px;
    border-radius: 14px;
    border: 1px solid rgba(255,255,255,0.25);
    background: rgba(255,255,255,0.04);
    display: flex;
    align-items: center;
    padding: 0 16px;
    font-family: monospace;
    color: #9aa4b2;
    letter-spacing: 3px;
    position: relative;
}

.api-edit {
    position: absolute;
    right: 16px;
    color: #4da3ff;
    font-weight: 600;
    cursor: pointer;
}

.api-edit:hover {
    text-decoration: underline;
}
</style>
""", unsafe_allow_html=True)

# -------------------------------------------------
# API INPUT COMPONENT (FIXED)
# -------------------------------------------------
def api_input(label, engine):
    key_name = f"{engine}_key"
    lock_name = f"{engine}_locked"
    tmp_name = f"{engine}_tmp"

    # ---------- EDIT MODE ----------
    if not st.session_state[lock_name]:
        val = st.text_input(
            label,
            type="password",
            key=tmp_name
        )

        # ✅ Update ONLY if value actually changed
        if val and val != st.session_state[key_name]:
            st.session_state[key_name] = val
            st.session_state[lock_name] = True
            st.session_state[tmp_name] = ""
            st.rerun()

    # ---------- LOCKED MODE ----------
    else:
        st.markdown(f"**{label}**")

        st.markdown(
            f"""
            <div class="api-box">
                ••••••••••••••••••••
                <span class="api-edit">Edit</span>
            </div>
            """,
            unsafe_allow_html=True
        )

        # Real Streamlit button (logic only)
        if st.button("Edit", key=f"edit_{engine}"):
            st.session_state[lock_name] = False
            st.session_state[tmp_name] = st.session_state[key_name]
            st.rerun()

# -------------------------------------------------
# SIDEBAR
# -------------------------------------------------
with st.sidebar:
    st.markdown("## 🛡️ TI Command Center")
    st.divider()

    for engine in ENGINES:
        api_input(f"{engine} Key", engine)

# -------------------------------------------------
# MAIN CONTENT
# -------------------------------------------------
st.title("🛡️ SOC Intelligence Console")
st.markdown("#### Universal Threat Intelligence & Forensic Aggregator")

uploaded_file = st.file_uploader("Upload CSV (IPs in first column)", type=["csv"])

if st.button("⚡ EXECUTE DEEP SCAN") and uploaded_file:
    df = pd.read_csv(uploaded_file, header=None)
    ips = df.iloc[:, 0].astype(str).tolist()

    results = []
    progress = st.progress(0)

    for i, ip in enumerate(ips):
        results.append({
            "IP": ip,
            "Country": "Unknown",
            "ASN": "N/A",
            "Reputation": 0,
            "Lat": 20.0,
            "Lon": 0.0
        })
        progress.progress((i + 1) / len(ips))
        time.sleep(0.05)

    st.session_state.scan_results = pd.DataFrame(results)

# -------------------------------------------------
# RESULTS
# -------------------------------------------------
if st.session_state.scan_results is not None:
    res = st.session_state.scan_results

    st.subheader("🌍 Threat Map")
    m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
    for _, r in res.iterrows():
        folium.CircleMarker(
            [r["Lat"], r["Lon"]],
            radius=6,
            color="#00ffcc",
            fill=True
        ).add_to(m)

    st_folium(m, width=1200, height=450)

    st.subheader("📋 Report")
    st.dataframe(res, use_container_width=True)
