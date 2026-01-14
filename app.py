import streamlit as st
import pandas as pd
import time
import ipaddress
import hashlib
import folium
from streamlit_folium import st_folium

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="ViperIntel Pro | By Maveera",
    page_icon="🛡️",
    layout="wide"
)

# ---------------- CONSTANTS ----------------
ENGINES = ["AbuseIPDB", "VirusTotal", "AlienVault OTX"]

# ---------------- SESSION STATE ----------------
for engine in ENGINES:
    st.session_state.setdefault(f"{engine}_key", "")
    st.session_state.setdefault(f"{engine}_editing", True)

st.session_state.setdefault("scan_results", None)

# ---------------- GLOBAL STYLES ----------------
st.markdown("""
<style>
.stApp { background-color: #0a0e14; color: #e0e6ed; }
footer { visibility:hidden; }

.api-box {
    width: 100%;
    height: 48px;
    border-radius: 14px;
    border: 1px solid rgba(255,255,255,0.25);
    background: rgba(255,255,255,0.04);
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 16px;
    font-family: monospace;
    color: #9aa4b2;
}

.api-btn {
    background: none;
    border: none;
    color: #4da3ff;
    font-weight: 600;
    cursor: pointer;
}
</style>
""", unsafe_allow_html=True)

# ---------------- UTILITIES ----------------
def valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False

def pseudo_geo(ip: str):
    """
    Deterministic pseudo-geo for simulation.
    Prevents overlap and avoids fake real-world claims.
    """
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    lat = ((h % 1800000) / 10000) - 90
    lon = ((h % 3600000) / 10000) - 180
    return round(lat, 4), round(lon, 4)

# ---------------- API INPUT ----------------
def api_input(engine):
    key = f"{engine}_key"
    editing = f"{engine}_editing"

    st.markdown(f"**{engine} Key**")

    if st.session_state[editing]:
        st.text_input(
            label="",
            type="password",
            key=key,
            placeholder=f"Enter {engine} API Key",
            label_visibility="collapsed"
        )
        if st.button("Lock", key=f"lock_{engine}"):
            if not st.session_state[key]:
                st.warning("API key cannot be empty.")
            else:
                st.session_state[editing] = False
                st.rerun()
    else:
        st.markdown(
            f"""
            <div class="api-box">
                ••••••••••••••••••••
                <form method="post">
                    <button class="api-btn">Edit</button>
                </form>
            </div>
            """,
            unsafe_allow_html=True
        )
        if st.button("Edit", key=f"edit_{engine}"):
            st.session_state[editing] = True
            st.rerun()

# ---------------- SIDEBAR ----------------
with st.sidebar:
    st.markdown("## 🛡️ TI Command Center")
    st.divider()
    for engine in ENGINES:
        api_input(engine)

# ---------------- MAIN ----------------
st.title("🛡️ SOC Intelligence Console")
st.markdown("#### Universal Threat Intelligence & Forensic Aggregator")
st.caption("⚠️ Current mode: **Simulated Threat Enrichment**")

uploaded = st.file_uploader(
    "Upload CSV (IPs in first column)",
    type=["csv"]
)

if st.button("⚡ EXECUTE SIMULATED SCAN") and uploaded:
    try:
        df = pd.read_csv(uploaded, header=None)
    except Exception as e:
        st.error(f"CSV read failed: {e}")
        st.stop()

    raw_ips = df.iloc[:, 0].astype(str).tolist()
    ips = [ip.strip() for ip in raw_ips if valid_ip(ip)]

    if not ips:
        st.error("No valid IP addresses found.")
        st.stop()

    results = []
    progress = st.progress(0)
    status = st.empty()

    for i, ip in enumerate(ips):
        status.markdown(f"🔍 **Analyzing:** `{ip}` ({i+1}/{len(ips)})")

        lat, lon = pseudo_geo(ip)

        results.append({
            "IP": ip,
            "Country": "Simulated",
            "ASN": "AS-UNKNOWN",
            "Reputation": int(hash(ip)) % 100,
            "Latitude": lat,
            "Longitude": lon
        })

        progress.progress((i + 1) / len(ips))
        time.sleep(0.03)

    st.session_state.scan_results = pd.DataFrame(results)
    status.empty()

# ---------------- RESULTS ----------------
if st.session_state.scan_results is not None:
    res = st.session_state.scan_results

    st.subheader("🌍 Threat Visualization Map")
    fmap = folium.Map(location=[0, 0], zoom_start=2, tiles="CartoDB dark_matter")

    for _, r in res.iterrows():
        folium.CircleMarker(
            location=[r["Latitude"], r["Longitude"]],
            radius=6,
            color="#00ffcc",
            fill=True,
            fill_opacity=0.7,
            tooltip=f"IP: {r['IP']} | Rep: {r['Reputation']}"
        ).add_to(fmap)

    st_folium(fmap, width=1200, height=450)

    st.subheader("📋 Enrichment Report")
    st.dataframe(res, use_container_width=True)
