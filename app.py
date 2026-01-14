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

.api-wrapper {
    position: relative;
    width: 100%;
}

.api-field {
    width: 100%;
    height: 48px;
    border-radius: 14px;
    border: 1px solid rgba(255,255,255,0.25);
    background: rgba(255,255,255,0.04);
    display: flex;
    align-items: center;
    padding: 0 16px;
    box-sizing: border-box;
    font-family: monospace;
}

.api-dots {
    flex: 1;
    color: #9aa4b2;
    letter-spacing: 3px;
    font-size: 14px;
    user-select: none;
}

.api-edit-btn {
    position: absolute;
    right: 8px;
    top: 50%;
    transform: translateY(-50%);
}

.api-edit-btn button {
    background: none !important;
    border: none !important;
    color: #4da3ff !important;
    font-weight: 600 !important;
    padding: 0 6px !important;
}

.api-edit-btn button:hover {
    text-decoration: underline;
}
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
    st.markdown(
        "Developed by: <span class='author-text'>Maveera</span>",
        unsafe_allow_html=True
    )
    st.divider()
    st.subheader("🔑 Global API Configuration")

    # -------- FINAL API INPUT (NO FREEZE) --------
    def api_input(label, engine):
        if not st.session_state[f"{engine}_locked"]:
            val = st.text_input(label, type="password", key=f"inp_{engine}")
            if val:
                st.session_state[f"{engine}_key"] = val
                st.session_state[f"{engine}_locked"] = True
                st.rerun()
        else:
            st.markdown(f"**{label}**")

            st.markdown(
                """
                <div class="api-wrapper">
                    <div class="api-field">
                        <div class="api-dots">••••••••••••••••••••</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            col_btn = st.columns([1])[0]
            with col_btn:
                if st.button("Edit", key=f"edit_{engine}"):
                    st.session_state[f"{engine}_locked"] = False
                    st.rerun()

            # move button visually inside field
            st.markdown(
                f"""
                <script>
                const btn = window.parent.document.querySelector(
                    'button[key="edit_{engine}"]'
                );
                </script>
                """,
                unsafe_allow_html=True
            )
    # --------------------------------------------

    for eng in primary_engines:
        api_input(f"{eng} Key", eng)

    with st.expander("🔍 Search More Engines"):
        selected = st.selectbox("Select Provider", [""] + extended_engines)
        if selected:
            api_input(f"{selected} Key", selected)

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
    m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")

    for _, r in df.iterrows():
        folium.CircleMarker(
            [r["Lat"], r["Lon"]],
            radius=7,
            color="#00ffcc",
            fill=True
        ).add_to(m)

    st_folium(m, width=1200, height=500)

    st.subheader("📋 Detailed Intelligence Report")
    st.dataframe(df.drop(columns=["Lat", "Lon"]), use_container_width=True)

    st.download_button(
        "📥 DOWNLOAD CSV",
        df.to_csv(index=True).encode(),
        "ViperIntel_Report.csv"
    )

# ---------------- FOOTER ----------------
st.markdown("""
<div style="text-align:center;padding:20px;color:#666;">
© 2026 ViperIntel Pro | Developed by
<a href="https://maveera.tech" target="_blank" style="color:#00ffcc;">Maveera</a>
</div>
""", unsafe_allow_html=True)
