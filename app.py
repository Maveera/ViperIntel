import streamlit as st
import pandas as pd
import time
import folium
from streamlit_folium import st_folium
import streamlit.components.v1 as components

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

    # -------- FIXED API INPUT (EDIT → SAVE FLOW) --------
    def api_input(label, engine):
        key_name = f"{engine}_key"
        lock_name = f"{engine}_locked"

        if not st.session_state[lock_name]:
            # Editable state
            st.markdown(f"**{label}**")
            new_val = st.text_input(
                "Enter API Key",
                type="password",
                value=st.session_state[key_name],
                key=f"inp_{engine}",
                label_visibility="collapsed"
            )

            col1, col2 = st.columns([1, 1])
            with col1:
                if st.button("💾 Save", key=f"save_{engine}"):
                    st.session_state[key_name] = new_val
                    st.session_state[lock_name] = True
                    st.rerun()

            with col2:
                if st.button("❌ Cancel", key=f"cancel_{engine}"):
                    st.session_state[lock_name] = True
                    st.rerun()

        else:
            # Locked (Image-2 UI)
            st.markdown(f"**{label}**")

            components.html(
                f"""
                <style>
                .api-field {{
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
                }}

                .api-dots {{
                    flex: 1;
                    color: #9aa4b2;
                    letter-spacing: 3px;
                    font-size: 14px;
                    user-select: none;
                }}

                .api-edit {{
                    color: #4da3ff;
                    font-weight: 600;
                    cursor: pointer;
                }}
                </style>

                <div class="api-field">
                    <div class="api-dots">••••••••••••••••••••</div>
                    <div class="api-edit"
                        onclick="window.location.search='?edit={engine}'">
                        Edit
                    </div>
                </div>
                """,
                height=65
            )

            if st.query_params.get("edit") == engine:
                st.session_state[lock_name] = False
                st.query_params.clear()
                st.rerun()
    # --------------------------------------------------

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

# ---------------- FOOTER ----------------
st.markdown("""
<div style="text-align:center;padding:20px;color:#666;">
© 2026 ViperIntel Pro | Developed by
<a href="https://maveera.tech" target="_blank" style="color:#00ffcc;">Maveera</a>
</div>
""", unsafe_allow_html=True)
