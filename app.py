import streamlit as st
import pandas as pd
import asyncio
import ipaddress
from datetime import datetime

# =========================
# PAGE CONFIG
# =========================
st.set_page_config(
    page_title="ViperIntel Pro | By Maveera",
    page_icon="🛡️",
    layout="wide"
)

# =========================
# SESSION STATE
# =========================
ENGINES = ["AbuseIPDB", "VirusTotal", "AlienVaultOTX", "IPQualityScore"]

for e in ENGINES:
    st.session_state.setdefault(f"{e}_key", "")
    st.session_state.setdefault(f"{e}_locked", False)

st.session_state.setdefault("scan_results", None)

# =========================
# UTILITIES
# =========================
def valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# =========================
# API KEY INPUT (FINAL FIX)
# =========================
def api_input(engine: str):
    key_name = f"{engine}_key"
    lock_name = f"{engine}_locked"

    st.markdown(f"**{engine} Key**")

    # SAME layout for BOTH modes → NO width mismatch
    col_key, col_btn = st.columns([6, 2], gap="small")

    # ---------- EDIT MODE ----------
    if not st.session_state[lock_name]:
        with col_key:
            value = st.text_input(
                "",
                type="password",
                key=f"input_{engine}",
                placeholder=f"Enter {engine} API Key",
                label_visibility="collapsed"
            )

        with col_btn:
            st.empty()  # keeps column width identical

        if value:
            st.session_state[key_name] = value
            st.session_state[lock_name] = True
            st.rerun()

    # ---------- LOCKED MODE ----------
    else:
        with col_key:
            st.text_input(
                "",
                value="••••••••••••••••••••",
                disabled=True,
                label_visibility="collapsed",
                key=f"mask_{engine}"
            )

        with col_btn:
            if st.button(
                "Edit",
                key=f"edit_{engine}",
                use_container_width=True
            ):
                st.session_state[lock_name] = False
                st.rerun()

# =========================
# UI HEADER
# =========================
st.title("🛡️ SOC Intelligence Console")
st.markdown("#### Universal Threat Intelligence & Forensic Aggregator")

# =========================
# SIDEBAR
# =========================
with st.sidebar:
    st.subheader("🔑 API Configuration")
    for engine in ENGINES:
        api_input(engine)

# =========================
# FILE UPLOAD
# =========================
uploaded = st.file_uploader("Upload CSV (IPs in first column)", type=["csv"])

# =========================
# ASYNC SCAN (SIMPLE PLACEHOLDER)
# =========================
async def enrich_ip(ip: str):
    await asyncio.sleep(0)
    return {
        "IP": ip,
        "Status": "Clean",
        "Timeline": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    }

async def run_scan(ips):
    return await asyncio.gather(*(enrich_ip(ip) for ip in ips))

# =========================
# SCAN BUTTON
# =========================
if st.button("⚡ EXECUTE SCAN") and uploaded:
    df = pd.read_csv(uploaded, header=None)
    ips = [ip for ip in df.iloc[:, 0].astype(str) if valid_ip(ip)]

    if not ips:
        st.error("No valid IPs found in the file.")
    else:
        with st.spinner("Scanning IPs…"):
            st.session_state.scan_results = pd.DataFrame(
                asyncio.run(run_scan(ips))
            )

# =========================
# RESULTS (ALL IPS + S.No FIX)
# =========================
if st.session_state.scan_results is not None:
    res = st.session_state.scan_results.copy()
    res.reset_index(drop=True, inplace=True)
    res.insert(0, "S.No", range(1, len(res) + 1))

    st.subheader("📋 Intelligence Report")
    st.dataframe(res, use_container_width=True, hide_index=True)
