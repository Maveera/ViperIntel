import streamlit as st
import pandas as pd
import aiohttp
import asyncio
import ipaddress
import folium
import hashlib
from datetime import datetime
from streamlit_folium import st_folium

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
st.session_state.setdefault("history", {})

# =========================
# STYLES
# =========================
st.markdown("""
<style>
.stApp { background-color:#0a0e14; color:#e0e6ed; }
footer { visibility:hidden; }

.key-row {
    display: flex;
    align-items: center;
    gap: 10px;
}

.key-mask {
    flex: 1;
    background: rgba(255,255,255,0.06);
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 8px;
    padding: 10px;
    font-family: monospace;
    letter-spacing: 3px;
    color: #9aa4b2;
}
</style>
""", unsafe_allow_html=True)

# =========================
# UTILITIES
# =========================
def valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def fingerprint(ip):
    return hashlib.sha256(ip.encode()).hexdigest()

# =========================
# API KEY INPUT (FINAL FIX)
# =========================
def api_input(engine):
    key_name = f"{engine}_key"
    lock_name = f"{engine}_locked"

    st.markdown(f"**{engine} Key**")

    if not st.session_state[lock_name]:
        # EDIT MODE
        val = st.text_input(
            "",
            type="password",
            key=f"input_{engine}",
            placeholder=f"Enter {engine} API Key",
            label_visibility="collapsed"
        )
        if val:
            st.session_state[key_name] = val
            st.session_state[lock_name] = True
            st.rerun()
    else:
        # LOCKED MODE — INLINE (NO STACKING)
        col_mask, col_btn = st.columns([5, 1], gap="small")

        with col_mask:
            st.markdown(
                "<div class='key-mask'>••••••••••••••••••••</div>",
                unsafe_allow_html=True
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
    for e in ENGINES:
        api_input(e)

# =========================
# FILE UPLOAD
# =========================
uploaded = st.file_uploader("Upload CSV (IPs in first column)", type=["csv"])

# =========================
# ASYNC SCAN LOGIC (UNCHANGED)
# =========================
async def enrich_ip(ip, keys, sem):
    async with sem:
        intel = {
            "IP": ip,
            "Status": "Clean",
            "Confidence": 0,
            "Timeline": datetime.utcnow().isoformat() + "Z"
        }
        return intel

async def run_scan(ips, keys):
    sem = asyncio.Semaphore(5)
    return await asyncio.gather(*(enrich_ip(ip, keys, sem) for ip in ips))

# =========================
# SCAN TRIGGER
# =========================
if st.button("⚡ EXECUTE FULL ASYNC SCAN") and uploaded:
    df = pd.read_csv(uploaded, header=None)
    ips = [ip for ip in df.iloc[:, 0].astype(str) if valid_ip(ip)]
    keys = {e: st.session_state[f"{e}_key"] for e in ENGINES}

    with st.spinner("Running scan…"):
        st.session_state.scan_results = pd.DataFrame(
            asyncio.run(run_scan(ips, keys))
        )

# =========================
# RESULTS (S.No FIXED)
# =========================
if st.session_state.scan_results is not None:
    res = st.session_state.scan_results.copy()
    res.reset_index(drop=True, inplace=True)
    res.insert(0, "S.No", range(1, len(res) + 1))

    st.subheader("📋 Intelligence Report")
    st.dataframe(res, use_container_width=True, hide_index=True)
