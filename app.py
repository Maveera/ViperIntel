import streamlit as st
import requests
import pandas as pd
import json, os
from datetime import datetime
from cryptography.fernet import Fernet, InvalidToken

# ================= FILES =================
CONFIG_FILE = "config.json"
AUDIT_FILE = "audit.log"
KEY_FILE = ".secret.key"

# ================= ENCRYPTION =================
def load_or_create_key():
    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE, "wb") as f:
            f.write(Fernet.generate_key())
    return open(KEY_FILE, "rb").read()

FERNET = Fernet(load_or_create_key())

def encrypt(val: str) -> str:
    return FERNET.encrypt(val.encode()).decode()

def decrypt_safe(val: str):
    try:
        return FERNET.decrypt(val.encode()).decode()
    except InvalidToken:
        return None

# ================= AUDIT =================
def audit(action):
    with open(AUDIT_FILE, "a") as f:
        f.write(f"{datetime.utcnow().isoformat()}Z | {action}\n")

# ================= TI =================
ALL_TI_ENGINES = [
    "AbuseIPDB", "VirusTotal", "AlienVault OTX",
    "IPQualityScore", "GreyNoise", "Spamhaus",
    "Recorded Future", "Cisco Talos", "IBM X-Force"
]

SUPPORTED_TI = ["AbuseIPDB", "VirusTotal"]

DEFAULT_CONFIG = {
    "active_ti": ALL_TI_ENGINES[:3],
    "inactive_ti": ALL_TI_ENGINES[3:],
    "keys": {},
    "locked": {}
}

# ================= CONFIG =================
def load_config():
    if not os.path.exists(CONFIG_FILE):
        return DEFAULT_CONFIG.copy()

    with open(CONFIG_FILE, "r") as f:
        cfg = json.load(f)

    clean_keys, clean_locked = {}, {}

    for ti, enc in cfg.get("keys", {}).items():
        dec = decrypt_safe(enc)
        if dec is None:
            audit(f"Invalid token for {ti}, key reset")
            clean_keys[ti] = ""
            clean_locked[ti] = False
        else:
            clean_keys[ti] = dec
            clean_locked[ti] = cfg.get("locked", {}).get(ti, False)

    cfg["keys"] = clean_keys
    cfg["locked"] = clean_locked
    return cfg

def save_config():
    cfg = {
        "active_ti": st.session_state.active_ti,
        "inactive_ti": st.session_state.inactive_ti,
        "keys": {
            ti: encrypt(st.session_state[f"{ti}_key"])
            for ti in ALL_TI_ENGINES
            if st.session_state[f"{ti}_key"]
        },
        "locked": {
            ti: st.session_state[f"{ti}_locked"]
            for ti in ALL_TI_ENGINES
        }
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)

# ================= INIT =================
config = load_config()

st.session_state.setdefault("active_ti", config["active_ti"])
st.session_state.setdefault("inactive_ti", config["inactive_ti"])

for ti in ALL_TI_ENGINES:
    st.session_state.setdefault(f"{ti}_key", config["keys"].get(ti, ""))
    st.session_state.setdefault(f"{ti}_locked", config["locked"].get(ti, False))

st.session_state.setdefault("scan_results", None)
st.session_state.setdefault("uploaded_file", None)

# ================= PAGE =================
st.set_page_config(page_title="ViperIntel Pro", page_icon="🛡️", layout="wide")
st.title("🛡️ ViperIntel Pro")
st.markdown("#### Universal Threat Intelligence & Forensic Aggregator")

# ================= SIDEBAR =================
with st.sidebar:
    st.subheader("🔑 Global API Configuration")

    def ti_block(ti):
        st.markdown(f"### {ti}")

        if not st.session_state[f"{ti}_locked"]:
            val = st.text_input("", type="password", key=f"inp_{ti}")
            if val:
                st.session_state[f"{ti}_key"] = val
                st.session_state[f"{ti}_locked"] = True
                audit(f"{ti} key updated")
                save_config()
                st.rerun()
        else:
            st.markdown("••••••••••••••••")
            if st.button("Edit", key=f"edit_{ti}"):
                st.session_state[f"{ti}_locked"] = False
                save_config()
                st.rerun()

        if st.button("Remove", key=f"remove_{ti}"):
            st.session_state.active_ti.remove(ti)
            st.session_state.inactive_ti.append(ti)
            audit(f"{ti} removed from active")
            save_config()
            st.rerun()

    for ti in st.session_state.active_ti:
        ti_block(ti)

    if st.session_state.inactive_ti:
        st.divider()
        add_ti = st.selectbox(
            "➕ Add Threat Intelligence Source",
            ["Select TI"] + st.session_state.inactive_ti
        )
        if add_ti != "Select TI":
            st.session_state.inactive_ti.remove(add_ti)
            st.session_state.active_ti.append(add_ti)
            audit(f"{add_ti} added to active")
            save_config()
            st.rerun()

    st.divider()
    if st.button("🧹 Clear Scan Data"):
        st.session_state.scan_results = None
        st.session_state.uploaded_file = None
        audit("Scan data cleared")
        st.rerun()

# ================= FILE UPLOAD =================
uploaded = st.file_uploader("Upload CSV (IPs in first column)", type=["csv"])
if uploaded:
    st.session_state.uploaded_file = uploaded

# ================= SCAN =================
if st.button("⚡ EXECUTE DEEP SCAN"):
    active_supported = [
        ti for ti in st.session_state.active_ti
        if ti in SUPPORTED_TI and st.session_state[f"{ti}_key"]
    ]

    if not active_supported:
        st.error("❌ At least one supported TI API is required.")
    elif not st.session_state.uploaded_file:
        st.error("❌ Please upload a CSV file.")
    else:
        df = pd.read_csv(st.session_state.uploaded_file, header=None)
        ips = df.iloc[:, 0].astype(str).tolist()

        results = []
        for ip in ips:
            intel = {"IP": ip, "Status": "Clean", "Abuse Score": 0, "VT Hits": 0}

            if "AbuseIPDB" in active_supported:
                try:
                    r = requests.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        headers={"Key": st.session_state["AbuseIPDB_key"], "Accept": "application/json"},
                        params={"ipAddress": ip},
                        timeout=10
                    ).json()
                    intel["Abuse Score"] = r.get("data", {}).get("abuseConfidenceScore", 0)
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

        st.session_state.scan_results = pd.DataFrame(results)

# ================= RESULTS =================
if st.session_state.scan_results is not None:
    st.subheader("📋 Intelligence Report")
    st.dataframe(st.session_state.scan_results, use_container_width=True)

# ================= FOOTER =================
st.markdown("""
<style>
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

<div class="custom-footer">
© 2026 <b>ViperIntel Pro</b> | All Rights Reserved
</div>
""", unsafe_allow_html=True)
