import streamlit as st
import requests
import pandas as pd
import json, os, time
from datetime import datetime
from cryptography.fernet import Fernet, InvalidToken
from pandas.errors import EmptyDataError
import ipaddress

# ==================================================
# FILES
# ==================================================
CONFIG_FILE = "config.json"
AUDIT_FILE = "audit.log"
KEY_FILE = ".secret.key"

# ==================================================
# ENCRYPTION
# ==================================================
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

# ==================================================
# AUDIT
# ==================================================
def audit(action):
    with open(AUDIT_FILE, "a") as f:
        f.write(f"{datetime.utcnow().isoformat()}Z | {action}\n")

# ==================================================
# MITRE ATT&CK (RULE-BASED, HONEST)
# ==================================================
MITRE_MAP = {
    "AbuseIPDB": "T1046 – Network Service Scanning",
    "VirusTotal": "T1105 – Ingress Tool Transfer"
}

# ==================================================
# THREAT INTELLIGENCE SOURCES
# ==================================================
ALL_TI_ENGINES = [
    "AbuseIPDB","VirusTotal","AlienVault OTX","GreyNoise","Spamhaus",
    "IPQualityScore","Recorded Future","Cisco Talos","IBM X-Force",
    "CrowdStrike Falcon","Microsoft Defender Threat Intelligence"
]

SUPPORTED_TI = ["AbuseIPDB", "VirusTotal"]
DEFAULT_ACTIVE = ["AbuseIPDB", "VirusTotal", "AlienVault OTX"]

# ==================================================
# CONFIG HANDLING
# ==================================================
def load_config():
    if not os.path.exists(CONFIG_FILE):
        return {"active_ti": DEFAULT_ACTIVE.copy(), "keys": {}, "locked": {}}

    with open(CONFIG_FILE, "r") as f:
        cfg = json.load(f)

    clean_keys, clean_locked = {}, {}
    for ti, enc in cfg.get("keys", {}).items():
        dec = decrypt_safe(enc)
        if dec is None:
            audit(f"Invalid token for {ti} – key reset")
            clean_keys[ti] = ""
            clean_locked[ti] = False
        else:
            clean_keys[ti] = dec
            clean_locked[ti] = cfg.get("locked", {}).get(ti, False)

    return {
        "active_ti": [ti for ti in cfg.get("active_ti", DEFAULT_ACTIVE) if ti in ALL_TI_ENGINES],
        "keys": clean_keys,
        "locked": clean_locked
    }

def save_config():
    cfg = {
        "active_ti": st.session_state.active_ti,
        "keys": {
            ti: encrypt(st.session_state[f"{ti}_key"])
            for ti in ALL_TI_ENGINES
            if st.session_state[f"{ti}_key"]
        },
        "locked": {ti: st.session_state[f"{ti}_locked"] for ti in ALL_TI_ENGINES}
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)

# ==================================================
# IP HELPERS
# ==================================================
def is_public_ip(ip):
    obj = ipaddress.ip_address(ip)
    return not (
        obj.is_private or obj.is_loopback or obj.is_multicast
        or obj.is_reserved or obj.is_link_local
    )

def expand_ip(value, max_expand=1024):
    try:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=False)
            return [str(ip) for ip in list(net.hosts())[:max_expand]]
        return [str(ipaddress.ip_address(value))]
    except:
        return []

# ==================================================
# INIT SESSION
# ==================================================
config = load_config()

st.session_state.setdefault("active_ti", config["active_ti"])
st.session_state["inactive_ti"] = sorted(list(set(ALL_TI_ENGINES) - set(st.session_state.active_ti)))

for ti in ALL_TI_ENGINES:
    st.session_state.setdefault(f"{ti}_key", config["keys"].get(ti, ""))
    st.session_state.setdefault(f"{ti}_locked", config["locked"].get(ti, False))

st.session_state.setdefault("scan_results", None)
st.session_state.setdefault("uploaded_file", None)

# ==================================================
# PAGE
# ==================================================
st.set_page_config(page_title="ViperIntel Pro", page_icon="🛡️", layout="wide")
st.title("🛡️ ViperIntel Pro")
st.markdown("### Universal Threat Intelligence & Forensic Aggregator")

# ==================================================
# SIDEBAR (FIXED & RESTORED)
# ==================================================
with st.sidebar:
    st.subheader("🔑 Global API Configuration")

    def ti_block(ti):
        st.markdown(f"**{ti}**")

        if not st.session_state[f"{ti}_locked"]:
            val = st.text_input("", type="password", key=f"inp_{ti}", placeholder=f"Enter {ti} API Key")
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
            audit(f"{ti} removed from active")
            save_config()
            st.rerun()

    for ti in st.session_state.active_ti:
        ti_block(ti)

    st.divider()
    add_ti = st.selectbox("➕ Add Threat Intelligence Source", ["Select TI"] + st.session_state.inactive_ti)
    if add_ti != "Select TI":
        st.session_state.active_ti.append(add_ti)
        audit(f"{add_ti} added to active")
        save_config()
        st.rerun()

    st.divider()
    st.markdown(
        """
        <a href="https://www.buymeacoffee.com/maveera" target="_blank"
        style="display:block;text-align:center;
        background:#FFDD00;color:#000;
        padding:10px;border-radius:8px;
        font-weight:bold;text-decoration:none;">
        ☕ Buy Me a Coffee
        </a>
        """,
        unsafe_allow_html=True
    )

    st.divider()
    if st.button("🧹 Clear Scan Data"):
        st.session_state.scan_results = None
        st.session_state.uploaded_file = None
        audit("Scan data cleared")
        st.rerun()

# ==================================================
# FILE UPLOAD
# ==================================================
uploaded = st.file_uploader("Upload CSV / TXT (IPs, CIDRs, mixed)", type=["csv", "txt"])
if uploaded:
    st.session_state.uploaded_file = uploaded

# ==================================================
# SCAN ENGINE
# ==================================================
if st.button("⚡ EXECUTE DEEP SCAN"):
    with st.spinner("🔍 Executing Deep Scan..."):
        time.sleep(0.4)

        if not st.session_state.uploaded_file:
            st.error("❌ Upload a file first.")
            st.stop()

        try:
            df = pd.read_csv(st.session_state.uploaded_file, header=None)
        except EmptyDataError:
            st.error("❌ Uploaded file is empty.")
            st.stop()

        # Column auto-detection
        ip_values = None
        for col in df.columns:
            series = df[col].astype(str)
            if series.str.contains(r"[0-9a-fA-F\.:/]").any():
                ip_values = series.tolist()
                break

        if not ip_values:
            st.error("❌ No IP-like column detected.")
            st.stop()

        # Expand, validate, filter
        expanded = []
        for v in ip_values:
            expanded.extend(expand_ip(v.strip()))

        valid_ips = sorted({ip for ip in expanded if is_public_ip(ip)})

        if not valid_ips:
            st.error("❌ No valid public IPs after filtering.")
            st.stop()

        progress = st.progress(0)
        results = []

        for i, ip in enumerate(valid_ips):
            progress.progress((i + 1) / len(valid_ips))

            intel = {
                "IP": ip,
                "Status": "Clean",
                "Abuse Score": 0,
                "VT Hits": 0,
                "MITRE ATT&CK": ""
            }

            if st.session_state["AbuseIPDB_key"]:
                try:
                    r = requests.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        headers={"Key": st.session_state["AbuseIPDB_key"], "Accept": "application/json"},
                        params={"ipAddress": ip},
                        timeout=10
                    ).json()
                    intel["Abuse Score"] = r.get("data", {}).get("abuseConfidenceScore", 0)
                    if intel["Abuse Score"] > 0:
                        intel["MITRE ATT&CK"] = MITRE_MAP["AbuseIPDB"]
                except:
                    pass

            if st.session_state["VirusTotal_key"]:
                try:
                    r = requests.get(
                        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                        headers={"x-apikey": st.session_state["VirusTotal_key"]},
                        timeout=10
                    ).json()
                    intel["VT Hits"] = r["data"]["attributes"]["last_analysis_stats"].get("malicious", 0)
                    if intel["VT Hits"] > 0:
                        intel["MITRE ATT&CK"] = MITRE_MAP["VirusTotal"]
                except:
                    pass

            if intel["Abuse Score"] > 25 or intel["VT Hits"] > 0:
                intel["Status"] = "🚨 Malicious"

            results.append(intel)

        st.session_state.scan_results = pd.DataFrame(results)
        st.success("✅ Scan completed successfully.")

# ==================================================
# RESULTS
# ==================================================
if st.session_state.scan_results is not None:
    st.subheader("📋 Intelligence Report")
    st.dataframe(st.session_state.scan_results, use_container_width=True)

# ==================================================
# FOOTER
# ==================================================
st.markdown(
    """
    <div style="position:fixed;bottom:0;width:100%;
    background:rgba(2,6,23,0.95);color:#94a3b8;
    text-align:center;padding:12px;border-top:1px solid #1f2937;">
    © 2026 <b>ViperIntel Pro</b> | All Rights Reserved
    </div>
    """,
    unsafe_allow_html=True
)
