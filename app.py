import streamlit as st
import requests
import pandas as pd
import json, os, time, uuid
from datetime import datetime
from cryptography.fernet import Fernet, InvalidToken
from pandas.errors import EmptyDataError
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

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
# MITRE ATT&CK MAP (EXTENDED)
# ==================================================
MITRE_MAP = {
    "AbuseIPDB": {
        "technique": "T1046",
        "technique_name": "Network Service Scanning",
        "tactic": "TA0043",
        "tactic_name": "Reconnaissance"
    },
    "VirusTotal": {
        "technique": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "TA0011",
        "tactic_name": "Command and Control"
    }
}

# ==================================================
# TI CONFIG
# ==================================================
ALL_TI_ENGINES = ["AbuseIPDB", "VirusTotal"]
SUPPORTED_TI = ["AbuseIPDB", "VirusTotal"]
DEFAULT_ACTIVE = ["AbuseIPDB", "VirusTotal"]

MAX_RPS = 4

# ==================================================
# IP HELPERS
# ==================================================
def is_public_ip(ip):
    obj = ipaddress.ip_address(ip)
    return not (
        obj.is_private or obj.is_loopback or obj.is_multicast
        or obj.is_reserved or obj.is_link_local
    )

def expand_ip(value, max_expand=512):
    try:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=False)
            return [str(ip) for ip in list(net.hosts())[:max_expand]]
        return [str(ipaddress.ip_address(value))]
    except:
        return []

# ==================================================
# CONFIG
# ==================================================
def load_config():
    if not os.path.exists(CONFIG_FILE):
        return {"active_ti": DEFAULT_ACTIVE.copy(), "keys": {}, "locked": {}}

    with open(CONFIG_FILE, "r") as f:
        cfg = json.load(f)

    clean_keys, clean_locked = {}, {}
    for ti, enc in cfg.get("keys", {}).items():
        dec = decrypt_safe(enc)
        clean_keys[ti] = dec if dec else ""
        clean_locked[ti] = cfg.get("locked", {}).get(ti, False)

    return {
        "active_ti": cfg.get("active_ti", DEFAULT_ACTIVE),
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
# INIT
# ==================================================
config = load_config()

st.session_state.setdefault("active_ti", config["active_ti"])
for ti in ALL_TI_ENGINES:
    st.session_state.setdefault(f"{ti}_key", config["keys"].get(ti, ""))
    st.session_state.setdefault(f"{ti}_locked", config["locked"].get(ti, False))

st.session_state.setdefault("scan_results", None)
st.session_state.setdefault("mitre_stats", {})
st.session_state.setdefault("uploaded_file", None)

# ==================================================
# PAGE
# ==================================================
st.set_page_config(page_title="ViperIntel Pro", page_icon="🛡️", layout="wide")
st.title("🛡️ ViperIntel Pro")
st.markdown("### Universal Threat Intelligence & Forensic Aggregator")

# ==================================================
# SIDEBAR
# ==================================================
with st.sidebar:
    st.subheader("🔑 Global API Configuration")

    for ti in ALL_TI_ENGINES:
        st.markdown(f"**{ti}**")
        if not st.session_state[f"{ti}_locked"]:
            val = st.text_input("", type="password", key=f"inp_{ti}")
            if val:
                st.session_state[f"{ti}_key"] = val
                st.session_state[f"{ti}_locked"] = True
                save_config()
                st.rerun()
        else:
            st.markdown("••••••••••••••")
            if st.button("Edit", key=f"edit_{ti}"):
                st.session_state[f"{ti}_locked"] = False
                save_config()
                st.rerun()

    st.divider()
    if st.button("🧹 Clear Scan Data"):
        st.session_state.scan_results = None
        st.session_state.mitre_stats = {}
        st.session_state.uploaded_file = None
        audit("Scan data cleared")
        st.rerun()

# ==================================================
# FILE UPLOAD
# ==================================================
uploaded = st.file_uploader("Upload CSV / TXT (IPs or CIDRs)", type=["csv", "txt"])
if uploaded:
    st.session_state.uploaded_file = uploaded

# ==================================================
# ASYNC SCAN WORKER
# ==================================================
def scan_ip(ip):
    intel = {
        "IP": ip,
        "Abuse Score": 0,
        "VT Hits": 0,
        "Risk Score": 0,
        "Confidence": "Low",
        "MITRE Technique": "",
        "MITRE Tactic": "",
        "Status": "Clean"
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
                intel["MITRE Technique"] = MITRE_MAP["AbuseIPDB"]["technique"]
                intel["MITRE Tactic"] = MITRE_MAP["AbuseIPDB"]["tactic"]
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
                intel["MITRE Technique"] = MITRE_MAP["VirusTotal"]["technique"]
                intel["MITRE Tactic"] = MITRE_MAP["VirusTotal"]["tactic"]
        except:
            pass

    intel["Risk Score"] = min(100, int(intel["Abuse Score"] * 0.6 + intel["VT Hits"] * 10))

    # ✅ Confidence Bands (NEW)
    if intel["Risk Score"] >= 70:
        intel["Confidence"] = "High"
    elif intel["Risk Score"] >= 30:
        intel["Confidence"] = "Medium"

    if intel["Risk Score"] >= 40:
        intel["Status"] = "🚨 Malicious"

    return intel

# ==================================================
# SCAN
# ==================================================
if st.button("⚡ EXECUTE DEEP SCAN"):
    if not st.session_state.uploaded_file:
        st.error("Upload a file first.")
        st.stop()

    try:
        df = pd.read_csv(st.session_state.uploaded_file, header=None)
    except EmptyDataError:
        st.error("Uploaded file is empty.")
        st.stop()

    raw_values = df.iloc[:, 0].astype(str).tolist()

    expanded = []
    for v in raw_values:
        expanded.extend(expand_ip(v.strip()))

    ips = sorted({ip for ip in expanded if is_public_ip(ip)})

    if not ips:
        st.error("No valid public IPs found.")
        st.stop()

    results = []
    mitre_count = {}

    with st.spinner("🔍 Scanning with rate limiting..."):
        with ThreadPoolExecutor(max_workers=MAX_RPS) as executor:
            futures = [executor.submit(scan_ip, ip) for ip in ips]

            for future in as_completed(futures):
                intel = future.result()
                results.append(intel)

                if intel["MITRE Technique"]:
                    mitre_count[intel["MITRE Technique"]] = mitre_count.get(intel["MITRE Technique"], 0) + 1

                time.sleep(1 / MAX_RPS)

    st.session_state.scan_results = pd.DataFrame(results)
    st.session_state.mitre_stats = mitre_count
    st.success("Scan completed.")

# ==================================================
# RESULTS
# ==================================================
if st.session_state.scan_results is not None:
    st.subheader("📋 Intelligence Report")
    st.dataframe(st.session_state.scan_results, use_container_width=True)

    st.subheader("🔥 MITRE ATT&CK Heatmap")
    heatmap_df = pd.DataFrame(
        [{"Technique": k, "Count": v} for k, v in st.session_state.mitre_stats.items()]
    )
    st.dataframe(heatmap_df, use_container_width=True)

    # ==================================================
    # STIX EXPORT (UNCHANGED)
    # ==================================================
    stix_bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": []
    }

    for _, row in st.session_state.scan_results.iterrows():
        stix_bundle["objects"].append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": f"Malicious IP {row['IP']}",
            "pattern": f"[ipv4-addr:value = '{row['IP']}']",
            "confidence":
