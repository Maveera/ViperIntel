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

# ================= GLOBAL TI (SOURCE OF TRUTH) =================
ALL_TI_ENGINES = [
    # IP / Reputation
    "AbuseIPDB","IPQualityScore","GreyNoise","Spamhaus","Project Honey Pot",
    "IPInfo","MaxMind","Spur.us","CleanTalk","SANS ISC","Talos Reputation",
    "FortiGuard IP Reputation","Barracuda Reputation","Proofpoint ET Intelligence",

    # Malware / Sandbox
    "VirusTotal","Hybrid Analysis","Any.Run","Joe Sandbox","MalwareBazaar",
    "VirusShare","ThreatFox","InQuest","ReversingLabs","OPSWAT MetaDefender",
    "YARAify","MalShare",

    # Phishing / URL
    "OpenPhish","PhishTank","URLhaus","Google Safe Browsing",
    "Microsoft SmartScreen","Netcraft","APWG eCrime Exchange",
    "Cofense Intelligence","SpamCop","SURBL","PhishStats",

    # Open / CERT
    "AlienVault OTX","MISP","CIRCL","Shadowserver","Abuse.ch","FIRST.org",
    "CERT-EU","US-CERT (CISA)","NCSC UK","CERT-IN","Team Cymru",

    # Enterprise
    "Microsoft Defender Threat Intelligence","IBM X-Force","Cisco Talos",
    "Palo Alto Unit42","CrowdStrike Falcon Intelligence","Recorded Future",
    "Kaspersky Threat Intelligence","Check Point ThreatCloud",
    "Secureworks CTU","Mandiant","Trend Micro TI","Bitdefender TI",
    "SophosLabs","Rapid7 InsightIDR","ESET Threat Intelligence",
    "Zscaler ThreatLabZ","Akamai Threat Intelligence","Cloudflare Radar"
]

SUPPORTED_TI = ["AbuseIPDB", "VirusTotal"]
DEFAULT_ACTIVE = ["AbuseIPDB", "VirusTotal", "AlienVault OTX"]

# ================= CONFIG =================
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

# ================= INIT =================
config = load_config()

st.session_state.setdefault("active_ti", config["active_ti"])
st.session_state["inactive_ti"] = sorted(list(set(ALL_TI_ENGINES) - set(st.session_state.active_ti)))

for ti in ALL_TI_ENGINES:
    st.session_state.setdefault(f"{ti}_key", config["keys"].get(ti, ""))
    st.session_state.setdefault(f"{ti}_locked", config["locked"].get(ti, False))

st.session_state.setdefault("scan_results", None)
st.session_state.setdefault("uploaded_file", None)

# ================= PAGE =================
st.set_page_config(page_title="ViperIntel Pro", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.stApp { background: radial-gradient(circle at top left, #0f172a, #020617); }
footer { visibility:hidden; }

.custom-footer {
    position: fixed;
    bottom: 0;
    width: 100%;
    background: rgba(2,6,23,0.95);
    color: #94a3b8;
    text-align: center;
    padding: 14px;
    border-top: 1px solid #1f2937;
}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ ViperIntel Pro")
st.markdown("### Universal Threat Intelligence & Forensic Aggregator")

# ================= SIDEBAR =================
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
            audit(f"{ti} removed")
            save_config()
            st.rerun()

    for ti in st.session_state.active_ti:
        ti_block(ti)

    st.divider()
    add_ti = st.selectbox("➕ Add Threat Intelligence Source", ["Select TI"] + st.session_state.inactive_ti)
    if add_ti != "Select TI":
        st.session_state.active_ti.append(add_ti)
        audit(f"{add_ti} added")
        save_config()
        st.rerun()

    st.divider()
    st.markdown("""
    <a href="https://www.buymeacoffee.com/maveera" target="_blank"
    style="display:block;text-align:center;
    background:#FFDD00;color:#000;
    padding:10px;border-radius:8px;
    font-weight:bold;text-decoration:none;">
    ☕ Buy Me a Coffee
    </a>
    """, unsafe_allow_html=True)

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
        st.error("❌ Configure at least one supported TI (AbuseIPDB / VirusTotal).")
    elif not st.session_state.uploaded_file:
        st.error("❌ Upload a CSV file.")
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
<div class="custom-footer">
© 2026 <b>ViperIntel Pro</b> | All Rights Reserved
</div>
""", unsafe_allow_html=True)
