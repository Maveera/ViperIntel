import streamlit as st
import requests
import pandas as pd
import json, os, time
from cryptography.fernet import Fernet, InvalidToken
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

# ================= FILE PATHS =================
CONFIG_FILE = "config.json"
KEY_FILE = ".secret.key"

# ================= ENCRYPTION =================
def load_or_create_key():
    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE, "wb") as f:
            f.write(Fernet.generate_key())
    return open(KEY_FILE, "rb").read()

FERNET = Fernet(load_or_create_key())

def encrypt(v): 
    return FERNET.encrypt(v.encode()).decode()

def decrypt_safe(v):
    try:
        return FERNET.decrypt(v.encode()).decode()
    except InvalidToken:
        return ""

# ================= THREAT INTEL SOURCES =================
ALL_TI = [
    # IP / Network / Reputation
    "AbuseIPDB","IPQualityScore","GreyNoise","Spamhaus","Project Honey Pot",
    "Talos Reputation","FortiGuard IP Reputation","Barracuda Reputation",
    "Proofpoint ET Intelligence","CleanTalk","SANS ISC","Team Cymru",
    "Shadowserver IP Feeds","SpamCop Blocking List","OpenBL",
    "Blocklist.de","FireHOL IP Lists",

    # Malware / Sandbox / IOC
    "VirusTotal","MalwareBazaar","ThreatFox","VirusShare","Hybrid Analysis",
    "Any.Run","Joe Sandbox","InQuest Labs","ReversingLabs",
    "OPSWAT MetaDefender","MalShare","YARAify","PolySwarm",
    "Cuckoo Sandbox Feeds",

    # Phishing / URL / Domain
    "OpenPhish","PhishTank","URLhaus","Google Safe Browsing",
    "Microsoft SmartScreen","Netcraft","SpamCop URI","SURBL",
    "PhishStats","APWG eCrime Exchange","Cofense Intelligence",
    "Proofpoint URL Defense","Palo Alto URL Filtering",

    # Open / CERT / Community
    "AlienVault OTX","MISP","OpenCTI","Abuse.ch","CIRCL","FIRST.org",
    "CERT-IN","US-CERT (CISA)","NCSC UK","CERT-EU","JPCERT/CC",
    "KISA","AusCERT","GovCERT.ch",

    # Enterprise / Vendor
    "Microsoft Defender Threat Intelligence","Cisco Talos","IBM X-Force Exchange",
    "Palo Alto Unit 42","CrowdStrike Falcon Intelligence","Recorded Future",
    "Kaspersky Threat Intelligence","Check Point ThreatCloud","Trend Micro TI",
    "SophosLabs","Secureworks CTU","Mandiant Advantage","Bitdefender TI",
    "Zscaler ThreatLabZ","Akamai Threat Intelligence","Cloudflare Radar",
    "Rapid7 InsightIDR",

    # Blockchain / Fraud / Abuse
    "Chainalysis","TRM Labs","CipherTrace","Elliptic","Abuse.ch SSLBL",
    "ScamAdviser"
]


SUPPORTED_TI = ["AbuseIPDB", "VirusTotal"]
DEFAULT_ACTIVE = ["AbuseIPDB", "VirusTotal"]

# ================= MITRE MAP =================
MITRE_MAP = {
    "AbuseIPDB": {"technique": "T1046", "tactic": "TA0043"},
    "VirusTotal": {"technique": "T1105", "tactic": "TA0011"}
}

MAX_RPS = 4

# ================= CONFIG =================
def load_config():
    if not os.path.exists(CONFIG_FILE):
        return {"active": DEFAULT_ACTIVE.copy(), "keys": {}, "locked": {}}

    with open(CONFIG_FILE) as f:
        cfg = json.load(f)

    keys, locked = {}, {}
    for ti in ALL_TI:
        enc = cfg.get("keys", {}).get(ti)
        keys[ti] = decrypt_safe(enc) if enc else ""
        locked[ti] = cfg.get("locked", {}).get(ti, False)

    return {
        "active": cfg.get("active", DEFAULT_ACTIVE),
        "keys": keys,
        "locked": locked
    }

def save_config():
    with open(CONFIG_FILE, "w") as f:
        json.dump({
            "active": st.session_state.active_ti,
            "keys": {
                ti: encrypt(st.session_state[f"{ti}_key"])
                for ti in ALL_TI if st.session_state.get(f"{ti}_key")
            },
            "locked": {
                ti: st.session_state.get(f"{ti}_locked", False)
                for ti in ALL_TI
            }
        }, f, indent=2)

# ================= INIT =================
cfg = load_config()
st.session_state.setdefault("active_ti", cfg["active"])

for ti in ALL_TI:
    st.session_state.setdefault(f"{ti}_key", cfg["keys"].get(ti, ""))
    st.session_state.setdefault(f"{ti}_locked", cfg["locked"].get(ti, False))

st.session_state.setdefault("scan_results", None)
st.session_state.setdefault("uploaded_file", None)

# ================= PAGE =================
st.set_page_config("ViperIntel Pro", "🐍", layout="wide")
st.title("🐍 ViperIntel Pro")
st.markdown("### Universal Threat Intelligence & Forensic Aggregator")

# ================= SIDEBAR =================
with st.sidebar:
    st.subheader("🔑 Global API Configuration")

    for ti in st.session_state.active_ti:
        st.markdown(f"**{ti}**")

        if not st.session_state[f"{ti}_locked"]:
            val = st.text_input(f"{ti} API Key", type="password", key=f"input_{ti}")
            if val:
                st.session_state[f"{ti}_key"] = val
                st.session_state[f"{ti}_locked"] = True
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
            save_config()
            st.rerun()

        st.divider()

    inactive = [ti for ti in ALL_TI if ti not in st.session_state.active_ti]
    add_ti = st.selectbox("➕ Add Threat Intelligence Source", ["Select"] + inactive)
    if add_ti != "Select":
        st.session_state.active_ti.append(add_ti)
        save_config()
        st.rerun()

    st.divider()
    st.markdown(
        """
        <a href="https://www.buymeacoffee.com/maveera" target="_blank"
        style="display:block;background:#FFDD00;color:#000;
        padding:10px;border-radius:6px;
        text-align:center;font-weight:bold;text-decoration:none;">
        ☕ Buy Me a Coffee
        </a>
        """,
        unsafe_allow_html=True
    )

    st.divider()
    if st.button("🧹 Clear Scan Data"):
        st.session_state.scan_results = None
        st.session_state.uploaded_file = None
        st.rerun()

# ================= FILE UPLOAD =================
uploaded = st.file_uploader("Upload CSV / TXT (IPs or CIDRs)", ["csv", "txt"])
if uploaded:
    st.session_state.uploaded_file = uploaded

# ================= IP HELPERS =================
def is_public_ip(ip):
    o = ipaddress.ip_address(ip)
    return not (o.is_private or o.is_loopback or o.is_reserved or o.is_multicast)

def expand(v):
    try:
        if "/" in v:
            return [str(ip) for ip in ipaddress.ip_network(v, strict=False).hosts()]
        return [str(ipaddress.ip_address(v))]
    except:
        return []

# ================= SCAN WORKER =================
def scan_ip(ip, abuse_key, vt_key):
    r = {
        "IP": ip,
        "Abuse Score": 0,
        "VT Hits": 0,
        "Risk Score": 0,
        "Confidence": "Low",
        "MITRE Technique": "",
        "MITRE Tactic": "",
        "Status": "Clean"
    }

    if abuse_key:
        try:
            d = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": abuse_key, "Accept": "application/json"},
                params={"ipAddress": ip}, timeout=10
            ).json()
            r["Abuse Score"] = d.get("data", {}).get("abuseConfidenceScore", 0)
            if r["Abuse Score"] > 0:
                r["MITRE Technique"] = MITRE_MAP["AbuseIPDB"]["technique"]
                r["MITRE Tactic"] = MITRE_MAP["AbuseIPDB"]["tactic"]
        except:
            pass

    if vt_key:
        try:
            d = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": vt_key}, timeout=10
            ).json()
            r["VT Hits"] = d["data"]["attributes"]["last_analysis_stats"].get("malicious", 0)
            if r["VT Hits"] > 0:
                r["MITRE Technique"] = MITRE_MAP["VirusTotal"]["technique"]
                r["MITRE Tactic"] = MITRE_MAP["VirusTotal"]["tactic"]
        except:
            pass

    r["Risk Score"] = min(100, int(r["Abuse Score"] * 0.6 + r["VT Hits"] * 10))

    if r["Risk Score"] >= 70:
        r["Confidence"] = "High"
    elif r["Risk Score"] >= 30:
        r["Confidence"] = "Medium"

    if r["Risk Score"] >= 40:
        r["Status"] = "🚨 Malicious"

    return r

# ================= EXECUTE SCAN =================
if st.button("⚡ EXECUTE DEEP SCAN"):
    if not st.session_state.uploaded_file:
        st.error("Upload a file first.")
        st.stop()

    df = pd.read_csv(st.session_state.uploaded_file, header=None)
    expanded = []
    for v in df.iloc[:, 0].astype(str):
        expanded.extend(expand(v.strip()))

    ips = sorted({ip for ip in expanded if is_public_ip(ip)})
    if not ips:
        st.error("No valid public IPs.")
        st.stop()

    abuse_key = st.session_state.get("AbuseIPDB_key")
    vt_key = st.session_state.get("VirusTotal_key")

    if not (abuse_key or vt_key):
        st.error("Configure at least one API key.")
        st.stop()

    results = []
    with st.spinner("🔍 Scanning..."):
        with ThreadPoolExecutor(MAX_RPS) as ex:
            futures = [ex.submit(scan_ip, ip, abuse_key, vt_key) for ip in ips]
            for f in as_completed(futures):
                results.append(f.result())
                time.sleep(1 / MAX_RPS)

    st.session_state.scan_results = pd.DataFrame(results)

# ================= RESULTS (UPDATED OUTPUT ONLY) =================
if st.session_state.scan_results is not None:
    df = st.session_state.scan_results.copy()

    # ✅ S.NO starting from 1
    df.insert(0, "S.NO", range(1, len(df) + 1))

    # ✅ Column selector
    st.subheader("📋 Intelligence Report")
    selected_cols = st.multiselect(
        "Select columns to display",
        options=df.columns.tolist(),
        default=df.columns.tolist()
    )

    st.dataframe(df[selected_cols], use_container_width=True)

# ================= FOOTER =================
st.markdown(
    """
    <style>
    .viper-footer {
        position: fixed;
        bottom: 0;
        left: 0;
        width: 100%;
        background: rgba(2, 6, 23, 0.96);
        border-top: 1px solid #1f2937;
        z-index: 9999;
    }

    .viper-footer-content {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        text-align: center;
        padding: 12px 10px;
        color: #94a3b8;
        font-size: 14px;
        gap: 4px;
    }

    .viper-footer-content a {
        color: #00ffcc;
        text-decoration: none;
        font-weight: 600;
    }

    @media (max-width: 768px) {
        .viper-footer-content {
            font-size: 13px;
            padding: 10px 6px;
        }
    }
    </style>

    <div class="viper-footer">
        <div class="viper-footer-content">
            <div>© 2026 <b>ViperIntel Pro</b></div>
            <div>
                Developed by 
                <a href="https://maveera.tech" target="_blank">Maveera</a>
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True
)
