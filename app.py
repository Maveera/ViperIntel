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
.metric-card { background:#161b22; padding:20px; border-radius:10px; border:1px solid #1f2937; text-align:center; }
.key-freeze { background:rgba(255,255,255,0.05); padding:8px; border-radius:6px; font-family:monospace; }
</style>
""", unsafe_allow_html=True)

# =========================
# UTILITIES
# =========================
def valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except:
        return False

def fingerprint(ip):
    return hashlib.sha256(ip.encode()).hexdigest()

# =========================
# RISK MODEL
# =========================
ENGINE_WEIGHTS = {
    "AbuseIPDB": 0.4,
    "VirusTotal": 0.5,
    "AlienVaultOTX": 0.3,
    "IPQualityScore": 0.4
}

def calculate_risk(intel):
    score = 0
    reasons = []

    if intel["Abuse Score"] >= 25:
        score += intel["Abuse Score"] * ENGINE_WEIGHTS["AbuseIPDB"]
        reasons.append("AbuseIPDB confidence")

    if intel["VT Hits"] > 0:
        score += 100 * ENGINE_WEIGHTS["VirusTotal"]
        reasons.append("VirusTotal detections")

    if intel["OTX Pulses"] > 0:
        score += 60 * ENGINE_WEIGHTS["AlienVaultOTX"]
        reasons.append("OTX pulse association")

    if intel["IPQS Fraud Score"] >= 75:
        score += intel["IPQS Fraud Score"] * ENGINE_WEIGHTS["IPQualityScore"]
        reasons.append("IPQS high fraud score")

    if intel["Seen Before"]:
        score += 15
        reasons.append("Previously observed IOC")

    return min(int(score), 100), reasons

# =========================
# MITRE ATT&CK MAPPING
# =========================
def mitre_mapping(intel):
    techniques = []
    if intel["Abuse Score"] >= 50:
        techniques.append(("T1046", "Network Service Discovery"))
    if intel["VT Hits"] > 0:
        techniques.append(("T1071", "Application Layer Protocol"))
    if intel["OTX Pulses"] > 0:
        techniques.append(("T1098", "Account Manipulation"))
    if intel["IPQS Fraud Score"] >= 75:
        techniques.append(("T1587", "Malware Infrastructure"))
    return techniques

# =========================
# ASYNC LOOKUPS
# =========================
async def abuseipdb(session, ip, key):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": key, "Accept": "application/json"}
    async with session.get(url, headers=headers, params={"ipAddress": ip}) as r:
        return (await r.json()).get("data", {})

async def virustotal(session, ip, key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": key}
    async with session.get(url, headers=headers) as r:
        return (await r.json()).get("data", {}).get("attributes", {})

async def otx(session, ip, key):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": key}
    async with session.get(url, headers=headers) as r:
        return await r.json()

async def ipqs(session, ip, key):
    url = f"https://ipqualityscore.com/api/json/ip/{key}/{ip}"
    async with session.get(url) as r:
        return await r.json()

# =========================
# ASYNC ENRICHMENT
# =========================
async def enrich_ip(ip, keys, sem):
    async with sem:
        fp = fingerprint(ip)
        seen_before = fp in st.session_state.history

        intel = {
            "IP": ip,
            "Status": "Clean",
            "Country": "Unknown",
            "ISP": "Unknown",
            "Abuse Score": 0,
            "VT Hits": 0,
            "OTX Pulses": 0,
            "IPQS Fraud Score": 0,
            "Confidence": 0,
            "Correlation": "None",
            "MITRE Techniques": [],
            "Seen Before": seen_before,
            "Timeline": datetime.utcnow().isoformat() + "Z",
            "Lat": None,
            "Lon": None
        }

        async with aiohttp.ClientSession() as session:
            if keys["AbuseIPDB"]:
                try:
                    d = await abuseipdb(session, ip, keys["AbuseIPDB"])
                    intel["Abuse Score"] = d.get("abuseConfidenceScore", 0)
                    intel["Country"] = d.get("countryName", "Unknown")
                    intel["ISP"] = d.get("isp", "Unknown")
                    intel["Lat"] = d.get("latitude")
                    intel["Lon"] = d.get("longitude")
                except: pass

            if keys["VirusTotal"]:
                try:
                    v = await virustotal(session, ip, keys["VirusTotal"])
                    intel["VT Hits"] = v.get("last_analysis_stats", {}).get("malicious", 0)
                except: pass

            if keys["AlienVaultOTX"]:
                try:
                    o = await otx(session, ip, keys["AlienVaultOTX"])
                    intel["OTX Pulses"] = len(o.get("pulse_info", {}).get("pulses", []))
                except: pass

            if keys["IPQualityScore"]:
                try:
                    q = await ipqs(session, ip, keys["IPQualityScore"])
                    intel["IPQS Fraud Score"] = q.get("fraud_score", 0)
                except: pass

        intel["Confidence"], _ = calculate_risk(intel)
        intel["MITRE Techniques"] = mitre_mapping(intel)

        hits = sum([
            intel["Abuse Score"] > 0,
            intel["VT Hits"] > 0,
            intel["OTX Pulses"] > 0,
            intel["IPQS Fraud Score"] >= 75
        ])

        intel["Correlation"] = (
            "High" if hits >= 3 else
            "Medium" if hits == 2 else
            "Low" if hits == 1 else "None"
        )

        if intel["Confidence"] >= 50:
            intel["Status"] = "🚨 Malicious"

        st.session_state.history[fp] = intel["Timeline"]
        return intel

async def run_scan(ips, keys):
    sem = asyncio.Semaphore(5)
    return await asyncio.gather(*(enrich_ip(ip, keys, sem) for ip in ips))

# =========================
# UI
# =========================
st.title("🛡️ SOC Intelligence Console")
st.markdown("#### Universal Threat Intelligence & Forensic Aggregator")

with st.sidebar:
    st.subheader("🔑 API Configuration")
    for e in ENGINES:
        if not st.session_state[f"{e}_locked"]:
            val = st.text_input(f"{e} Key", type="password")
            if val:
                st.session_state[f"{e}_key"] = val
                st.session_state[f"{e}_locked"] = True
                st.rerun()
        else:
            st.markdown(f"**{e} Key**")
            st.markdown("<div class='key-freeze'>••••••••••••••</div>", unsafe_allow_html=True)
            if st.button(f"Edit {e}"):
                st.session_state[f"{e}_locked"] = False
                st.rerun()

uploaded = st.file_uploader("Upload CSV (IPs in first column)", type=["csv"])

if st.button("⚡ EXECUTE FULL ASYNC SCAN") and uploaded:
    df = pd.read_csv(uploaded, header=None)
    ips = [ip for ip in df.iloc[:,0].astype(str) if valid_ip(ip)]
    keys = {e: st.session_state[f"{e}_key"] for e in ENGINES}

    with st.spinner("Running async enrichment…"):
        st.session_state.scan_results = pd.DataFrame(asyncio.run(run_scan(ips, keys)))

# =========================
# RESULTS
# =========================
if st.session_state.scan_results is not None:
    res = st.session_state.scan_results
    st.dataframe(res, use_container_width=True)

    m = folium.Map(location=[20,0], zoom_start=2, tiles="CartoDB dark_matter")
    for _, r in res.iterrows():
        if r["Lat"] and r["Lon"]:
            folium.CircleMarker(
                [r["Lat"], r["Lon"]],
                radius=7,
                color="red" if r["Status"]!="Clean" else "#00ffcc",
                fill=True
            ).add_to(m)
    st_folium(m, width=1200, height=450)
