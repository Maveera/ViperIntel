import streamlit as st
import pandas as pd
import aiohttp
import asyncio
import ipaddress
import folium
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
ENGINES = ["AbuseIPDB", "VirusTotal"]
for e in ENGINES:
    st.session_state.setdefault(f"{e}_key", "")
    st.session_state.setdefault(f"{e}_locked", False)

st.session_state.setdefault("scan_results", None)

# =========================
# STYLES (UNCHANGED)
# =========================
st.markdown("""
<style>
.stApp { background-color:#0a0e14; color:#e0e6ed; }
footer { visibility:hidden; }
.metric-card { background:#161b22; padding:20px; border-radius:10px; border:1px solid #1f2937; text-align:center; }
.key-freeze-row { background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.1); border-radius:8px; padding:8px; font-family:monospace; }
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

# =========================
# RISK SCORING MODEL
# =========================
ENGINE_WEIGHTS = {
    "AbuseIPDB": 0.6,
    "VirusTotal": 0.8
}

def calculate_risk(abuse, vt):
    score = 0
    reasons = []

    if abuse >= 25:
        score += abuse * ENGINE_WEIGHTS["AbuseIPDB"]
        reasons.append("AbuseIPDB confidence")

    if vt > 0:
        score += 100 * ENGINE_WEIGHTS["VirusTotal"]
        reasons.append("VirusTotal detections")

    score = min(int(score), 100)
    return score, reasons

# =========================
# MITRE ATT&CK MAPPING
# =========================
def mitre_mapping(intel):
    techniques = []

    if intel["Abuse Score"] >= 50:
        techniques.append(("T1046", "Network Service Discovery"))

    if intel["VT Hits"] > 0:
        techniques.append(("T1071", "Application Layer Protocol"))

    return techniques

# =========================
# ASYNC ENRICHMENT
# =========================
async def abuseipdb_lookup(session, ip, key):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": key, "Accept": "application/json"}
    params = {"ipAddress": ip}
    async with session.get(url, headers=headers, params=params) as r:
        js = await r.json()
        return js.get("data", {})

async def virustotal_lookup(session, ip, key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": key}
    async with session.get(url, headers=headers) as r:
        js = await r.json()
        return js.get("data", {}).get("attributes", {})

async def enrich_ip(ip, keys, sem):
    async with sem:
        intel = {
            "IP": ip,
            "Status": "Clean",
            "Country": "Unknown",
            "ISP": "Unknown",
            "Abuse Score": 0,
            "VT Hits": 0,
            "Confidence": 0,
            "Correlation": "None",
            "MITRE Techniques": [],
            "Timeline": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "Lat": None,
            "Lon": None
        }

        async with aiohttp.ClientSession() as session:
            if keys["AbuseIPDB"]:
                try:
                    d = await abuseipdb_lookup(session, ip, keys["AbuseIPDB"])
                    intel["Abuse Score"] = d.get("abuseConfidenceScore", 0)
                    intel["Country"] = d.get("countryName", "Unknown")
                    intel["ISP"] = d.get("isp", "Unknown")
                    intel["Lat"] = d.get("latitude")
                    intel["Lon"] = d.get("longitude")
                except:
                    pass

            if keys["VirusTotal"]:
                try:
                    v = await virustotal_lookup(session, ip, keys["VirusTotal"])
                    intel["VT Hits"] = v.get("last_analysis_stats", {}).get("malicious", 0)
                except:
                    pass

        intel["Confidence"], reasons = calculate_risk(intel["Abuse Score"], intel["VT Hits"])

        if intel["Abuse Score"] > 0 and intel["VT Hits"] > 0:
            intel["Correlation"] = "High (Multi-engine agreement)"
        elif intel["Abuse Score"] > 0 or intel["VT Hits"] > 0:
            intel["Correlation"] = "Medium (Single-engine)"

        intel["MITRE Techniques"] = mitre_mapping(intel)

        if intel["Confidence"] >= 50:
            intel["Status"] = "🚨 Malicious"

        return intel

async def run_scan(ips, keys):
    sem = asyncio.Semaphore(5)
    tasks = [enrich_ip(ip, keys, sem) for ip in ips]
    return await asyncio.gather(*tasks)

# =========================
# UI
# =========================
st.title("🛡️ SOC Intelligence Console")
st.markdown("#### Universal Threat Intelligence & Forensic Aggregator")

with st.sidebar:
    st.markdown("## 🔑 API Configuration")
    for e in ENGINES:
        if not st.session_state[f"{e}_locked"]:
            val = st.text_input(f"{e} Key", type="password")
            if val:
                st.session_state[f"{e}_key"] = val
                st.session_state[f"{e}_locked"] = True
                st.rerun()
        else:
            st.markdown(f"**{e} Key**")
            st.markdown("<div class='key-freeze-row'>••••••••••••••</div>", unsafe_allow_html=True)
            if st.button(f"Edit {e}"):
                st.session_state[f"{e}_locked"] = False
                st.rerun()

uploaded = st.file_uploader("Upload CSV (IPs in first column)", type=["csv"])

if st.button("⚡ EXECUTE ASYNC SCAN") and uploaded:
    df = pd.read_csv(uploaded, header=None)
    raw_ips = df.iloc[:,0].astype(str).tolist()
    ips = [ip for ip in raw_ips if valid_ip(ip)]

    keys = {e: st.session_state[f"{e}_key"] for e in ENGINES}

    with st.spinner("Running async enrichment..."):
        results = asyncio.run(run_scan(ips, keys))

    st.session_state.scan_results = pd.DataFrame(results)

# =========================
# RESULTS
# =========================
if st.session_state.scan_results is not None:
    res = st.session_state.scan_results

    c1,c2,c3 = st.columns(3)
    c1.markdown(f"<div class='metric-card'><b>Total IPs</b><h2>{len(res)}</h2></div>", unsafe_allow_html=True)
    c2.markdown(f"<div class='metric-card'><b>Malicious</b><h2 style='color:red'>{len(res[res['Status']!='Clean'])}</h2></div>", unsafe_allow_html=True)
    c3.markdown(f"<div class='metric-card'><b>Clean</b><h2>{len(res[res['Status']=='Clean'])}</h2></div>", unsafe_allow_html=True)

    st.subheader("🌍 Threat Map")
    fmap = folium.Map(location=[20,0], zoom_start=2, tiles="CartoDB dark_matter")
    for _, r in res.iterrows():
        if r["Lat"] and r["Lon"]:
            folium.CircleMarker(
                [r["Lat"], r["Lon"]],
                radius=7,
                color="red" if r["Status"]!="Clean" else "#00ffcc",
                fill=True
            ).add_to(fmap)
    st_folium(fmap, width=1200, height=450)

    st.subheader("📋 Intelligence Report")
    st.dataframe(res, use_container_width=True)

    st.subheader("🧠 MITRE ATT&CK Mapping")
    for _, r in res.iterrows():
        with st.expander(f"{r['IP']} | {r['Status']} | Confidence {r['Confidence']}%"):
            if r["MITRE Techniques"]:
                for t in r["MITRE Techniques"]:
                    st.markdown(f"- **{t[0]}** — {t[1]}")
            else:
                st.markdown("No ATT&CK techniques inferred.")
