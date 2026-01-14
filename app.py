import streamlit as st
import requests
import pandas as pd
import time
import folium
import ipaddress
import json
from datetime import datetime
from streamlit_folium import st_folium

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="ViperIntel Pro | By Maveera",
    page_icon="🛡️",
    layout="wide"
)

# ---------------- SESSION STATE ----------------
engines = ["AbuseIPDB", "VirusTotal", "AlienVault OTX", "IPQualityScore"]
for e in engines:
    st.session_state.setdefault(f"{e}_key", "")
    st.session_state.setdefault(f"{e}_locked", False)

st.session_state.setdefault("scan_results", None)

# ---------------- STYLES ----------------
st.markdown("""
<style>
.stApp { background-color: #0a0e14; color: #e0e6ed; }
.author-text { color: #00ffcc; font-weight: bold; font-size: 18px; }
footer { visibility:hidden; }

div.stButton > button:first-child {
    background-color: #00ffcc !important;
    color: #0a0e14 !important;
    font-weight: bold !important;
    width: 100% !important;
    height: 3.8em !important;
    border-radius: 10px !important;
    border: none !important;
    box-shadow: 0px 0px 15px #00ffcc;
}

.key-freeze-row {
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 8px;
    padding: 8px;
    font-family: monospace;
    letter-spacing: 2px;
}

.metric-card {
    background: #161b22;
    padding: 20px;
    border-radius: 10px;
    border: 1px solid #1f2937;
    text-align: center;
}

.custom-footer {
    position: fixed; left: 0; bottom: 0; width: 100%;
    background: rgba(10,14,20,0.95);
    color: #94a3b8; padding: 15px;
    border-top: 1px solid #1f2937;
    text-align: center;
}
</style>
""", unsafe_allow_html=True)

# ---------------- UTILITIES ----------------
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def confidence_score(abuse, vt):
    score = 0
    if abuse >= 75: score += 60
    elif abuse >= 25: score += 30
    if vt > 0: score += 40
    return min(score, 100)

def verdict_reason(intel):
    reasons = []
    if intel["Abuse Score"] > 25:
        reasons.append("AbuseIPDB confidence exceeded threshold")
    if intel["VT Hits"] > 0:
        reasons.append("VirusTotal detections present")
    return "; ".join(reasons) if reasons else "No malicious indicators"

# ---------------- HEADER ----------------
col1, col2 = st.columns([5,1])
with col1:
    st.title("🛡️ SOC Intelligence Console")
    st.markdown("#### Universal Threat Intelligence & Forensic Aggregator")
with col2:
    if st.button("🔄 RESET"):
        st.session_state.scan_results = None
        st.rerun()

# ---------------- SIDEBAR ----------------
with st.sidebar:
    st.markdown("## 🛡️ TI Command Center")
    st.markdown("Developed by: <span class='author-text'>Maveera</span>", unsafe_allow_html=True)
    st.divider()

    def api_input(label, engine):
        if not st.session_state[f"{engine}_locked"]:
            val = st.text_input(label, type="password", key=f"in_{engine}")
            if val:
                st.session_state[f"{engine}_key"] = val
                st.session_state[f"{engine}_locked"] = True
                st.rerun()
        else:
            st.markdown(f"**{label}**")
            cols = st.columns([3,1])
            cols[0].markdown("<div class='key-freeze-row'>••••••••••••••••</div>", unsafe_allow_html=True)
            if cols[1].button("Edit", key=f"edit_{engine}"):
                st.session_state[f"{engine}_locked"] = False
                st.rerun()

    for e in engines:
        api_input(f"{e} Key", e)

# ---------------- UPLOAD ----------------
uploaded_file = st.file_uploader("Upload CSV (IPs in first column)", type=["csv"])

# ---------------- SCAN ----------------
if st.button("⚡ EXECUTE DEEP SCAN") and uploaded_file:
    if not any(st.session_state[f"{e}_key"] for e in engines):
        st.error("Configure at least one API key.")
        st.stop()

    df = pd.read_csv(uploaded_file, header=None)
    raw_ips = df.iloc[:,0].astype(str).str.strip().tolist()

    ips, invalid_ips = [], []
    for ip in raw_ips:
        if is_valid_ip(ip):
            ips.append(ip)
        else:
            invalid_ips.append(ip)

    if not ips:
        st.error("No valid IPs found.")
        st.stop()

    results = []
    progress = st.progress(0)
    status = st.empty()

    for i, ip in enumerate(ips):
        status.markdown(f"🔍 **Analyzing:** `{ip}` ({i+1}/{len(ips)})")

        intel = {
            "IP": ip,
            "Status": "Clean",
            "Country": "Unknown",
            "ISP": "Unknown",
            "AS Number": "N/A",
            "Network": "N/A",
            "Last Analysis": "N/A",
            "Abuse Score": 0,
            "VT Hits": 0,
            "Confidence": 0,
            "Verdict Reason": "",
            "Engines Hit": [],
            "Timeline": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "Lat": None,
            "Lon": None,
            "Raw JSON": {}
        }

        # AbuseIPDB
        if st.session_state["AbuseIPDB_key"]:
            try:
                r = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": st.session_state["AbuseIPDB_key"], "Accept": "application/json"},
                    params={"ipAddress": ip}
                ).json()
                d = r.get("data", {})
                intel["Abuse Score"] = d.get("abuseConfidenceScore", 0)
                intel["ISP"] = d.get("isp", "Unknown")
                intel["Country"] = d.get("countryName", "Unknown")
                intel["Lat"] = d.get("latitude")
                intel["Lon"] = d.get("longitude")
                if intel["Abuse Score"] > 0:
                    intel["Engines Hit"].append("AbuseIPDB")
                intel["Raw JSON"]["AbuseIPDB"] = d
            except Exception as e:
                intel["Raw JSON"]["AbuseIPDB"] = {"error": str(e)}

        # VirusTotal
        if st.session_state["VirusTotal_key"]:
            try:
                r = requests.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey": st.session_state["VirusTotal_key"]}
                ).json()
                attr = r["data"]["attributes"]
                intel["VT Hits"] = attr["last_analysis_stats"].get("malicious", 0)
                intel["AS Number"] = f"AS {attr.get('asn','N/A')}"
                intel["Network"] = attr.get("network","N/A")
                ts = attr.get("last_analysis_date",0)
                intel["Last Analysis"] = time.strftime("%Y-%m-%d %H:%M", time.gmtime(ts)) if ts else "Never"
                if intel["VT Hits"] > 0:
                    intel["Engines Hit"].append("VirusTotal")
                intel["Raw JSON"]["VirusTotal"] = attr
            except Exception as e:
                intel["Raw JSON"]["VirusTotal"] = {"error": str(e)}

        intel["Confidence"] = confidence_score(intel["Abuse Score"], intel["VT Hits"])
        intel["Verdict Reason"] = verdict_reason(intel)
        if intel["Confidence"] >= 50:
            intel["Status"] = "🚨 Malicious"

        results.append(intel)
        progress.progress((i+1)/len(ips))
        time.sleep(0.05)

    st.session_state.scan_results = pd.DataFrame(results)
    status.empty()

    if invalid_ips:
        with st.expander("⚠️ Invalid IOCs Skipped"):
            st.write(invalid_ips)

# ---------------- RESULTS ----------------
if st.session_state.scan_results is not None:
    res = st.session_state.scan_results
    res.index = res.index + 1
    res.index.name = "S.No"

    c1,c2,c3 = st.columns(3)
    c1.markdown(f"<div class='metric-card'><b>Total IPs</b><h2>{len(res)}</h2></div>", unsafe_allow_html=True)
    c2.markdown(f"<div class='metric-card'><b>Malicious</b><h2 style='color:#ff4b4b'>{len(res[res['Status']!='Clean'])}</h2></div>", unsafe_allow_html=True)
    c3.markdown(f"<div class='metric-card'><b>Clean</b><h2>{len(res[res['Status']=='Clean'])}</h2></div>", unsafe_allow_html=True)

    st.subheader("🌐 Geographic Threat Origin")
    fmap = folium.Map(location=[20,0], zoom_start=2, tiles="CartoDB dark_matter")
    for _, r in res.iterrows():
        if r["Lat"] and r["Lon"]:
            folium.CircleMarker(
                [r["Lat"], r["Lon"]],
                radius=8,
                color="red" if r["Status"]!="Clean" else "#00ffcc",
                fill=True
            ).add_to(fmap)
    st_folium(fmap, width=1200, height=500)

    st.subheader("📋 Intelligence Report")
    st.dataframe(res.drop(columns=["Lat","Lon","Raw JSON"]), use_container_width=True)

    st.subheader("🧠 SOC Analysis Panels")
    for _, r in res.iterrows():
        with st.expander(f"{r['IP']} | {r['Status']} | Confidence {r['Confidence']}%"):
            st.markdown(f"**Verdict Reason:** {r['Verdict Reason']}")
            st.markdown(f"**Engines Hit:** {', '.join(r['Engines Hit']) or 'None'}")
            st.markdown(f"**Timeline:** {r['Timeline']}")
            if st.checkbox("Show Raw JSON", key=f"json_{r['IP']}"):
                st.json(r["Raw JSON"])

    st.download_button(
        "📥 DOWNLOAD CSV",
        data=res.to_csv(index=True).encode(),
        file_name="ViperIntel_Report.csv",
        mime="text/csv"
    )

# ---------------- FOOTER ----------------
st.markdown(
    "<div class='custom-footer'>© 2026 ViperIntel Pro | Developed by "
    "<a href='https://maveera.tech' target='_blank' style='color:#00ffcc'>Maveera</a></div>",
    unsafe_allow_html=True
)
