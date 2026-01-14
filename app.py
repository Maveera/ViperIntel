import streamlit as st
import requests
import pandas as pd
import time
import smtplib
import folium
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from io import StringIO
from streamlit_folium import st_folium

# --- Page Config ---
st.set_page_config(page_title="ViperIntel Pro | By Maveera", page_icon="🐍", layout="wide")

# --- UI Styling ---
st.markdown("""
    <style>
    .stApp { background-color: #0a0e14; color: #e0e6ed; }
    .author-text { color: #00ffcc; font-weight: bold; font-size: 18px; }
    footer { visibility: hidden; }
    .custom-footer {
        position: fixed; left: 0; bottom: 0; width: 100%;
        background-color: rgba(10, 14, 20, 0.95); color: #94a3b8;
        text-align: center; padding: 15px; border-top: 1px solid #1f2937;
        z-index: 1000;
    }
    .custom-footer a { color: #00ffcc; text-decoration: none; font-weight: bold; }
    .help-card { background: #161b22; padding: 15px; border-radius: 8px; border-left: 4px solid #00ffcc; margin-bottom: 10px; }
    .stButton>button { background-color: #00ffcc; color: #0a0e14; font-weight: bold; border: none; width: 100%; height: 3em;}
    .coffee-btn { display: inline-block; background-color: #FFDD00; color: #000000; padding: 10px 20px; border-radius: 5px; text-decoration: none; font-weight: bold; margin-top: 10px; text-align: center;}
    </style>
    """, unsafe_allow_html=True)

# --- Email Logic ---
def send_email_report(to_email, df, sender, pwd):
    try:
        msg = MIMEMultipart()
        msg['Subject'] = "🐍 ViperIntel Pro: Threat Report by Maveera"
        msg['From'], msg['To'] = sender, to_email
        msg.attach(MIMEText("Report attached.", 'plain'))
        csv_buffer = StringIO()
        df.to_csv(csv_buffer, index=False)
        part = MIMEApplication(csv_buffer.getvalue(), Name="ViperIntel_Report.csv")
        part['Content-Disposition'] = 'attachment; filename="ViperIntel_Report.csv"'
        msg.attach(part)
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender, pwd)
            server.send_message(msg)
        return True
    except: return False

# --- Sidebar ---
with st.sidebar:
    st.markdown("## 🛡️ ViperIntel Pro")
    st.markdown(f"Developed by: <span class='author-text'>Maveera</span>", unsafe_allow_html=True)
    st.markdown("[🌐 Visit Website](https://maveera.tech)")
    
    st.divider()
    st.subheader("🔑 API Configuration")
    use_abuse = st.toggle("AbuseIPDB", value=True)
    abuse_api = st.text_input("Key", type="password", key="a1") if use_abuse else None
    
    use_vt = st.toggle("VirusTotal", value=True)
    vt_api = st.text_input("Key", type="password", key="v1") if use_vt else None
    
    use_otx = st.toggle("AlienVault OTX", value=False)
    otx_api = st.text_input("Key", type="password", key="o1") if use_otx else None
    
    use_ipqs = st.toggle("IPQualityScore", value=False)
    ipqs_api = st.text_input("Key", type="password", key="i1") if use_ipqs else None

    st.divider()
    st.subheader("📬 Auto-Email")
    enable_email = st.checkbox("Email Report")
    if enable_email:
        s_email = st.text_input("Sender Gmail")
        s_pass = st.text_input("App Password", type="password")
        t_email = st.text_input("Target Email")

    st.divider()
    st.markdown("### ☕ Support the Project")
    # Replace URL with your actual Buy Me a Coffee link
    st.markdown('<a href="https://www.buymeacoffee.com/maveera" target="_blank" class="coffee-btn">☕ Buy Me a Coffee</a>', unsafe_allow_html=True)

# --- Main Dashboard ---
st.title("🐍 ViperIntel Pro")
st.markdown("#### Universal Threat Intelligence Aggregator")

# Expandable Guide
with st.expander("📘 API & Threat Intel Guide (Tutorial)"):
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("<div class='help-card'><b>AbuseIPDB:</b> Flags IPs reported for brute-force/spam.</div>", unsafe_allow_html=True)
        st.markdown("<div class='help-card'><b>VirusTotal:</b> Checks 70+ AV engines for malicious flagging.</div>", unsafe_allow_html=True)
    with c2:
        st.markdown("<div class='help-card'><b>AlienVault OTX:</b> Crowdsourced investigations into malware pulses.</div>", unsafe_allow_html=True)
        st.markdown("<div class='help-card'><b>IPQS:</b> Fraud scoring and VPN/Proxy detection.</div>", unsafe_allow_html=True)

uploaded_file = st.file_uploader("Upload CSV (IPs in first column)", type=["csv"])

if st.button("⚡ EXECUTE DEEP SCAN") and uploaded_file:
    active_keys = [abuse_api, vt_api, otx_api, ipqs_api]
    if not any(active_keys):
        st.error("❌ Please enable at least one engine and enter an API key.")
    else:
        df_ips = pd.read_csv(uploaded_file)
        ips = df_ips.iloc[:, 0].dropna().unique().tolist()
        results = []
        progress = st.progress(0)
        status_box = st.empty()

        for i, ip in enumerate(ips):
            status_box.text(f"Scanning: {ip}")
            intel = {"IP": ip, "Status": "Clean", "Lat": 20.0, "Lon": 0.0}

            if abuse_api:
                try:
                    r = requests.get("https://api.abuseipdb.com/api/v2/check", headers={"Key": abuse_api, "Accept":"application/json"}, params={"ipAddress": ip}).json()
                    intel["Abuse Score"] = r['data'].get('abuseConfidenceScore', 0)
                    intel["Lat"], intel["Lon"] = r['data'].get('latitude'), r['data'].get('longitude')
                except: intel["Abuse Score"] = "Err"
            
            if vt_api:
                try:
                    r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey": vt_api}).json()
                    intel["VT Hits"] = r['data']['attributes']['last_analysis_stats'].get('malicious', 0)
                except: intel["VT Hits"] = "Err"

            if otx_api:
                try:
                    r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general", headers={"X-OTX-API-KEY": otx_api}).json()
                    intel["OTX Pulses"] = r.get('pulse_info', {}).get('count', 0)
                except: intel["OTX Pulses"] = "Err"

            if ipqs_api:
                try:
                    r = requests.get(f"https://www.ipqualityscore.com/api/json/ip/{ipqs_api}/{ip}").json()
                    intel["Fraud Score"] = r.get('fraud_score', 0)
                except: intel["Fraud Score"] = "Err"

            # Risk Logic
            vals = [intel.get("Abuse Score", 0), intel.get("VT Hits", 0), intel.get("Fraud Score", 0)]
            if any(isinstance(v, int) and v > 25 for v in vals): intel["Status"] = "🚨 High Risk"
            
            results.append(intel)
            progress.progress((i + 1) / len(ips))
            time.sleep(0.3)

        res_df = pd.DataFrame(results)
        st.success("✅ Analysis Complete!")

        # Visuals
        m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
        for _, r in res_df.iterrows():
            if isinstance(r['Lat'], (int, float)):
                folium.CircleMarker([r['Lat'], r['Lon']], radius=7, color='red' if r['Status'] != 'Clean' else '#00ffcc', fill=True).add_to(m)
        st_folium(m, width=1200, height=400)
        st.dataframe(res_df.drop(columns=['Lat', 'Lon']), use_container_width=True)

        if enable_email and t_email:
            if send_email_report(t_email, res_df, s_email, s_pass):
                st.toast("📧 Report sent to inbox!")

# --- Footer ---
st.markdown(f"""
    <div class="custom-footer">
        © 2026 ViperIntel Pro | Developed by <a href="https://maveera.tech" target="_blank">Maveera</a>
    </div>
    """, unsafe_allow_html=True)
