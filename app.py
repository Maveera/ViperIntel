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

# --- UI Styling & High-Contrast Design ---
st.markdown("""
    <style>
    .stApp { background-color: #0a0e14; color: #e0e6ed; }
    .author-text { color: #00ffcc; font-weight: bold; font-size: 18px; }
    footer { visibility: hidden; }
    
    /* Sticky Footer Styling */
    .custom-footer {
        position: fixed; left: 0; bottom: 0; width: 100%;
        background-color: rgba(10, 14, 20, 0.95); color: #94a3b8;
        text-align: center; padding: 15px; border-top: 1px solid #1f2937;
        z-index: 1000;
    }
    .custom-footer a { color: #00ffcc; text-decoration: none; font-weight: bold; }
    
    /* High-Contrast EXECUTE Button Old Design */
    div.stButton > button:first-child {
        background-color: #00ffcc !important;
        color: #0a0e14 !important;
        font-weight: bold !important;
        border: none !important;
        width: 100% !important;
        height: 3.8em !important;
        font-size: 18px !important;
        border-radius: 8px !important;
        box-shadow: 0px 4px 15px rgba(0, 255, 204, 0.4);
        margin-top: 20px;
    }
    div.stButton > button:hover {
        background-color: #00ccaa !important;
        box-shadow: 0px 6px 20px rgba(0, 255, 204, 0.6);
        transform: translateY(-2px);
    }
    
    /* Metric Card Styling */
    .metric-container { background: #161b22; padding: 20px; border-radius: 10px; border: 1px solid #1f2937; text-align: center; }
    .help-card { background: #161b22; padding: 15px; border-radius: 8px; border-left: 4px solid #00ffcc; margin-bottom: 10px; }
    </style>
    """, unsafe_allow_html=True)

# --- Email Logic ---
def send_email_report(to_email, df, sender, pwd):
    try:
        msg = MIMEMultipart()
        msg['Subject'] = "🐍 ViperIntel Pro: Threat Intelligence Report"
        msg['From'], msg['To'] = sender, to_email
        msg.attach(MIMEText("The automated IP reputation scan is complete. Report attached.", 'plain'))
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

# --- Sidebar Configuration ---
with st.sidebar:
    st.markdown("## 🛡️ ViperIntel Pro")
    st.markdown(f"Developed by: <span class='author-text'>Maveera</span>", unsafe_allow_html=True)
    st.markdown("[🌐 Portfolio](https://maveera.tech)")
    st.divider()
    
    st.subheader("🔑 API Key Configuration")
    abuse_api = st.text_input("AbuseIPDB Key", type="password")
    vt_api = st.text_input("VirusTotal Key", type="password")
    otx_api = st.text_input("AlienVault OTX Key", type="password")
    ipqs_api = st.text_input("IPQualityScore Key", type="password")
    
    st.divider()
    st.subheader("📬 Reporting Settings")
    enable_email = st.checkbox("Enable Auto-Email")
    if enable_email:
        s_email = st.text_input("Sender Gmail")
        s_pass = st.text_input("App Password", type="password")
        t_email = st.text_input("Recipient Email")

    st.divider()
    st.markdown("### ☕ Support the Project")
    st.markdown('<a href="https://www.buymeacoffee.com/maveera" target="_blank" style="display:block; background:#FFDD00; color:black; padding:12px; border-radius:5px; text-align:center; text-decoration:none; font-weight:bold;">☕ Buy Me a Coffee</a>', unsafe_allow_html=True)

# --- Main Dashboard ---
st.title("🐍 ViperIntel Pro")
st.markdown("#### Universal Threat Intelligence Aggregator & Tracker")

# Guide Dropdown
with st.expander("📘 API Configuration Guide & TI Tutorial"):
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("<div class='help-card'><b>AbuseIPDB:</b> Flags IPs reported for brute-force & spam. Confidence > 25% = Risk.</div>", unsafe_allow_html=True)
        st.markdown("<div class='help-card'><b>VirusTotal:</b> Checks 70+ engines. Any 'Hits' indicate a malicious record.</div>", unsafe_allow_html=True)
    with c2:
        st.markdown("<div class='help-card'><b>AlienVault OTX:</b> Open Threat Exchange investigating pulses and campaigns.</div>", unsafe_allow_html=True)
        st.markdown("<div class='help-card'><b>IPQS:</b> Fraud scoring. Detects hidden VPNs, Proxies, and Tor exit nodes.</div>", unsafe_allow_html=True)

uploaded_file = st.file_uploader("Upload CSV (IP addresses in the first column)", type=["csv"])

if st.button("⚡ EXECUTE DEEP SCAN") and uploaded_file:
    if not any([abuse_api, vt_api, otx_api, ipqs_api]):
        st.error("❌ Configuration Error: Please provide at least one API key in the sidebar.")
    else:
        # Load and clean IPs
        df_ips = pd.read_csv(uploaded_file)
        ips = df_ips.iloc[:, 0].dropna().unique().tolist()
        
        results = []
        progress = st.progress(0)
        status_box = st.empty()

        for i, ip in enumerate(ips):
            status_box.markdown(f"🔍 **Scanning:** `{ip}` ({i+1}/{len(ips)})")
            intel = {"IP": ip, "Status": "Clean", "Abuse Score": 0, "VT Hits": 0, "OTX Pulses": 0, "Fraud Score": 0, "Lat": 20.0, "Lon": 0.0}

            # 1. AbuseIPDB
            if abuse_api:
                try:
                    r = requests.get("https://api.abuseipdb.com/api/v2/check", 
                                     headers={"Key": abuse_api, "Accept":"application/json"},
                                     params={"ipAddress": ip}).json()
                    intel["Abuse Score"] = r['data'].get('abuseConfidenceScore', 0)
                    intel["Lat"], intel["Lon"] = r['data'].get('latitude'), r['data'].get('longitude')
                except: pass

            # 2. VirusTotal
            if vt_api:
                try:
                    r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", 
                                     headers={"x-apikey": vt_api}).json()
                    intel["VT Hits"] = r['data']['attributes']['last_analysis_stats'].get('malicious', 0)
                except: pass
            
            # 3. AlienVault OTX
            if otx_api:
                try:
                    r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general", 
                                     headers={"X-OTX-API-KEY": otx_api}).json()
                    intel["OTX Pulses"] = r.get('pulse_info', {}).get('count', 0)
                except: pass

            # 4. IPQualityScore
            if ipqs_api:
                try:
                    r = requests.get(f"https://www.ipqualityscore.com/api/json/ip/{ipqs_api}/{ip}").json()
                    intel["Fraud Score"] = r.get('fraud_score', 0)
                except: pass

            # Unified Risk Logic
            if (isinstance(intel["Abuse Score"], int) and intel["Abuse Score"] > 25) or (intel["VT Hits"] > 0) or (intel.get("Fraud Score", 0) > 75):
                intel["Status"] = "🚨 Malicious"
            
            results.append(intel)
            progress.progress((i + 1) / len(ips))
            time.sleep(0.3)

        status_box.empty()
        res_df = pd.DataFrame(results)
        malicious_count = len(res_df[res_df["Status"] == "🚨 Malicious"])

        # === DISPLAY SECTION ===
        st.markdown("### 📊 Real-Time Scan Metrics")
        m1, m2, m3 = st.columns(3)
        with m1:
            st.markdown(f"<div class='metric-container'><b>Total IPs Scanned</b><br><h2 style='color:#00ffcc;'>{len(ips)}</h2></div>", unsafe_allow_html=True)
        with m2:
            st.markdown(f"<div class='metric-container'><b>Malicious Found</b><br><h2 style='color:#ff4b4b;'>{malicious_count}</h2></div>", unsafe_allow_html=True)
        with m3:
            st.markdown(f"<div class='metric-container'><b>Safe IPs</b><br><h2 style='color:#00ffcc;'>{len(ips) - malicious_count}</h2></div>", unsafe_allow_html=True)

        st.subheader("🌐 Geographic Threat Origin Map")
        m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
        for _, r in res_df.iterrows():
            marker_color = 'red' if r['Status'] == '🚨 Malicious' else '#00ffcc'
            folium.CircleMarker([r['Lat'], r['Lon']], radius=8, color=marker_color, fill=True, fill_opacity=0.7, popup=r['IP']).add_to(m)
        st_folium(m, width=1200, height=450)

        st.subheader("📋 Detailed Intelligence Report")
        st.dataframe(res_df.drop(columns=['Lat', 'Lon']), use_container_width=True)

        # CSV Download
        csv_data = res_df.to_csv(index=False).encode('utf-8')
        st.download_button("📥 Download Intelligence Report (CSV)", data=csv_data, file_name="ViperIntel_Full_Report.csv", mime="text/csv")

        # Email Trigger
        if enable_email and t_email and s_pass:
            if send_email_report(t_email, res_df, s_email, s_pass):
                st.toast("📧 Report sent successfully!", icon="📩")

# --- Footer ---
st.markdown(f"""
    <div class="custom-footer">
        © 2026 ViperIntel Pro | Developed by <a href="https://maveera.tech" target="_blank">Maveera</a>
    </div>
    """, unsafe_allow_html=True)
