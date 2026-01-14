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
st.set_page_config(page_title="ViperIntel Pro", page_icon="🐍", layout="wide")

# --- Custom Styling ---
st.markdown("""
    <style>
    .stApp { background-color: #0d1117; color: #c9d1d9; }
    .stButton>button { background-color: #238636; color: white; border-radius: 5px; }
    footer { visibility: hidden; }
    .custom-footer {
        position: fixed; left: 0; bottom: 0; width: 100%;
        background-color: #161b22; color: #8b949e;
        text-align: center; padding: 10px; border-top: 1px solid #30363d;
    }
    </style>
    """, unsafe_allow_html=True)

# --- Email Function ---
def send_email_report(to_email, df, sender, pwd):
    try:
        msg = MIMEMultipart()
        msg['Subject'] = "🐍 ViperIntel Pro: Threat Intelligence Report"
        msg['From'], msg['To'] = sender, to_email
        msg.attach(MIMEText("Your automated threat report is attached.", 'plain'))

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
    except Exception as e:
        st.error(f"Email Failed: {e}")
        return False

# --- Sidebar: User Config ---
with st.sidebar:
    st.title("🛡️ TI Command Center")
    st.info("Input your personal API keys to begin.")
    abuse_api = st.text_input("AbuseIPDB Key", type="password")
    vt_api = st.text_input("VirusTotal Key", type="password")
    otx_api = st.text_input("AlienVault OTX Key", type="password")
    ipqs_api = st.text_input("IPQualityScore Key", type="password")
    
    st.divider()
    enable_email = st.checkbox("Enable Email Reports")
    s_email = st.text_input("Sender Gmail (App Password required)")
    s_pass = st.text_input("App Password", type="password")
    t_email = st.text_input("Recipient Email")

# --- Main Dashboard ---
st.title("🐍 ViperIntel Pro")
st.caption("Open-Source Multi-Engine Threat Intelligence Dashboard")

uploaded_file = st.file_uploader("Upload CSV (IP addresses in first column)", type=["csv"])

if st.button("⚡ Execute Global Scan") and uploaded_file:
    if not all([abuse_api, vt_api, otx_api, ipqs_api]):
        st.error("Missing API Keys! Please fill out the sidebar.")
    else:
        df_ips = pd.read_csv(uploaded_file)
        ips = df_ips.iloc[:, 0].dropna().unique().tolist()
        results = []
        progress = st.progress(0)

        for i, ip in enumerate(ips):
            intel = {"IP": ip, "Risk": "Clean", "Lat": None, "Lon": None}
            
            # 1. AbuseIPDB
            try:
                r = requests.get("https://api.abuseipdb.com/api/v2/check", 
                                 headers={"Key": abuse_api, "Accept":"application/json"},
                                 params={"ipAddress": ip}).json()
                intel["Abuse Score"] = r['data'].get('abuseConfidenceScore', 0)
                intel["Lat"], intel["Lon"] = r['data'].get('latitude'), r['data'].get('longitude')
                intel["Country"] = r['data'].get('countryName')
            except: intel["Abuse Score"] = 0

            # 2. VirusTotal
            try:
                r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", 
                                 headers={"x-apikey": vt_api}).json()
                intel["VT Detections"] = r['data']['attributes']['last_analysis_stats'].get('malicious', 0)
            except: intel["VT Detections"] = 0

            # 3. AlienVault OTX
            try:
                r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general", 
                                 headers={"X-OTX-API-KEY": otx_api}).json()
                intel["OTX Pulses"] = r.get('pulse_info', {}).get('count', 0)
            except: intel["OTX Pulses"] = 0

            # 4. IPQualityScore
            try:
                r = requests.get(f"https://www.ipqualityscore.com/api/json/ip/{ipqs_api}/{ip}").json()
                intel["Fraud Score"] = r.get('fraud_score', 0)
            except: intel["Fraud Score"] = 0

            # Logic Check
            if intel["Abuse Score"] > 25 or intel["VT Detections"] > 0 or intel["Fraud Score"] > 75:
                intel["Risk"] = "🚨 High Risk"
            
            results.append(intel)
            progress.progress((i + 1) / len(ips))
            time.sleep(0.5)

        res_df = pd.DataFrame(results)
        st.success("Analysis Complete!")

        # --- Visualizations ---
        st.subheader("🌐 Geographic Threat Origin")
        m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
        for _, r in res_df.dropna(subset=['Lat', 'Lon']).iterrows():
            color = 'red' if r['Risk'] != 'Clean' else 'cyan'
            folium.CircleMarker([r['Lat'], r['Lon']], radius=7, color=color, fill=True).add_to(m)
        st_folium(m, width=1200, height=400)

        st.subheader("📊 Master Threat Intelligence Report")
        st.dataframe(res_df.drop(columns=['Lat', 'Lon']), use_container_width=True)

        # Email Trigger
        if enable_email and t_email and s_pass:
            if send_email_report(t_email, res_df, s_email, s_pass):
                st.toast(f"Report emailed to {t_email}!")

# --- Footer ---
st.markdown('<div class="custom-footer">© 2026 All Rights Reserved | Maveera</div>', unsafe_allow_html=True)
