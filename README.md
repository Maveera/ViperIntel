# 🐍 ViperIntel Pro
### Multi-Engine IP Reputation & Geospatial Analysis Dashboard

[![Open Source Love](https://badges.frapsoft.com/os/v1/open-source.svg?v=103)](https://github.com/ellerbrock/open-source-badges/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**ViperIntel Pro** is a high-performance Threat Intelligence (TI) tool designed to help security analysts cross-reference suspicious IP addresses against the world's leading reputation databases. 

[Image of a professional cyber threat intelligence dashboard architecture]

---

## 🚀 Key Capabilities
- **Universal Aggregation:** One-click scanning across **AbuseIPDB**, **VirusTotal**, **AlienVault OTX**, and **IPQualityScore**.
- **Live Mapping:** Real-time satellite visualization of IP origins to identify geographic attack patterns.
- **Fraud Detection:** Detects VPNs, Proxies, and high-risk residential connections.
- **Email Automation:** Automatically sends a CSV intel report to your inbox upon scan completion.
- **Private & Secure:** We do not store your API keys. They are used only for the duration of your session.

---

## 🛠️ Quick Start

### For Users
1. Access the web app: `[PASTE_YOUR_STREAMLIT_LINK_HERE]`
2. Enter your API keys in the sidebar.
3. Upload a CSV of IPs and hit **Execute Deep Scan**.

### For Developers (Local Install)
```bash
# Clone the repo
git clone [https://github.com/yourusername/viperintel-pro.git](https://github.com/yourusername/viperintel-pro.git)

# Install requirements
pip install -r requirements.txt

# Run the dashboard
streamlit run app.py

#🔑 Required API Keys
ViperIntel Pro requires your own API keys to function. Most have free tiers:

AbuseIPDB API
VirusTotal API
AlienVault OTX
IPQualityScore



### 3. The `requirements.txt` (Essential)
Create another file named `requirements.txt` and paste this:

streamlit
requests
pandas
folium
streamlit-folium
streamlit-lottie
