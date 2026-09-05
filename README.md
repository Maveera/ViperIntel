# Viper Intel — SOC Threat Intelligence Scanner (Multi-Feed API)

A Streamlit-based SOC toolkit for **bulk IP / hash / domain / URL / CVE triage**
against **your configurable threat-intelligence feeds**. Correlate independent
feeds into one explainable 0–100 risk score with a colour-coded verdict table
and charts. No hardcoded API keys — you supply them at runtime.

## Core Workflow

```
Bulk IOC Upload / Paste → Auto-Detect Type → Query Configured TI Feeds (threaded) → Aggregate Risk Score 0–100 → Colour-Coded Verdict Table + Charts → Drill-Down Evidence → Recommendations
```

## Supported IOC Types (Auto-Detected)

- IPv4 / IPv6
- Domain / URL
- SHA256 / SHA1 / MD5
- CVE
- Email Address / Hostname

## Supported TI Feeds (API-configurable)

| Feed | IOC Types | Key | Notes |
|------|-----------|-----|-------|
| VirusTotal | IP · domain · URL · hashes | required | engine detections, reputation, ASN |
| AbuseIPDB | IP | required | abuse-confidence % + reports |
| AlienVault OTX | IP · domain · URL · hashes · CVE | required | pulses, tags, malware families, threat actors |
| GreyNoise | IP | required | noise / riot / classification |
| Shodan | IP | required | open ports + exposed CVEs |
| URLScan.io | IP · domain · URL | required | scan history |

Only feeds for which an API key is configured are queried — there are no
"always-on" free feeds, and a missing key or failed request marks the feed as
unavailable and **never crashes the scan**.

## Features

| View | Description |
|------|-------------|
| **Dashboard** | Session metrics, verdict distribution chart, critical findings, full dataset table. |
| **Bulk Analysis** | Upload CSV/TXT or paste IOCs; threaded multi-feed scan; **colour-coded verdict table** (red/orange/yellow/green), risk-score bars, confidence, feed/signal counts, per-IOC drill-down, **CSV / JSON export**, **Refresh Data** and **Reset Data** controls. |
| **Investigate** | Single-IOC deep dive: per-feed evidence, structured intel JSON, risk-factor breakdown, MITRE ATT&CK, SOC recommendations. |

No accounts, logins, or databases are needed — provide your TI-feed API keys in
the sidebar and the app is fully operational. Scanned results are automatically
remembered for the session and restored after a refresh (`viperintel_data.pkl`
snapshot, git-ignored); the API keys themselves live only in the browser.

## API Key Configuration

Add keys in the **sidebar → API Key Configuration**. Only add the feeds you
need — pick a feed from the dropdown, type its key, and press **Enter**. Keys
are **stored only in your browser** (localStorage) — nothing is written to the
server, to the repository, or to code. Keys are always **masked** on the page
(revealed only as the last 4 characters via the 👁 button). Each saved
key has a **👁 view**, **✏️ edit**, and **🗑 delete** button.

## Risk Score Scale

| Score | Verdict | Severity |
|-------|---------|----------|
| 0–21  | CLEAN | Informational |
| 22–39 | LOW | Low |
| 40–59 | SUSPICIOUS | Medium |
| 60–79 | MALICIOUS | High |
| 80–100| MALICIOUS | Critical |

Scores are explainable with concrete factors, e.g.
`+60 VirusTotal Detections`, `+40 AbuseIPDB Score`.

## Quick Start (Local)

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Deploy on Streamlit Cloud

1. Push this repository to GitHub.
2. In Streamlit Cloud → **New app** → select repo & branch → Main file `app.py`.
3. Open the app and enter your API keys in the **sidebar** — they stay in your
   own browser and never touch the server.

## Embed on another site (e.g. your Vercel page)

Community Cloud apps can be embedded with the `?embed=true` query parameter:

```html
<iframe
  src="https://<your-app>.streamlit.app/?embed=true"
  height="900"
  style="width:100%;border:none;"
></iframe>
```

**Security binding**: this app only renders when embedded by an approved
origin. The allowlist defaults to `https://inspira-center-command.vercel.app`
and can be changed with the `VIPER_ALLOWED_EMBED_ORIGINS` environment variable
(comma-separated). Any other site that tries to frame it sees a lockout message
instead of the app. Opening the app directly (without embedding) always works.
`VIPER_ALLOWED_EMBED_ORIGINS` is the app's only optional environment variable.

> Note: keep the embedded app public, and make sure the parent page is served
> over HTTPS, or Safari may hide the frame due to third-party cookie blocking.

## Requirements

```
streamlit>=1.32.0
streamlit-javascript>=0.1.5
pandas>=2.0.0
requests>=2.31.0
```

## Privacy

Indicator lookups only ever go to the threat-intelligence feeds you configure —
feeds without a key are never queried. API keys are never written to the
repository, the server, or logs; they live in your browser's localStorage only.