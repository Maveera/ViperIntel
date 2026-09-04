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
| NVD | CVE | optional | CVSS base score + description |
| CISA KEV | CVE | none | known-exploited flag |
| EPSS | CVE | none | exploitation probability percentile |

Feeds degrade gracefully: a missing key or failed request marks the feed as
unavailable and **never crashes the scan**.

## Features

| View | Description |
|------|-------------|
| **Dashboard** | Session metrics, verdict distribution chart, critical findings, full dataset table. |
| **Bulk Analysis** | Upload CSV/TXT or paste IOCs; threaded multi-feed scan; **colour-coded verdict table** (red/orange/yellow/green), risk-score bars, confidence, feed/signal counts, CSV export, per-IOC drill-down. |
| **Investigate** | Single-IOC deep dive: per-feed evidence, structured intel JSON, risk-factor breakdown, MITRE ATT&CK, SOC recommendations. |
| **Threat Map** | PyDeck scatter of geo-located indicators (country from IP feeds). |
| **Watchlist** | In-memory tracking of indicators under monitoring. |
| **Investigation History** | Every investigation performed in the current session. |

## API Key Configuration

Add keys in the **sidebar → API Key Configuration**. Keys are kept in the
session only; they can also be
[configured as Streamlit secrets](https://docs.streamlit.io/develop/concepts/connections/secrets-management)
or environment variables with the names shown beside each feed:

- `VIRUSTOTAL_API_KEY` · `ABUSEIPDB_API_KEY` · `ALIENVault_API_KEY` · `GREYNOISE_API_KEY` · `SHODAN_API_KEY` · `URLSCAN_API_KEY` · `NVD_API_KEY`

"💾 Save config" stores keys encrypted locally (`config.json` + `.secret.key`,
Fernet). Add `config.json` and `.secret.key` to `.gitignore` (already done).

## Risk Score Scale

| Score | Verdict | Severity |
|-------|---------|----------|
| 0–21  | CLEAN | Informational |
| 22–39 | LOW | Low |
| 40–59 | SUSPICIOUS | Medium |
| 60–79 | MALICIOUS | High |
| 80–100| MALICIOUS | Critical |

Scores are explainable with concrete factors, e.g. `+85 CISA KEV Cataloged`,
`+60 VirusTotal Detections`, `+40 AbuseIPDB Score`.

## Quick Start (Local)

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Deploy on Streamlit Cloud

1. Push this repository to GitHub.
2. In Streamlit Cloud → **New app** → select repo & branch → Main file `app.py`.
3. Add your API keys under Streamlit Cloud → **Settings → Secrets** using the
   environment-variable names above (or enter them in the sidebar at runtime).

## Requirements

```
streamlit>=1.32.0
pandas>=2.0.0
pydeck>=0.8.0
requests>=2.31.0
cryptography>=41.0.0
```

## Privacy

Indicator lookups only ever go to the threat-intelligence feeds you configure.
API keys are never written to the repository or logs; they live in your session
(or your private Streamlit secrets). Local analysis uses in-memory heuristics
(entropy / TLD / known CVE catalog) to supplement feed hits.