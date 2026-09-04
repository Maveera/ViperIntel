# Viper Intel — SOC Threat Intelligence & IOC Investigation Platform (Offline)

A lightweight, standalone SOC Threat Intelligence suite that runs **100% locally and offline** in your browser via Streamlit. No external APIs, no API keys, no third-party lookups, no databases — every analysis is computed in-memory with an explainable, deterministic engine.

## Core Workflow

```
IOC Input → Local Analysis Engine → Explainable Risk Score → MITRE ATT&CK → Offline SOC Analyst → Recommendations → Session Dashboard
```

## Supported IOC Types (Auto-Detected)

- IPv4 / IPv6
- Domain / URL
- SHA256 / SHA1 / MD5
- CVE
- Email Address / Hostname

## Features

| View | Description |
|------|-------------|
| **Dashboard** | Session metrics (Total Scans / Malicious / Suspicious / Clean), recent activity table, verdict distribution chart. |
| **Investigate** | Single-IOC investigation: 0–100 explainable Viper Risk Score, verdict, confidence, "why risky" factor breakdown, SOC Analyst analysis, MITRE ATT&CK mapping, Markdown report export. |
| **Threat Map** | Spatial distribution visualization using PyDeck for IP-based indicators plus an entropy-mapped regional view. |
| **Bulk Analysis** | Upload CSV/TXT to batch-scan IOCs offline; results table with download-to-CSV. |
| **Watchlist** | In-memory session watchlist for tracking monitored indicators. |
| **Investigation History** | Reopen and review every investigation performed in the current session. |

## Offline Analysis Engine

- **`core/detector.py`** — RegEx engine that detects all supported IOC types and handles CIDR expansion / bulk-file parsing.
- **`core/offline_intel.py`** — Local heuristics: Shannon entropy (DGA detection), high-risk TLD checks (.zip, .top, .xyz, .cc, .tk …), suspicious-pattern rules, and a curated catalog of critical CVEs (CISA KEV entries such as Log4Shell, MOVEit, FortiOS, PrintNightmare, Cisco IOS XE, PHP-CGI, etc.).
- **`core/risk_engine.py`** — Explainable 0–100 risk scoring with per-factor breakdown.
- **`core/ai_engine.py`** — Deterministic, context-locked SOC Analyst producing Executive Summary, Technical Analysis, MITRE ATT&CK mapping, and actionable SOC recommendations. No external LLM calls.

## Risk Score Scale

| Score | Verdict | Severity |
|-------|---------|----------|
| 0–19  | CLEAN | Informational |
| 20–39 | LOW | Low |
| 40–59 | SUSPICIOUS | Medium |
| 60–79 | MALICIOUS | High |
| 80–100| MALICIOUS | Critical |

Every score is explained with concrete factors, e.g. `+35 High-Risk TLD`, `+30 DGA Entropy`, `+85 CISA KEV Cataloged`.

## Quick Start (Local)

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Deploy on Streamlit Cloud

1. Push this repository to GitHub.
2. In the Streamlit Cloud dashboard, click **New app** → select repo & branch → Main file `app.py`.
3. No secrets, keys, or environment variables are required — the app runs entirely offline.

## Requirements

```
streamlit>=1.32.0
pandas>=2.0.0
pydeck>=0.8.0
```

## Privacy

Viper Intel performs no network calls. All IOC analysis, scoring, and reporting happens locally in your browser session. Investigation history and watchlist data live only in `st.session_state` and are discarded when the session ends.