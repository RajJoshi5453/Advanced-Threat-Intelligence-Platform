# TIP — Threat Intelligence Platform
**Finance & Banking SOC | Infotact Solutions Internship**

## Overview
A real-world Threat Intelligence Platform simulating a Finance & Banking SOC environment. Automatically collects, enriches, scores, and visualizes threat indicators from live intelligence feeds.

## Architecture
OTX API ──────┐

├──► Ingestion Pipeline ──► MongoDB ──► Elasticsearch ──► Kibana

VirusTotal ───┘         │                   │

▼                   ▼

Normalization      Threat Scoring

│                   │

▼                   ▼

MITRE Mapping ──► Flask SOC Dashboard

│

▼

Firewall Engine ──► iptables rules

│

▼

Rollback Module

## Features
- **Live Threat Ingestion** — AlienVault OTX + VirusTotal APIs
- **Threat Scoring Engine** — Custom 0.0–1.0 risk scoring
- **MITRE ATT&CK Mapping** — Auto-maps IOCs to tactics/techniques
- **Firewall Automation** — Auto-blocks malicious IPs via iptables
- **Rollback Module** — Safely reverses false positive blocks
- **Alerting System** — Critical IOC detection alerts
- **Correlation Engine** — Groups related IOCs by domain/source
- **Flask SOC Dashboard** — Real-time threat visualization
- **Kibana Dashboard** — Elasticsearch-powered analytics
- **PDF Report Generator** — Auto-generates downloadable threat reports

## Tech Stack
| Component | Technology |
|---|---|
| Language | Python 3.13 |
| Database | MongoDB |
| Search Engine | Elasticsearch |
| Visualization | Kibana + Flask |
| Threat Feeds | AlienVault OTX, VirusTotal |
| Framework | Flask |
| Firewall | iptables |

## Project Structure
tip-project/

├── ingestion/          # OTX + VirusTotal feed ingestion

├── normalization/      # Data normalization

├── app/

│   ├── analysis/       # Threat scoring + correlation

│   ├── database/       # MongoDB client

│   ├── firewall/       # Firewall engine + alerting + rollback

│   ├── indexing/       # Elasticsearch integration

│   ├── ingestion/      # Async ingestion pipeline

│   └── dashboard/      # Kibana setup

├── dashboard/          # Flask SOC dashboard

├── extensions/         # MITRE mapping + report generator

└── tests/              # Test pipeline

## Setup & Installation
```bash
# Clone repo
git clone https://github.com/RajJoshi5453/tip-project.git
cd tip-project

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp config/.env.example config/.env
# Add your OTX_API_KEY and MONGO_URI

# Start services
sudo systemctl start mongodb
sudo systemctl start elasticsearch
sudo systemctl start kibana

# Run ingestion
python ingestion/otx_feed.py

# Start dashboard
python dashboard/app.py
```

## Dashboard
- **Flask SOC Dashboard:** http://localhost:5000
- **Kibana Analytics:** http://localhost:5601
- **PDF Report:** http://localhost:5000/report

## MITRE ATT&CK Coverage
Finance & Banking focused techniques including:
- T1566 Phishing / Spearphishing
- T1486 Data Encrypted for Impact (Ransomware)
- T1071 Command and Control
- T1185 Browser Session Hijacking
- T1539 Steal Web Session Cookie
- T1557 Adversary-in-the-Middle
- T1110 Brute Force

## Author
**Raj Joshi** — Cybersecurity Intern, Infotact Solutions
