# Phishing Lab · Threat Console (v2)

Local defensive toolkit for URL triage and awareness scenarios. It does not harvest credentials, OTPs, cookies, session tokens, or clone real provider login pages.

## Features
- Single URL heuristic scan
- Batch analysis (up to 25 URLs)
- URL risk score with findings
- Punycode, IP-host, shortener, deep-subdomain, user-info, nonstandard-port and keyword indicators
- CSV event export and JSON event API
- Local click-only awareness scenario
- SQLite event log
- Runs on loopback only (127.0.0.1)

## Install & run (Termux/Linux)
```bash
git clone https://github.com/GOKUxEDITION/Phishing-tool-.git
cd Phishing-tool-
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Visit http://127.0.0.1:5000

## Notes
The scanner does not open/fetch submitted URLs, avoiding SSRF and remote interaction. Scores are heuristic indicators and must not be treated as definitive verdicts.