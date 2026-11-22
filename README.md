# Phishing Lab & URL Threat Analyzer

A local-only phishing-awareness lab and URL risk analyzer. It **does not collect credentials, OTPs, cookies, session tokens, or impersonate real login providers**.

## Features
- Flask dashboard for URL risk analysis
- Heuristic checks for suspicious URLs (IP hosts, punycode, URL shorteners, risky keywords, excessive subdomains, HTTP)
- Local awareness simulation landing page with event logging (clicks only)
- SQLite event log
- Runs on localhost by default

## Run (Termux/Linux)
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

## Scope
Use only for defensive analysis and awareness simulations. The simulation intentionally has no password/OTP input, credential storage, external deployment, stealth, or provider-brand cloning.
