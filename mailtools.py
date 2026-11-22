from __future__ import annotations
import re
from email import policy
from email.parser import Parser
from urllib.parse import urlparse
from scanner import analyze_url

URL_RE=re.compile(r"https?://[^\s<>\"']+",re.I)
IP_RE=re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
DOMAIN_RE=re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b")
ATTACHMENT_RISK={".exe",".scr",".js",".jse",".vbs",".vbe",".bat",".cmd",".ps1",".hta",".iso",".img",".lnk",".jar",".apk",".msi",".dll",".docm",".xlsm",".pptm"}

def analyze_email(raw: str) -> dict:
    raw=str(raw or "")[:100000]
    msg=Parser(policy=policy.default).parsestr(raw)
    headers={k:str(v) for k,v in msg.items()}
    findings=[]; score=0
    sender=headers.get("From",""); reply=headers.get("Reply-To","")
    if reply and sender and reply.lower()!=sender.lower():
        score+=15; findings.append("Reply-To differs from From; inspect carefully.")
    auth=headers.get("Authentication-Results","").lower()
    if auth:
        for method in ("spf","dkim","dmarc"):
            if re.search(r"\b"+method+r"=fail\b",auth): score+=15; findings.append(method.upper()+" authentication failure reported.")
            elif re.search(r"\b"+method+r"=pass\b",auth): findings.append(method.upper()+" pass reported by supplied header (not independently verified).")
    else: findings.append("No Authentication-Results header provided; authentication cannot be evaluated.")
    urls=sorted(set(URL_RE.findall(raw)))
    url_reports=[analyze_url(u.rstrip(".,);]")) for u in urls[:30]]
    if any(r["score"]>=45 for r in url_reports): score+=20; findings.append("One or more extracted URLs have elevated heuristic risk.")
    if not urls: findings.append("No HTTP(S) URLs extracted.")
    names=[]
    for part in msg.walk():
        filename=part.get_filename()
        if filename:
            names.append(filename)
            ext="."+filename.lower().rsplit(".",1)[-1] if "." in filename else ""
            if ext in ATTACHMENT_RISK: score+=10; findings.append("Risky attachment extension: "+filename)
    if not headers.get("Subject"): findings.append("Missing subject header.")
    if not findings: findings.append("No obvious indicators found; this is not a verdict.")
    score=min(100,score)
    level="Low" if score<20 else "Moderate" if score<45 else "High"
    return {"score":score,"level":level,"findings":findings,"headers":headers,"urls":url_reports,"attachments":names}

def extract_iocs(text: str) -> dict:
    text=str(text or "")[:100000]
    urls=sorted(set(x.rstrip(".,);]") for x in URL_RE.findall(text)))
    ips=sorted(set(IP_RE.findall(text)))
    domains=sorted(set(DOMAIN_RE.findall(text)))
    # Exclude hosts already represented by extracted URL text.
    url_hosts={urlparse(u).hostname for u in urls}
    domains=[d for d in domains if d.lower() not in url_hosts]
    return {"urls":urls[:100],"ipv4":ips[:100],"domains":domains[:100]}
