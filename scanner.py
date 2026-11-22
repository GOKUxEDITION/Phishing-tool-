from __future__ import annotations
import ipaddress, re
from urllib.parse import urlparse, unquote

SHORTENERS = {"bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","cutt.ly","tiny.cc","rb.gy","lnkd.in"}
RISK_WORDS = {"login","verify","verification","account","secure","update","password","wallet","billing","confirm","free","gift","signin","sign-in","urgent","unlock","suspended","recover","auth"}
BRAND_WORDS = {"instagram","facebook","whatsapp","paypal","google","microsoft","apple","amazon","netflix"}

def analyze_url(raw: str) -> dict:
    raw = str(raw or "").strip()[:2048]
    if not raw: return {"input":"","score":0,"level":"Unknown","findings":["Enter a URL."],"host":""}
    candidate = raw if re.match(r"^https?://", raw, re.I) else "https://" + raw
    findings=[]; score=0
    try:
        p=urlparse(candidate); host=(p.hostname or "").lower().rstrip(".")
    except Exception:
        return {"input":raw,"score":100,"level":"High","findings":["URL parsing failed."],"host":""}
    if p.scheme not in {"http","https"}: score+=25; findings.append("Unexpected URL scheme.")
    if p.scheme != "https": score+=15; findings.append("Not using HTTPS.")
    if not host: score+=35; findings.append("Missing hostname.")
    try:
        ipaddress.ip_address(host); score+=25; findings.append("Host is a raw IP address.")
    except ValueError: pass
    if "xn--" in host: score+=20; findings.append("Punycode hostname: inspect for homograph risk.")
    if host in SHORTENERS: score+=20; findings.append("URL-shortener host obscures destination.")
    if len(host.split(".")) >= 5: score+=10; findings.append("Deep subdomain structure.")
    if "@" in p.netloc: score+=25; findings.append("User-info syntax may visually disguise the hostname.")
    if p.port and p.port not in {80,443}: score+=10; findings.append("Nonstandard port.")
    if len(raw)>180: score+=10; findings.append("Unusually long URL.")
    if raw.count("%")>=4 or re.search(r"%[0-9a-f]{2}",raw.lower()): score+=5; findings.append("URL uses encoded characters; inspect decoded form.")
    decoded=unquote(raw).lower()
    tokens=set(re.findall(r"[a-z0-9-]+",(host+" "+p.path+" "+p.query+" "+decoded).lower()))
    matched=sorted(tokens & RISK_WORDS)
    if matched: score+=min(20,4*len(matched)); findings.append("Risk-associated words: "+", ".join(matched))
    brandhits=sorted(tokens & BRAND_WORDS)
    if brandhits and host:
        # Heuristic only: token presence in hostname isn't verification.
        if not any(host==b or host.endswith("."+b+".com") or host.endswith("."+b) for b in brandhits):
            score+=10; findings.append("Brand-name token appears in URL text: "+", ".join(brandhits))
    score=min(100,score)
    level="Low" if score<20 else "Moderate" if score<45 else "High"
    if not findings: findings.append("No heuristic indicators detected; this is not a safety guarantee.")
    return {"input":raw,"score":score,"level":level,"findings":findings,"host":host}
