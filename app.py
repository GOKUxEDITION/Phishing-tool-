from __future__ import annotations
import ipaddress, sqlite3, re
from datetime import datetime, timezone
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)
DB = "lab_events.sqlite3"
SHORTENERS = {"bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","cutt.ly"}
RISK_WORDS = {"login","verify","verification","account","secure","update","password","wallet","billing","confirm","free","gift"}

def db():
    conn = sqlite3.connect(DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL,
        detail TEXT NOT NULL, created_at TEXT NOT NULL)""")
    conn.commit()
    return conn

def analyze_url(raw: str):
    raw = raw.strip()
    if not raw: return {"score":0,"level":"Unknown","findings":["Enter a URL."]}
    candidate = raw if re.match(r"^https?://", raw, re.I) else "https://" + raw
    try: p = urlparse(candidate); host=(p.hostname or "").lower()
    except Exception: return {"score":100,"level":"High","findings":["URL parsing failed."]}
    findings=[]; score=0
    if p.scheme != "https": score+=15; findings.append("Not using HTTPS.")
    if not host: score+=35; findings.append("Missing hostname.")
    try:
        ipaddress.ip_address(host); score+=25; findings.append("Host is a raw IP address.")
    except ValueError: pass
    if host.startswith("xn--") or "xn--" in host: score+=20; findings.append("Punycode hostname may conceal lookalike characters.")
    if host in SHORTENERS: score+=20; findings.append("Known URL-shortener domain.")
    if len(host.split(".")) >= 5: score+=10; findings.append("Unusually deep subdomain structure.")
    if "@" in p.netloc: score+=20; findings.append("URL contains user-info syntax that can disguise the host.")
    tokens=set(re.findall(r"[a-z]+", (host + " " + p.path + " " + p.query).lower()))
    matched=sorted(tokens & RISK_WORDS)
    if matched: score+=min(20, 5*len(matched)); findings.append("Pressure/credential-related terms: " + ", ".join(matched))
    if len(raw)>180: score+=10; findings.append("Unusually long URL.")
    score=min(100,score)
    level="Low" if score<20 else "Moderate" if score<45 else "High"
    if not findings: findings.append("No heuristic indicators detected. This does not prove the URL is safe.")
    return {"score":score,"level":level,"findings":findings,"host":host}

def log_event(event, detail):
    with db() as conn:
        conn.execute("INSERT INTO events(event,detail,created_at) VALUES(?,?,?)",
                     (event, detail[:500], datetime.now(timezone.utc).isoformat()))

@app.route("/")
def home():
    with db() as conn:
        events=conn.execute("SELECT event,detail,created_at FROM events ORDER BY id DESC LIMIT 20").fetchall()
    return render_template("index.html", events=events)

@app.post("/api/analyze")
def api_analyze():
    data=request.get_json(silent=True) or {}
    raw=str(data.get("url",""))[:2048]
    result=analyze_url(raw)
    log_event("url_analysis", f"{raw} | score={result['score']} | {result['level']}")
    return jsonify(result)

@app.get("/simulation")
def simulation():
    return render_template("simulation.html")

@app.post("/api/event")
def event():
    data=request.get_json(silent=True) or {}
    name=str(data.get("event",""))[:60]
    if name not in {"simulation_open","simulation_continue_click","simulation_report_click"}:
        return jsonify({"error":"Unsupported event"}),400
    log_event(name, "awareness demo event; no personal data collected")
    return jsonify({"ok":True})

@app.get("/api/events")
def events():
    with db() as conn:
        rows=conn.execute("SELECT event,detail,created_at FROM events ORDER BY id DESC LIMIT 100").fetchall()
    return jsonify([{"event":r[0],"detail":r[1],"created_at":r[2]} for r in rows])

if __name__ == "__main__":
    db().close()
    app.run(host="127.0.0.1", port=5000, debug=False)
