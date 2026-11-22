from __future__ import annotations
import sqlite3, json
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template, Response
from scanner import analyze_url
from mailtools import analyze_email, extract_iocs
from security import rate_limited, security_headers

app=Flask(__name__)
app.config['MAX_CONTENT_LENGTH']=256*1024

@app.after_request
def hardening(response):
    return security_headers(response)

@app.before_request
def limit_api_requests():
    if request.path.startswith('/api/') and rate_limited(request.remote_addr or 'unknown',limit=90,window=60):
        return jsonify({'error':'Rate limit exceeded. Try again shortly.'}),429
DB="lab_events.sqlite3"
MAX_BATCH=50

def db():
    conn=sqlite3.connect(DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,event TEXT NOT NULL,
        detail TEXT NOT NULL,created_at TEXT NOT NULL)""")
    conn.commit(); return conn

def log_event(event,detail):
    with db() as conn:
        conn.execute("INSERT INTO events(event,detail,created_at) VALUES(?,?,?)",
          (event,str(detail)[:500],datetime.now(timezone.utc).isoformat()))

def recent_events(limit=50):
    with db() as conn:
        return conn.execute("SELECT event,detail,created_at FROM events ORDER BY id DESC LIMIT ?",(limit,)).fetchall()

@app.get("/")
def home():
    return render_template("index.html",events=recent_events(30))

@app.post("/api/analyze")
def api_analyze():
    data=request.get_json(silent=True) or {}; result=analyze_url(data.get("url",""))
    log_event("url_analysis",f"score={result['score']} host={result['host']}")
    return jsonify(result)

@app.post("/api/batch")
def api_batch():
    data=request.get_json(silent=True) or {}; items=data.get("urls",[])
    if not isinstance(items,list): return jsonify({"error":"urls must be a list"}),400
    results=[analyze_url(x) for x in items[:MAX_BATCH]]
    log_event("batch_analysis",f"{len(results)} URLs parsed")
    return jsonify({"count":len(results),"results":results})

@app.post("/api/email")
def api_email():
    data=request.get_json(silent=True) or {}; result=analyze_email(data.get("text",""))
    log_event("email_analysis",f"score={result['score']} attachments={len(result['attachments'])}")
    return jsonify(result)

@app.post("/api/iocs")
def api_iocs():
    data=request.get_json(silent=True) or {}; result=extract_iocs(data.get("text",""))
    log_event("ioc_extract",f"URLs={len(result['urls'])} IPs={len(result['ipv4'])} domains={len(result['domains'])}")
    return jsonify(result)

@app.get("/simulation")
def simulation(): return render_template("simulation.html")

@app.post("/api/event")
def event():
    data=request.get_json(silent=True) or {}; name=str(data.get("event",""))[:60]
    if name not in {"simulation_open","simulation_continue_click","simulation_report_click"}: return jsonify({"error":"Unsupported event"}),400
    log_event(name,"awareness demo event; no personal data collected"); return jsonify({"ok":True})

@app.get("/api/events")
def events():
    return jsonify([{"event":r[0],"detail":r[1],"created_at":r[2]} for r in recent_events(100)])

@app.get("/api/report.json")
def report_json():
    rows=recent_events(500)
    return jsonify({"generated_at":datetime.now(timezone.utc).isoformat(),"events":[{"event":r[0],"detail":r[1],"created_at":r[2]} for r in rows]})

@app.get("/api/report.csv")
def report_csv():
    rows=recent_events(500); lines=["event,detail,created_at"]
    for e,d,t in rows: lines.append(",".join('"'+str(v).replace('"','""')+'"' for v in [e,d,t]))
    return Response("\n".join(lines),mimetype="text/csv",headers={"Content-Disposition":"attachment; filename=lab-report.csv"})

@app.post("/api/clear-events")
def clear_events():
    with db() as conn: conn.execute("DELETE FROM events")
    return jsonify({"ok":True})

if __name__=="__main__":
    db().close(); app.run(host="127.0.0.1",port=5000,debug=False)
