from __future__ import annotations
import sqlite3
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template, Response
from scanner import analyze_url

app=Flask(__name__)
DB="lab_events.sqlite3"
MAX_BATCH=25

def db():
    conn=sqlite3.connect(DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,event TEXT NOT NULL,
        detail TEXT NOT NULL,created_at TEXT NOT NULL)""")
    conn.commit()
    return conn

def log_event(event,detail):
    with db() as conn:
        conn.execute("INSERT INTO events(event,detail,created_at) VALUES(?,?,?)",
          (event,str(detail)[:500],datetime.now(timezone.utc).isoformat()))

def recent_events(limit=50):
    with db() as conn:
        return conn.execute("SELECT event,detail,created_at FROM events ORDER BY id DESC LIMIT ?",(limit,)).fetchall()

@app.get("/")
def home():
    return render_template("index.html",events=recent_events(25))

@app.post("/api/analyze")
def api_analyze():
    data=request.get_json(silent=True) or {}
    result=analyze_url(data.get("url",""))
    log_event("url_analysis",f"score={result['score']} host={result['host']}")
    return jsonify(result)

@app.post("/api/batch")
def api_batch():
    data=request.get_json(silent=True) or {}
    items=data.get("urls",[])
    if not isinstance(items,list): return jsonify({"error":"urls must be a list"}),400
    items=items[:MAX_BATCH]
    results=[analyze_url(x) for x in items]
    log_event("batch_analysis",f"{len(results)} URLs analyzed")
    return jsonify({"count":len(results),"results":results})

@app.get("/simulation")
def simulation():
    return render_template("simulation.html")

@app.post("/api/event")
def event():
    data=request.get_json(silent=True) or {}
    name=str(data.get("event",""))[:60]
    allowed={"simulation_open","simulation_continue_click","simulation_report_click"}
    if name not in allowed: return jsonify({"error":"Unsupported event"}),400
    log_event(name,"awareness demo event; no personal data collected")
    return jsonify({"ok":True})

@app.get("/api/events")
def events():
    rows=recent_events(100)
    return jsonify([{"event":r[0],"detail":r[1],"created_at":r[2]} for r in rows])

@app.get("/api/report.csv")
def report_csv():
    rows=recent_events(500)
    lines=["event,detail,created_at"]
    for e,d,t in rows:
        vals=[e,d,t]
        lines.append(",".join('"'+str(v).replace('"','""')+'"' for v in vals))
    return Response("\n".join(lines),mimetype="text/csv",headers={"Content-Disposition":"attachment; filename=phishing-lab-report.csv"})

@app.post("/api/clear-events")
def clear_events():
    # Clear is restricted to a local dashboard action; no credentials are stored.
    with db() as conn: conn.execute("DELETE FROM events")
    return jsonify({"ok":True})

if __name__=="__main__":
    db().close()
    app.run(host="127.0.0.1",port=5000,debug=False)
