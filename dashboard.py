"""
dashboard.py — Web dashboard with live event feed using Server-Sent Events.
Run: python3 dashboard.py
Open: http://localhost:5000
"""

from flask import Flask, render_template_string, jsonify, Response
import sqlite3
import json
import os
import time

app = Flask(__name__)
DB_PATH = "logs/honeypot.db"

def query_db(sql, args=()):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(sql, args)
        return [dict(r) for r in cur.fetchall()]

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SSH Honeypot Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:       #050a0e;
    --surface:  #0a1520;
    --border:   #0f2a3a;
    --accent:   #00d4ff;
    --green:    #00ff88;
    --yellow:   #ffcc00;
    --red:      #ff3355;
    --magenta:  #cc44ff;
    --text:     #c8e0f0;
    --muted:    #4a6a7a;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Share Tech Mono', monospace;
    min-height: 100vh;
  }
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,212,255,0.015) 2px,rgba(0,212,255,0.015) 4px);
    pointer-events: none;
    z-index: 9999;
  }
  header {
    border-bottom: 1px solid var(--border);
    padding: 20px 32px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: linear-gradient(90deg, rgba(0,212,255,0.05), transparent);
  }
  .logo { font-family:'Orbitron',monospace; font-weight:900; font-size:1.4rem; color:var(--accent); letter-spacing:3px; text-shadow:0 0 20px rgba(0,212,255,0.5); }
  .logo span { color: var(--red); }
  .live-indicator { display:flex; align-items:center; gap:8px; font-size:0.75rem; color:var(--green); }
  .pulse { width:8px; height:8px; border-radius:50%; background:var(--green); box-shadow:0 0 8px var(--green); animation:pulse 1.5s infinite; }
  @keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.4;transform:scale(0.8)} }
  main { padding: 28px 32px; }
  .stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin-bottom:28px; }
  .stat-card { background:var(--surface); border:1px solid var(--border); border-radius:4px; padding:20px; position:relative; overflow:hidden; transition:border-color 0.2s; }
  .stat-card::before { content:''; position:absolute; top:0; left:0; right:0; height:2px; }
  .stat-card.blue::before   { background:var(--accent);  box-shadow:0 0 12px var(--accent); }
  .stat-card.green::before  { background:var(--green);   box-shadow:0 0 12px var(--green); }
  .stat-card.yellow::before { background:var(--yellow);  box-shadow:0 0 12px var(--yellow); }
  .stat-card.red::before    { background:var(--red);     box-shadow:0 0 12px var(--red); }
  .stat-card.purple::before { background:var(--magenta); box-shadow:0 0 12px var(--magenta); }
  .stat-label { font-size:0.65rem; color:var(--muted); letter-spacing:2px; text-transform:uppercase; margin-bottom:10px; }
  .stat-value { font-family:'Orbitron',monospace; font-size:2rem; font-weight:700; }
  .stat-card.blue   .stat-value { color:var(--accent); }
  .stat-card.green  .stat-value { color:var(--green); }
  .stat-card.yellow .stat-value { color:var(--yellow); }
  .stat-card.red    .stat-value { color:var(--red); }
  .stat-card.purple .stat-value { color:var(--magenta); }
  .grid { display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:20px; }
  .panel { background:var(--surface); border:1px solid var(--border); border-radius:4px; overflow:hidden; }
  .panel-header { padding:12px 18px; border-bottom:1px solid var(--border); font-family:'Orbitron',monospace; font-size:0.7rem; letter-spacing:2px; color:var(--accent); display:flex; align-items:center; justify-content:space-between; }
  .panel-header span { color:var(--muted); font-size:0.65rem; }
  .panel-header::before { content:'//'; color:var(--muted); margin-right:8px; }
  .data-table { width:100%; border-collapse:collapse; font-size:0.78rem; }
  .data-table th { padding:10px 14px; text-align:left; font-size:0.62rem; letter-spacing:1.5px; color:var(--muted); border-bottom:1px solid var(--border); text-transform:uppercase; }
  .data-table td { padding:9px 14px; border-bottom:1px solid rgba(15,42,58,0.6); vertical-align:middle; }
  .data-table tr:last-child td { border-bottom:none; }

  /* Flash animation for new rows */
  @keyframes flashRow {
    0%   { background: rgba(0,212,255,0.2); }
    100% { background: transparent; }
  }
  .new-row { animation: flashRow 1.5s ease-out forwards; }

  .badge { display:inline-block; padding:2px 8px; border-radius:2px; font-size:0.65rem; letter-spacing:1px; font-weight:bold; }
  .badge-connect      { background:rgba(0,212,255,0.15); color:var(--accent);   border:1px solid rgba(0,212,255,0.3); }
  .badge-login        { background:rgba(255,204,0,0.15);  color:var(--yellow);  border:1px solid rgba(255,204,0,0.3); }
  .badge-command      { background:rgba(204,68,255,0.15); color:var(--magenta); border:1px solid rgba(204,68,255,0.3); }
  .badge-rate_limited { background:rgba(255,51,85,0.15);  color:var(--red);     border:1px solid rgba(255,51,85,0.3); }
  .badge-error        { background:rgba(255,51,85,0.1);   color:var(--red);     border:1px solid rgba(255,51,85,0.2); }
  .bar-row { display:flex; align-items:center; gap:10px; padding:8px 18px; border-bottom:1px solid rgba(15,42,58,0.5); font-size:0.75rem; }
  .bar-row:last-child { border-bottom:none; }
  .bar-ip    { width:130px; color:var(--accent); flex-shrink:0; }
  .bar-track { flex:1; background:rgba(255,255,255,0.05); border-radius:2px; height:6px; }
  .bar-fill  { height:100%; border-radius:2px; background:linear-gradient(90deg,var(--accent),var(--green)); transition:width 0.8s ease; }
  .bar-count { width:32px; text-align:right; color:var(--muted); flex-shrink:0; }
  .pw-row { display:flex; justify-content:space-between; align-items:center; padding:8px 18px; border-bottom:1px solid rgba(15,42,58,0.5); font-size:0.78rem; }
  .pw-row:last-child { border-bottom:none; }
  .pw-val { color:var(--yellow); }
  .pw-cnt { color:var(--muted); font-size:0.7rem; }
  .scroll-body { max-height:380px; overflow-y:auto; }
  .scroll-body::-webkit-scrollbar { width:4px; }
  .scroll-body::-webkit-scrollbar-thumb { background:var(--border); border-radius:2px; }
  .ts        { color:var(--muted); font-size:0.7rem; }
  .ip-text   { color:var(--accent); }
  .cmd-text  { color:var(--magenta); }
  .user-text { color:var(--green); }
  .pass-text { color:var(--yellow); }
  .empty { padding:30px; text-align:center; color:var(--muted); font-size:0.8rem; }

  /* Live feed indicator in header */
  .feed-status { display:flex; align-items:center; gap:6px; font-size:0.65rem; color:var(--green); }
  .feed-dot    { width:6px; height:6px; border-radius:50%; background:var(--green); box-shadow:0 0 6px var(--green); animation:pulse 1s infinite; }
  .feed-status.disconnected { color:var(--red); }
  .feed-status.disconnected .feed-dot { background:var(--red); box-shadow:0 0 6px var(--red); animation:none; }

  @media (max-width:768px) { .grid { grid-template-columns:1fr; } main { padding:16px; } }
</style>
</head>
<body>

<header>
  <div class="logo">SSH<span>TRAP</span> // DASHBOARD</div>
  <div class="live-indicator"><div class="pulse"></div> MONITORING</div>
</header>

<main>
  <div class="stats" id="stats">
    <div class="stat-card blue">  <div class="stat-label">Total Events</div>  <div class="stat-value" id="s-total">—</div></div>
    <div class="stat-card green"> <div class="stat-label">Unique IPs</div>    <div class="stat-value" id="s-ips">—</div></div>
    <div class="stat-card yellow"><div class="stat-label">Login Attempts</div><div class="stat-value" id="s-logins">—</div></div>
    <div class="stat-card purple"><div class="stat-label">Commands Run</div>  <div class="stat-value" id="s-cmds">—</div></div>
    <div class="stat-card red">   <div class="stat-label">Rate Limited</div>  <div class="stat-value" id="s-blocked">—</div></div>
  </div>

  <div class="grid">
    <div class="panel">
      <div class="panel-header">TOP ATTACKING IPs</div>
      <div id="top-ips"><div class="empty">loading...</div></div>
    </div>
    <div class="panel">
      <div class="panel-header">TOP PASSWORDS TRIED</div>
      <div id="top-passwords"><div class="empty">loading...</div></div>
    </div>
  </div>

  <!-- Live event feed -->
  <div class="panel">
    <div class="panel-header">
      LIVE EVENT FEED
      <div class="feed-status" id="feed-status">
        <div class="feed-dot"></div>
        <span id="feed-label">CONNECTING...</span>
      </div>
    </div>
    <div class="scroll-body" id="live-scroll">
      <table class="data-table">
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>IP</th>
            <th>Event</th>
            <th>Country</th>
            <th>Username</th>
            <th>Password</th>
            <th>Command</th>
          </tr>
        </thead>
        <tbody id="events-body">
          <tr><td colspan="7" class="empty">Waiting for events...</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</main>

<script>
let lastId      = 0;
let initialLoad = true;

function badgeClass(ev) {
  return { CONNECT:'badge-connect', LOGIN_ATTEMPT:'badge-login', COMMAND:'badge-command',
           RATE_LIMITED:'badge-rate_limited', ERROR:'badge-error' }[ev] || 'badge-connect';
}

function badgeLabel(ev) { return ev.replace('_',' '); }

function makeRow(row, flash=false) {
  const tr = document.createElement('tr');
  if (flash) tr.classList.add('new-row');
  tr.innerHTML = `
    <td class="ts">${(row.timestamp||'').slice(0,19).replace('T',' ')}</td>
    <td class="ip-text">${row.ip||''}</td>
    <td><span class="badge ${badgeClass(row.event)}">${badgeLabel(row.event)}</span></td>
    <td>${row.country||'—'}</td>
    <td class="user-text">${row.username||'—'}</td>
    <td class="pass-text">${row.password||'—'}</td>
    <td class="cmd-text">${row.command||'—'}</td>`;
  return tr;
}

// ── Load stats & charts ────────────────────────────────────────────────────
async function loadStats() {
  const d = await fetch('/api/stats').then(r=>r.json());
  document.getElementById('s-total').textContent   = d.total    ?? 0;
  document.getElementById('s-ips').textContent     = d.unique_ips ?? 0;
  document.getElementById('s-logins').textContent  = d.logins   ?? 0;
  document.getElementById('s-cmds').textContent    = d.commands ?? 0;
  document.getElementById('s-blocked').textContent = d.blocked  ?? 0;
}

async function loadTopIPs() {
  const rows = await fetch('/api/top_ips').then(r=>r.json());
  const el   = document.getElementById('top-ips');
  if (!rows.length) { el.innerHTML='<div class="empty">No data yet</div>'; return; }
  const max  = rows[0].hits;
  el.innerHTML = rows.map(r=>`
    <div class="bar-row">
      <div class="bar-ip">${r.ip}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${Math.round(r.hits/max*100)}%"></div></div>
      <div class="bar-count">${r.hits}</div>
    </div>`).join('');
}

async function loadTopPasswords() {
  const rows = await fetch('/api/top_passwords').then(r=>r.json());
  const el   = document.getElementById('top-passwords');
  if (!rows.length) { el.innerHTML='<div class="empty">No data yet</div>'; return; }
  el.innerHTML = rows.map(r=>`
    <div class="pw-row">
      <span class="pw-val">${r.password||'(empty)'}</span>
      <span class="pw-cnt">${r.cnt} attempts</span>
    </div>`).join('');
}

// ── Server-Sent Events — live feed ─────────────────────────────────────────
function connectSSE() {
  const statusEl = document.getElementById('feed-status');
  const labelEl  = document.getElementById('feed-label');
  const tbody    = document.getElementById('events-body');
  const scroll   = document.getElementById('live-scroll');

  const es = new EventSource('/stream');

  es.onopen = () => {
    statusEl.className = 'feed-status';
    labelEl.textContent = 'LIVE';
  };

  es.onmessage = (e) => {
    const row = JSON.parse(e.data);

    // Update lastId
    if (row.id > lastId) lastId = row.id;

    // Remove placeholder row on first real event
    const placeholder = tbody.querySelector('td[colspan]');
    if (placeholder) placeholder.closest('tr').remove();

    // Prepend new row with flash — cap at 200 rows
    const tr = makeRow(row, !initialLoad);
    tbody.insertBefore(tr, tbody.firstChild);
    while (tbody.children.length > 200) tbody.removeChild(tbody.lastChild);

    // Refresh stats & charts on each new event
    loadStats();
    loadTopIPs();
    loadTopPasswords();
  };

  es.onerror = () => {
    statusEl.className = 'feed-status disconnected';
    labelEl.textContent = 'RECONNECTING...';
    es.close();
    setTimeout(connectSSE, 3000);   // auto-reconnect after 3s
  };
}

// Initial load then connect live feed
async function init() {
  await loadStats();
  await loadTopIPs();
  await loadTopPasswords();

  // Load last 100 events as seed
  const rows = await fetch('/api/events').then(r=>r.json());
  const tbody = document.getElementById('events-body');
  if (rows.length) {
    tbody.innerHTML = '';
    rows.forEach(r => { tbody.appendChild(makeRow(r, false)); });
    if (rows.length) lastId = rows[0].id;
  }

  initialLoad = false;
  connectSSE();
}

init();
</script>
</body>
</html>
"""

# ── API routes ────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/api/stats")
def stats():
    if not os.path.exists(DB_PATH):
        return jsonify({"total":0,"unique_ips":0,"logins":0,"commands":0,"blocked":0})
    rows   = query_db("SELECT event, COUNT(*) as c FROM events GROUP BY event")
    counts = {r["event"]: r["c"] for r in rows}
    unique = query_db("SELECT COUNT(DISTINCT ip) as c FROM events")[0]["c"]
    total  = query_db("SELECT COUNT(*) as c FROM events")[0]["c"]
    return jsonify({"total":total,"unique_ips":unique,
                    "logins":counts.get("LOGIN_ATTEMPT",0),
                    "commands":counts.get("COMMAND",0),
                    "blocked":counts.get("RATE_LIMITED",0)})

@app.route("/api/events")
def events():
    if not os.path.exists(DB_PATH):
        return jsonify([])
    return jsonify(query_db("SELECT * FROM events ORDER BY id DESC LIMIT 100"))

@app.route("/api/top_ips")
def top_ips():
    if not os.path.exists(DB_PATH):
        return jsonify([])
    return jsonify(query_db(
        "SELECT ip, COUNT(*) as hits FROM events GROUP BY ip ORDER BY hits DESC LIMIT 10"))

@app.route("/api/top_passwords")
def top_passwords():
    if not os.path.exists(DB_PATH):
        return jsonify([])
    return jsonify(query_db("""
        SELECT password, COUNT(*) as cnt FROM events
        WHERE event='LOGIN_ATTEMPT' AND password != ''
        GROUP BY password ORDER BY cnt DESC LIMIT 10"""))

# ── Server-Sent Events stream ─────────────────────────────────────────────────
@app.route("/stream")
def stream():
    """
    Streams new DB rows to the browser in real time using SSE.
    Polls the DB every 2 seconds for rows newer than last seen id.
    """
    def event_generator():
        last_id = 0

        # Seed with last 100 rows first
        if os.path.exists(DB_PATH):
            rows = query_db("SELECT * FROM events ORDER BY id DESC LIMIT 100")
            for row in reversed(rows):
                yield f"data: {json.dumps(row)}\n\n"
                if row["id"] > last_id:
                    last_id = row["id"]

        # Then poll for new rows
        while True:
            time.sleep(2)
            if not os.path.exists(DB_PATH):
                continue
            new_rows = query_db(
                "SELECT * FROM events WHERE id > ? ORDER BY id ASC", (last_id,))
            for row in new_rows:
                yield f"data: {json.dumps(row)}\n\n"
                last_id = row["id"]

    return Response(event_generator(),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})

if __name__ == "__main__":
    print("\n  SSH Honeypot Dashboard")
    print("  Open http://localhost:5000 in your browser\n")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
