#!/usr/bin/env python3
"""Browser control panel for the rotating SOCKS5 proxy.

A thin Flask front-end over proxymanager.py: it calls the exact same functions
the CLI/menu use, so the browser and terminal stay perfectly in sync. Lets you
view nodes, rotate all/one, pin/unpin the gateway exit, and read the IP log.

Login is required (credentials come from config.json: web_user / web_pass).

Run:
  pip install -r requirements.txt
  python webpanel.py            # then open http://<host>:8080

SECURITY: this controls your AWS account. Only expose it over a trusted network
or behind HTTPS. Change web_user / web_pass in config.json before hosting.
"""

from __future__ import annotations

import os
import threading
from functools import wraps

from flask import (Flask, jsonify, redirect, render_template_string, request,
                   session, url_for)

import proxymanager as pm

app = Flask(__name__)
app.secret_key = os.urandom(24)

CFG = pm.load_config()
# Serialize AWS-mutating actions so two clicks can't rotate concurrently.
_action_lock = threading.Lock()


# --------------------------------------------------------------------------- #
# auth
# --------------------------------------------------------------------------- #
def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("user"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "auth required"}), 401
            return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapper


# --------------------------------------------------------------------------- #
# data helpers (reuse proxymanager)
# --------------------------------------------------------------------------- #
def status_payload() -> dict:
    regions = CFG["regions"]
    targets = pm._collect_running(CFG, regions)
    gw = pm.load_state().get("gateway") or {}
    endpoint = f"{gw['eip']}:{CFG['socks_port']}" if gw.get("eip") else None

    nodes, pinned_ip = [], None
    for i, (region, n) in enumerate(targets, 1):
        pinned = pm._is_pinned(n)
        ip = n.get("PublicIpAddress")
        if pinned:
            pinned_ip = ip
        nodes.append({
            "n": i, "region": region, "instance_id": n["InstanceId"],
            "ip": ip or "-", "pinned": pinned,
        })

    log = pm.load_ip_log().get("records", [])
    recent = [r["ip"] for r in log[-15:]][::-1]
    return {
        "endpoint": endpoint,
        "mode": f"pinned \u2192 {pinned_ip}" if pinned_ip else "round-robin",
        "nodes": nodes,
        "log": recent,
        "log_count": len(log),
    }


def _find_target(instance_id: str):
    for region, n in pm._collect_running(CFG, CFG["regions"]):
        if n["InstanceId"] == instance_id:
            return region, n
    return None


# --------------------------------------------------------------------------- #
# routes
# --------------------------------------------------------------------------- #
@app.route("/login", methods=["GET", "POST"])
def login():
    err = ""
    if request.method == "POST":
        if (request.form.get("user") == CFG.get("web_user")
                and request.form.get("password") == CFG.get("web_pass")):
            session["user"] = request.form["user"]
            return redirect(url_for("index"))
        err = "Invalid credentials."
    return render_template_string(LOGIN_HTML, err=err)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template_string(PANEL_HTML)


@app.route("/api/status")
@login_required
def api_status():
    return jsonify(status_payload())


@app.route("/api/rotate", methods=["POST"])
@login_required
def api_rotate():
    instance_id = (request.json or {}).get("instance_id")
    with _action_lock:
        if instance_id:
            t = _find_target(instance_id)
            if not t:
                return jsonify({"error": "node not found"}), 404
            pm._rotate_targets(CFG, [t])
        else:
            pm._rotate_targets(CFG, pm._collect_running(CFG, CFG["regions"]))
    return jsonify(status_payload())


@app.route("/api/pin", methods=["POST"])
@login_required
def api_pin():
    instance_id = (request.json or {}).get("instance_id")
    t = _find_target(instance_id)
    if not t:
        return jsonify({"error": "node not found"}), 404
    with _action_lock:
        pm.set_pin(CFG, t[0], instance_id)
    return jsonify(status_payload())


@app.route("/api/unpin", methods=["POST"])
@login_required
def api_unpin():
    with _action_lock:
        pm.clear_pin(CFG, CFG["regions"])
    return jsonify(status_payload())


# --------------------------------------------------------------------------- #
# templates
# --------------------------------------------------------------------------- #
LOGIN_HTML = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Proxy Panel · Login</title>
<style>
:root{color-scheme:dark}
body{background:#0e1116;color:#e6edf3;font:15px/1.5 system-ui,sans-serif;
display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
form{background:#161b22;border:1px solid #232a33;border-radius:14px;padding:28px;
width:300px;box-shadow:0 10px 40px rgba(0,0,0,.4)}
h1{font-size:16px;margin:0 0 18px;font-weight:600}
input{width:100%;box-sizing:border-box;background:#0e1116;border:1px solid #2b333d;
color:#e6edf3;border-radius:8px;padding:10px 12px;margin-bottom:12px;font-size:14px}
button{width:100%;background:#2f81f7;color:#fff;border:0;border-radius:8px;
padding:11px;font-size:14px;font-weight:600;cursor:pointer}
button:hover{background:#4a92f9}
.err{color:#ff7b72;font-size:13px;margin-bottom:10px;min-height:16px}
</style></head><body>
<form method=post>
<h1>AWS Rotating Proxy</h1>
<div class=err>{{err}}</div>
<input name=user placeholder=Username autocomplete=username autofocus>
<input name=password type=password placeholder=Password autocomplete=current-password>
<button type=submit>Sign in</button>
</form></body></html>"""

PANEL_HTML = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Proxy Control Panel</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{background:#0e1116;color:#e6edf3;font:15px/1.5 system-ui,sans-serif;margin:0;padding:24px}
.wrap{max-width:760px;margin:0 auto}
.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
h1{font-size:17px;font-weight:600;margin:0}
a.logout{color:#8b949e;font-size:13px;text-decoration:none}
a.logout:hover{color:#e6edf3}
.card{background:#161b22;border:1px solid #232a33;border-radius:14px;padding:18px 20px;margin-bottom:16px}
.row{display:flex;justify-content:space-between;align-items:center;gap:12px}
.lbl{color:#8b949e;font-size:13px}
.mono{font-family:ui-monospace,Consolas,monospace}
.endp{font-size:20px;font-weight:600}
.badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:12px;
background:#1f6feb33;color:#79c0ff;border:1px solid #1f6feb55}
table{width:100%;border-collapse:collapse;margin-top:6px}
th,td{text-align:left;padding:10px 8px;border-bottom:1px solid #232a33;font-size:14px}
th{color:#8b949e;font-weight:500;font-size:12px}
td.ip{font-family:ui-monospace,Consolas,monospace}
.pin-dot{color:#3fb950;font-weight:700;margin-left:6px}
button{background:#21262d;color:#e6edf3;border:1px solid #30363d;border-radius:7px;
padding:6px 12px;font-size:13px;cursor:pointer}
button:hover{background:#2b313a}
button.primary{background:#2f81f7;border-color:#2f81f7;color:#fff}
button.primary:hover{background:#4a92f9}
button.warn{color:#ff7b72}
button:disabled{opacity:.5;cursor:not-allowed}
.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:4px}
.log{font-family:ui-monospace,Consolas,monospace;font-size:13px;color:#adbac7;
max-height:200px;overflow:auto}
.log div{padding:2px 0;border-bottom:1px solid #1b2028}
#toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);
background:#161b22;border:1px solid #30363d;border-radius:8px;padding:10px 16px;
font-size:13px;opacity:0;transition:.3s;pointer-events:none}
#toast.show{opacity:1}
.muted{color:#8b949e;font-size:12px}
</style></head><body>
<div class=wrap>
  <div class=top>
    <h1>AWS Rotating SOCKS5 Proxy</h1>
    <a class=logout href="/logout">Sign out</a>
  </div>

  <div class=card>
    <div class=row>
      <div>
        <div class=lbl>Endpoint</div>
        <div class="endp mono" id=endpoint>—</div>
      </div>
      <div style=text-align:right>
        <div class=lbl>Mode</div>
        <div class=badge id=mode>—</div>
      </div>
    </div>
    <div class=actions style=margin-top:16px>
      <button class=primary id=rotateAll>Rotate all</button>
      <button id=unpin>Unpin (round-robin)</button>
      <button id=refresh>Refresh</button>
    </div>
  </div>

  <div class=card>
    <table>
      <thead><tr><th>#</th><th>Node</th><th>Exit IP</th><th></th></tr></thead>
      <tbody id=nodes></tbody>
    </table>
  </div>

  <div class=card>
    <div class=row><div class=lbl>Recent IPs</div><div class=muted id=logcount></div></div>
    <div class=log id=log></div>
  </div>
</div>
<div id=toast></div>

<script>
let busy=false;
const $=s=>document.querySelector(s);
function toast(m){const t=$('#toast');t.textContent=m;t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2200);}
function setBusy(b){busy=b;document.querySelectorAll('button').forEach(x=>x.disabled=b);}

function render(d){
  $('#endpoint').textContent=d.endpoint||'—';
  $('#mode').textContent=d.mode;
  $('#logcount').textContent=d.log_count+' logged';
  const tb=$('#nodes');tb.innerHTML='';
  d.nodes.forEach(n=>{
    const tr=document.createElement('tr');
    tr.innerHTML=`<td>${n.n}</td><td class=mono>${n.instance_id}</td>
      <td class=ip>${n.ip}${n.pinned?'<span class=pin-dot>● pinned</span>':''}</td>
      <td class=actions style=justify-content:flex-end>
        <button data-rot="${n.instance_id}">Rotate</button>
        ${n.pinned?'<button data-unpin=1>Unpin</button>'
                  :`<button data-pin="${n.instance_id}">Pin</button>`}
      </td>`;
    tb.appendChild(tr);
  });
  $('#log').innerHTML=d.log.map(ip=>`<div>${ip}</div>`).join('')||'<div class=muted>none yet</div>';
}

async function api(path,body){
  const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(body||{})});
  if(!r.ok)throw new Error((await r.json()).error||r.status);
  return r.json();
}
async function load(){const r=await fetch('/api/status');render(await r.json());}

async function act(fn,msg){
  if(busy)return;setBusy(true);toast(msg);
  try{render(await fn());toast('Done');}
  catch(e){toast('Error: '+e.message);}
  finally{setBusy(false);}
}

$('#rotateAll').onclick=()=>act(()=>api('/api/rotate'),'Rotating all…');
$('#unpin').onclick=()=>act(()=>api('/api/unpin'),'Unpinning…');
$('#refresh').onclick=()=>act(()=>fetch('/api/status').then(r=>r.json()),'Refreshing…');
document.addEventListener('click',e=>{
  const b=e.target;
  if(b.dataset.rot)act(()=>api('/api/rotate',{instance_id:b.dataset.rot}),'Rotating node…');
  else if(b.dataset.pin)act(()=>api('/api/pin',{instance_id:b.dataset.pin}),'Pinning…');
  else if(b.dataset.unpin)act(()=>api('/api/unpin'),'Unpinning…');
});
load();setInterval(()=>{if(!busy)load();},10000);
</script></body></html>"""


if __name__ == "__main__":
    port = int(CFG.get("web_port", 8080))
    print(f"Control panel on http://0.0.0.0:{port}  (login: {CFG.get('web_user')})")
    app.run(host="0.0.0.0", port=port)
