import os, json, time, uuid, secrets, base64, sqlite3, subprocess, threading, hmac, hashlib, urllib.parse
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Response, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel

ADMIN_USER = (os.environ.get("ADMIN_USER") or "admin").strip()
# رمز پنل: بهتره در Railway ← Variables با اسم ADMIN_PASSWORD بذاری؛ اگه نبود از این مقدار استفاده می‌شه
ADMIN_PASSWORD = (os.environ.get("ADMIN_PASSWORD") or "99842222").strip()
print(f"[panel] user={ADMIN_USER!r} password_length={len(ADMIN_PASSWORD)} source={'railway-variable' if os.environ.get('ADMIN_PASSWORD') else 'code'}", flush=True)
# >>>>>>>>>> دامنه ریلوی خودتو اینجا بذار (بدون https://) <<<<<<<<<<
RAILWAY_DOMAIN = "confamir.up.railway.app"
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
DOMAIN = os.environ.get("DOMAIN") or RAILWAY_DOMAIN
# آدرس اتصال پیش‌فرض: اگه برای کاربر یا در تنظیمات آدرسی مشخص نشده باشه، کانفیگ‌ها به این آدرس وصل می‌شن
# (SNI و Host همچنان دامنه‌ی ریلوی خودته). خالی بذاری از خود دامنه استفاده می‌شه.
DEFAULT_ADDRESS = "up.railway.app"
WS_PATH = os.environ.get("WS_PATH", "/in2")
DATA = os.environ.get("DATA_DIR", "/data")
CONF = os.path.join(DATA, "xray.json")
GB = 1024 ** 3

os.makedirs(DATA, exist_ok=True)
L = threading.RLock()
db = sqlite3.connect(os.path.join(DATA, "panel.db"), check_same_thread=False)
db.row_factory = sqlite3.Row
db.execute("""CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, uuid TEXT, token TEXT,
 limit_bytes INTEGER DEFAULT 0, expire INTEGER DEFAULT 0,
 up INTEGER DEFAULT 0, down INTEGER DEFAULT 0, enabled INTEGER DEFAULT 1,
 note TEXT DEFAULT '', created INTEGER DEFAULT 0,
 protos TEXT DEFAULT 'vmess', port INTEGER DEFAULT 443, fp TEXT DEFAULT '', addr TEXT DEFAULT '', ttl_days INTEGER DEFAULT 0)""")
db.execute("CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT)")
for col in ("note TEXT DEFAULT ''", "created INTEGER DEFAULT 0", "protos TEXT DEFAULT 'vmess'",
            "port INTEGER DEFAULT 443", "fp TEXT DEFAULT ''", "addr TEXT DEFAULT ''", "ttl_days INTEGER DEFAULT 0"):
    try: db.execute("ALTER TABLE users ADD COLUMN " + col)
    except Exception: pass
db.commit()

DEFAULTS = {"title": "Black Panel", "accent": "#7c5cff", "theme": "dark", "radius": "16",
            "bg": "gradient", "domain": "", "address": "", "fp": "android", "prefix": "",
            "accent2": "#38d4ff", "font": "system", "fsize": "15", "blur": "14", "opacity": "40",
            "density": "normal", "layout": "list", "anim": "1", "shape": "squircle",
            "pbar": "gradient", "cardstyle": "glass", "preset": "midnight"}

def settings():
    with L:
        d = dict(DEFAULTS)
        d.update({r["k"]: r["v"] for r in db.execute("SELECT * FROM settings")})
    return d

app = FastAPI()

def _tok():
    return hmac.new(ADMIN_PASSWORD.encode(), b"panel-session", hashlib.sha256).hexdigest()

def authed(request: Request):
    c = request.cookies.get("sess")
    return bool(c) and hmac.compare_digest(c, _tok())

def auth(request: Request):
    if not authed(request):
        raise HTTPException(401)

def is_active(u):
    now = time.time()
    return (u["enabled"] and (u["limit_bytes"] == 0 or u["up"] + u["down"] < u["limit_bytes"])
            and (u["expire"] == 0 or u["expire"] > now))

# ---------- Xray management ----------
proc = None
current = None

PATHS = {"vmess": WS_PATH, "vless": "/vl", "trojan": "/tr", "vlessh": "/hu"}
LABEL = {"vmess": "VMess", "vless": "VLESS", "trojan": "Trojan", "vlessh": "VLESS-HU"}
# proto: (inbound tag, internal port, xray protocol, transport)
INB = {"vmess": ("vmess-in", 10000, "vmess", "ws"), "vless": ("vless-in", 10001, "vless", "ws"),
       "trojan": ("trojan-in", 10002, "trojan", "ws"), "vlessh": ("vlessh-in", 10003, "vless", "httpupgrade")}

def clients_for(p, users, dummy=True):
    out = []
    for u in users:
        if p not in u["protos"].split(","):
            continue
        e = f"u{u['id']}"
        if p == "vmess": out.append({"id": u["uuid"], "email": e, "alterId": 0})
        elif p == "trojan": out.append({"password": u["uuid"], "email": e})
        else: out.append({"id": u["uuid"], "email": e})
    if not out and dummy:  # xray wants at least one client
        d = str(uuid.uuid4())
        out = [{"password": d, "email": "dummy"} if p == "trojan" else {"id": d, "email": "dummy"}]
    return out

def write_config(users):
    inbounds = [{"tag": "api", "listen": "127.0.0.1", "port": 10085, "protocol": "dokodemo-door",
                 "settings": {"address": "127.0.0.1"}}]
    for p, (tag, port, proto, net) in INB.items():
        st = {"clients": clients_for(p, users)}
        if proto == "vless":
            st["decryption"] = "none"
        ss = ({"network": "ws", "wsSettings": {"path": PATHS[p]}} if net == "ws"
              else {"network": "httpupgrade", "httpupgradeSettings": {"path": PATHS[p]}})
        inbounds.append({"tag": tag, "listen": "127.0.0.1", "port": port, "protocol": proto,
                         "settings": st, "streamSettings": ss})
    cfg = {
        "log": {"loglevel": "warning"},
        "api": {"tag": "api", "services": ["HandlerService", "StatsService"]},
        "stats": {},
        "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}}},
        "inbounds": inbounds,
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
        "routing": {"rules": [{"type": "field", "inboundTag": ["api"], "outboundTag": "api"}]},
    }
    with open(CONF, "w") as f:
        json.dump(cfg, f)

API = "127.0.0.1:10085"
# False = با هر تغییر کاربر، Xray ری‌استارت می‌شه (مطمئن‌تر: همه‌ی پروتکل‌ها همیشه همه‌ی کاربرها رو دارن)
LIVE_ADD = False

def pairs(users):
    return frozenset((u["id"], p) for u in users for p in u["protos"].split(",") if p in INB)

def sync():
    """Adding users/protocols is live (no disconnects). Removing restarts Xray so open connections are cut."""
    global proc, current
    with L:
        users = [u for u in db.execute("SELECT * FROM users") if is_active(u)]
        ids = pairs(users)
        alive = proc is not None and proc.poll() is None
        if alive and ids == current:
            return
        if LIVE_ADD and alive and current is not None and current <= ids:
            try:
                by = {}
                for u in users:
                    for p in u["protos"].split(","):
                        if p in INB and (u["id"], p) not in current:
                            by.setdefault(p, []).append(u)
                inb = []
                for p, us in by.items():
                    st = {"clients": clients_for(p, us, dummy=False)}
                    if INB[p][2] == "vless":
                        st["decryption"] = "none"
                    inb.append({"tag": INB[p][0], "protocol": INB[p][2], "settings": st})
                path = os.path.join(DATA, "adu.json")
                with open(path, "w") as f:
                    json.dump({"inbounds": inb}, f)
                r = subprocess.run(["xray", "api", "adu", "-s", API, path], capture_output=True, text=True, timeout=10)
                if r.returncode == 0:
                    write_config(users)
                    current = ids
                    return
            except Exception as e:
                print("live add failed, restarting:", e)
        if alive:
            collect()  # save traffic counters before they reset
            proc.terminate()
            try: proc.wait(5)
            except Exception: proc.kill()
        write_config(users)
        proc = subprocess.Popen(["xray", "run", "-c", CONF])
        current = ids
        print("[xray] started, users per protocol:",
              {p: sum(1 for i, q in ids if q == p) for p in INB}, flush=True)

def collect():
    try:
        out = subprocess.run(["xray", "api", "statsquery", "-s", "127.0.0.1:10085",
                              "-pattern", "user>>>", "-reset"],
                             capture_output=True, text=True, timeout=10).stdout
        stats = json.loads(out).get("stat", []) if out.strip() else []
    except Exception:
        return
    with L:
        for s in stats:
            p = s["name"].split(">>>")
            if len(p) < 4 or not p[1].startswith("u"):
                continue
            col = "up" if p[3] == "uplink" else "down"
            db.execute(f"UPDATE users SET {col}={col}+? WHERE id=?", (int(s["value"]), int(p[1][1:])))
        db.execute("UPDATE users SET expire=?+ttl_days*86400, ttl_days=0 WHERE ttl_days>0 AND expire=0 AND up+down>0", (int(time.time()),))
        db.commit()

def loop():
    time.sleep(3)
    while True:
        try:
            collect()
            sync()
        except Exception as e:
            print("loop error:", e)
        time.sleep(10)

@app.on_event("startup")
def start():
    sync()
    threading.Thread(target=loop, daemon=True).start()

# ---------- API ----------
def clean_protos(l):
    l = [p for p in (l or []) if p in PATHS]
    return ",".join(dict.fromkeys(l)) or "vmess"

class NewUser(BaseModel):
    name: str
    gb: float = 0
    days: int = 0
    note: str = ""
    protos: list = ["vmess"]
    port: int = 443
    fp: str = ""
    addr: str = ""
    first_use: bool = False
    count: int = 1
    uuid: str = ""
    enabled: bool = True

class EditUser(BaseModel):
    name: Optional[str] = None
    note: Optional[str] = None
    gb: Optional[float] = None
    days: Optional[int] = None
    add_gb: Optional[float] = None
    add_days: Optional[int] = None
    enabled: Optional[bool] = None
    protos: Optional[list] = None
    port: Optional[int] = None
    fp: Optional[str] = None
    addr: Optional[str] = None
    reset: bool = False

def links(u, st=None):
    st = st or settings()
    dom = st["domain"] or DOMAIN
    addr = u["addr"] or st["address"] or DEFAULT_ADDRESS or dom
    fp = u["fp"] or st["fp"]
    port, tls = u["port"], u["port"] != 80
    name = st["prefix"] + u["name"]
    out = []
    for p in u["protos"].split(","):
        if p not in PATHS:
            continue
        if p == "vmess":
            cfg = {"v": "2", "ps": f"{name} {LABEL[p]}", "add": addr, "port": str(port), "id": u["uuid"], "aid": "0",
                   "scy": "auto", "net": "ws", "type": "none", "host": dom, "path": PATHS[p],
                   "tls": "tls" if tls else "", "sni": dom if tls else "", "alpn": "http/1.1" if tls else "",
                   "fp": fp if tls else ""}
            out.append((p, "vmess://" + base64.b64encode(json.dumps(cfg, ensure_ascii=False).encode()).decode()))
            continue
        q = {"security": "tls" if tls else "none", "type": "httpupgrade" if p == "vlessh" else "ws",
             "host": dom, "path": PATHS[p]}
        if p != "trojan":
            q["encryption"] = "none"
        if tls:
            q.update(sni=dom, fp=fp, alpn="http/1.1")
        scheme = "trojan" if p == "trojan" else "vless"
        tag = urllib.parse.quote(f"{name} {LABEL[p]}")
        out.append((p, f"{scheme}://{u['uuid']}@{addr}:{port}?{urllib.parse.urlencode(q)}#{tag}"))
    return out

@app.get("/api/users", dependencies=[Depends(auth)])
def list_users():
    st = settings()
    with L:
        return [dict(u, active=bool(is_active(u)), links=[{"p": p, "l": l} for p, l in links(u, st)])
                for u in db.execute("SELECT * FROM users ORDER BY id DESC")]

@app.post("/api/users", dependencies=[Depends(auth)])
def add_user(n: NewUser):
    cnt = max(1, min(n.count, 200))
    with L:
        for i in range(cnt):
            name = n.name.strip() or "user"
            if cnt > 1:
                name = f"{name}-{i + 1}"
            uid_ = str(uuid.uuid4())
            if cnt == 1 and n.uuid:
                try: uid_ = str(uuid.UUID(n.uuid))
                except ValueError: raise HTTPException(400, "bad uuid")
            first = n.first_use and n.days > 0
            db.execute("INSERT INTO users(name,uuid,token,limit_bytes,expire,note,created,protos,port,fp,addr,ttl_days,enabled) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (name, uid_, secrets.token_urlsafe(12), int(n.gb * GB),
                        0 if first or not n.days else int(time.time() + n.days * 86400), n.note, int(time.time()),
                        clean_protos(n.protos), n.port, n.fp, n.addr.strip(), n.days if first else 0, int(n.enabled)))
        db.commit()
    sync()
    return {"ok": True}

@app.put("/api/users/{uid}", dependencies=[Depends(auth)])
def edit_user(uid: int, e: EditUser):
    with L:
        u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not u:
            raise HTTPException(404)
        f = {}
        if e.name is not None: f["name"] = e.name.strip() or u["name"]
        if e.note is not None: f["note"] = e.note
        if e.enabled is not None: f["enabled"] = int(e.enabled)
        if e.protos is not None: f["protos"] = clean_protos(e.protos)
        if e.port is not None: f["port"] = e.port
        if e.fp is not None: f["fp"] = e.fp
        if e.addr is not None: f["addr"] = e.addr.strip()
        if e.gb is not None: f["limit_bytes"] = int(e.gb * GB)
        if e.days is not None:  # counted from now; 0 = unlimited
            f["expire"] = int(time.time() + e.days * 86400) if e.days else 0
            f["ttl_days"] = 0
        if e.add_gb:
            f["limit_bytes"] = int((f.get("limit_bytes", u["limit_bytes"])) + e.add_gb * GB)
        if e.add_days:
            base = max(f.get("expire", u["expire"]), time.time()) if u["expire"] or "expire" in f else time.time()
            f["expire"] = int(base + e.add_days * 86400)
        if e.reset: f["up"] = f["down"] = 0
        if f:
            db.execute("UPDATE users SET " + ",".join(f"{k}=?" for k in f) + " WHERE id=?", (*f.values(), uid))
            db.commit()
    sync()
    return {"ok": True}

@app.delete("/api/users/{uid}", dependencies=[Depends(auth)])
def del_user(uid: int):
    with L:
        db.execute("DELETE FROM users WHERE id=?", (uid,))
        db.commit()
    sync()
    return {"ok": True}

@app.get("/api/settings", dependencies=[Depends(auth)])
def get_settings():
    return dict(settings(), default_domain=DOMAIN, ws_path=WS_PATH)

@app.put("/api/settings", dependencies=[Depends(auth)])
def put_settings(body: dict):
    with L:
        for k, v in body.items():
            if k in DEFAULTS:
                db.execute("INSERT OR REPLACE INTO settings(k,v) VALUES(?,?)", (k, str(v)[:200]))
        db.commit()
    return {"ok": True}

@app.get("/api/stats", dependencies=[Depends(auth)])
def stats():
    with L:
        us = list(db.execute("SELECT * FROM users"))
    mem = {}
    try:
        for ln in open("/proc/meminfo"):
            k, v = ln.split(":"); mem[k] = int(v.split()[0]) * 1024
    except Exception:
        pass
    total = mem.get("MemTotal", 0)
    return {"users": len(us), "active": sum(1 for u in us if is_active(u)),
            "expired": sum(1 for u in us if u["expire"] and u["expire"] < time.time()),
            "traffic": sum(u["up"] + u["down"] for u in us),
            "ram_used": total - mem.get("MemAvailable", total), "ram_total": total,
            "load": os.getloadavg()[0], "xray": proc is not None and proc.poll() is None}

@app.get("/sub/{token}")
def sub(token: str):
    with L:
        u = db.execute("SELECT * FROM users WHERE token=?", (token,)).fetchone()
    if not u:
        raise HTTPException(404)
    st = settings()
    h = {"subscription-userinfo": f"upload={u['up']}; download={u['down']}; total={u['limit_bytes']}; expire={u['expire']}",
         "profile-update-interval": "1",
         "profile-title": "base64:" + base64.b64encode(st["title"].encode()).decode()}
    return Response(base64.b64encode("\n".join(l for _, l in links(u, st)).encode()), media_type="text/plain", headers=h)

@app.get("/")
def root(request: Request):
    if authed(request):
        return HTMLResponse(open(os.path.join(HERE, "admin.html"), encoding="utf-8").read())
    return RedirectResponse("/login")

fails = {}

def client_ip(request: Request):
    return (request.headers.get("x-forwarded-for") or request.client.host).split(",")[0].strip()

@app.post("/login")
def login(body: dict, request: Request):
    ip, now = client_ip(request), time.time()
    n, t = fails.get(ip, (0, now))
    if now - t > 600:
        n, t = 0, now
    if n >= 5:
        raise HTTPException(429)
    ok = (secrets.compare_digest(str(body.get("username", "")).strip().lower().encode(), ADMIN_USER.lower().encode())
          and secrets.compare_digest(str(body.get("password", "")).strip().encode(), ADMIN_PASSWORD.encode()))
    if not ok:
        fails[ip] = (n + 1, t)
        time.sleep(1.2)
        raise HTTPException(401)
    fails.pop(ip, None)
    r = Response('{"ok":true}', media_type="application/json")
    r.set_cookie("sess", _tok(), max_age=7 * 86400, httponly=True, samesite="lax", secure=True)
    return r

@app.get("/api/theme")
def theme():
    st = settings()
    return {k: st[k] for k in ("title", "accent", "accent2")}

@app.get("/logout")
def logout():
    r = RedirectResponse("/login")
    r.delete_cookie("sess")
    return r

@app.get("/login", response_class=HTMLResponse)
def login_page():
    return LOGIN

HERE = os.path.dirname(os.path.abspath(__file__))

@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request):
    if not authed(request):
        return RedirectResponse("/login")
    return open(os.path.join(HERE, "admin.html"), encoding="utf-8").read()

LOGIN = """<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>ورود</title>
<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:system-ui,Tahoma,sans-serif;
background:radial-gradient(900px 500px at 80% -10%,color-mix(in srgb,var(--a,#7c5cff) 70%,#000) 0,transparent 60%),radial-gradient(700px 500px at 0 110%,#0f6e8c 0,transparent 55%),#0a0c13;color:#eef0f8}
.b{width:min(360px,92vw);padding:28px;border-radius:22px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);backdrop-filter:blur(18px)}
h2{margin:0 0 4px}p{margin:0 0 18px;color:#9aa3bd;font-size:14px}
input{width:100%;padding:13px 14px;margin:6px 0;border-radius:12px;border:1px solid rgba(255,255,255,.14);background:rgba(0,0,0,.3);color:#fff;font-size:15px}
button{width:100%;margin-top:12px;padding:13px;border:0;border-radius:12px;background:linear-gradient(135deg,var(--a,#7c5cff),var(--a2,#5b8cff));color:#fff;font-size:16px;font-weight:700}
#e{color:#ff6b7a;font-size:13px;min-height:18px;margin-top:8px}</style></head><body>
<form class="b" onsubmit="go(event)"><h2>🔐 ورود به پنل</h2><p>اطلاعات مدیر را وارد کنید</p>
<input id="u" placeholder="نام کاربری" autocomplete="username" autocapitalize="none"><input id="p" type="password" placeholder="رمز عبور" autocomplete="current-password"><label style="font-size:13px;color:#9aa3bd;display:block;margin-top:4px"><input type="checkbox" style="width:auto;margin:6px" onchange="p.type=this.checked?'text':'password'">نمایش رمز</label>
<button>ورود</button><div id="e"></div></form>
<script>async function go(ev){ev.preventDefault();const r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({username:u.value,password:p.value})});if(r.ok)location='/admin';else e.textContent=r.status==429?'تلاش بیش از حد؛ ۱۰ دقیقه صبر کنید':r.status==401?'نام کاربری یا رمز اشتباه است':'خطای سرور (کد '+r.status+')'}
fetch('/api/theme').then(r=>r.json()).then(t=>{const s=document.documentElement.style;s.setProperty('--a',t.accent);s.setProperty('--a2',t.accent2);document.title=t.title;document.querySelector('h2').textContent='🔐 '+t.title})</script></body></html>"""
