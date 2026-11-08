import os, json, time, uuid, secrets, base64, sqlite3, subprocess, threading, hmac, hashlib
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Response, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel

# >>>>>>>>>> کلید ورود: یک متن طولانی و دلخواه بذار (هرکی این رو بدونه پنل رو می‌بینه) <<<<<<<<<<
ACCESS_KEY = (os.environ.get("ACCESS_KEY") or "amksjsjkshdhjsj").strip()
# True = با باز کردن خود دامنه مستقیم وارد پنل می‌شی (بدون هیچ رمزی) | False = فقط با لینک /enter/کلید
OPEN_ACCESS = True
# >>>>>>>>>> دامنه ریلوی خودتو اینجا بذار (بدون https://) <<<<<<<<<<
RAILWAY_DOMAIN = "confamir.up.railway.app"
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
DOMAIN = os.environ.get("DOMAIN") or RAILWAY_DOMAIN
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
 note TEXT DEFAULT '', created INTEGER DEFAULT 0)""")
db.execute("CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT)")
for col in ("note TEXT DEFAULT ''", "created INTEGER DEFAULT 0"):
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
    return hmac.new(ACCESS_KEY.encode(), b"panel-session", hashlib.sha256).hexdigest()

def authed(request: Request):
    if OPEN_ACCESS:
        return True
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

def write_config(users):
    clients = [{"id": u["uuid"], "email": f"u{u['id']}", "alterId": 0} for u in users]
    if not clients:  # xray needs at least one client
        clients = [{"id": str(uuid.uuid4()), "email": "dummy", "alterId": 0}]
    cfg = {
        "log": {"loglevel": "warning"},
        "api": {"tag": "api", "services": ["HandlerService", "StatsService"]},
        "stats": {},
        "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}}},
        "inbounds": [
            {"tag": "api", "listen": "127.0.0.1", "port": 10085, "protocol": "dokodemo-door",
             "settings": {"address": "127.0.0.1"}},
            {"tag": "vmess-in", "listen": "127.0.0.1", "port": 10000, "protocol": "vmess",
             "settings": {"clients": clients},
             "streamSettings": {"network": "ws", "wsSettings": {"path": WS_PATH}}},
        ],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
        "routing": {"rules": [{"type": "field", "inboundTag": ["api"], "outboundTag": "api"}]},
    }
    with open(CONF, "w") as f:
        json.dump(cfg, f)

API = "127.0.0.1:10085"

def sync():
    """Adding users is live (no disconnects). Removing restarts Xray so open connections are cut."""
    global proc, current
    with L:
        users = [u for u in db.execute("SELECT * FROM users") if is_active(u)]
        ids = frozenset(u["id"] for u in users)
        alive = proc is not None and proc.poll() is None
        if alive and ids == current:
            return
        if alive and current is not None and current <= ids:
            new = [u for u in users if u["id"] not in current]
            try:
                p = os.path.join(DATA, "adu.json")
                with open(p, "w") as f:
                    json.dump({"inbounds": [{"tag": "vmess-in", "protocol": "vmess", "settings": {"clients": [
                        {"id": u["uuid"], "email": f"u{u['id']}", "alterId": 0} for u in new]}}]}, f)
                r = subprocess.run(["xray", "api", "adu", "-s", API, p], capture_output=True, text=True, timeout=10)
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
class NewUser(BaseModel):
    name: str
    gb: float = 0
    days: int = 0
    note: str = ""

class EditUser(BaseModel):
    name: Optional[str] = None
    note: Optional[str] = None
    gb: Optional[float] = None
    days: Optional[int] = None
    add_gb: Optional[float] = None
    add_days: Optional[int] = None
    enabled: Optional[bool] = None
    reset: bool = False

def link(u, st=None):
    st = st or settings()
    dom = st["domain"] or DOMAIN
    cfg = {"v": "2", "ps": st["prefix"] + u["name"], "add": st["address"] or dom, "port": "443",
           "id": u["uuid"], "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": dom,
           "path": WS_PATH, "tls": "tls", "sni": dom, "alpn": "http/1.1", "fp": st["fp"]}
    return "vmess://" + base64.b64encode(json.dumps(cfg, ensure_ascii=False).encode()).decode()

@app.get("/api/users", dependencies=[Depends(auth)])
def list_users():
    st = settings()
    with L:
        return [dict(u, active=bool(is_active(u)), link=link(u, st)) for u in db.execute("SELECT * FROM users ORDER BY id DESC")]

@app.post("/api/users", dependencies=[Depends(auth)])
def add_user(n: NewUser):
    with L:
        db.execute("INSERT INTO users(name,uuid,token,limit_bytes,expire,note,created) VALUES(?,?,?,?,?,?,?)",
                   (n.name.strip() or "user", str(uuid.uuid4()), secrets.token_urlsafe(12), int(n.gb * GB),
                    int(time.time() + n.days * 86400) if n.days else 0, n.note, int(time.time())))
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
        if e.gb is not None: f["limit_bytes"] = int(e.gb * GB)
        if e.days is not None: f["expire"] = int(time.time() + e.days * 86400) if e.days else 0
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
    return Response(base64.b64encode(link(u, st).encode()), media_type="text/plain", headers=h)

@app.get("/")
def root(request: Request):
    if authed(request):
        return HTMLResponse(open(os.path.join(HERE, "admin.html"), encoding="utf-8").read())
    return Response("ok", media_type="text/plain")

@app.get("/enter/{key}")
def enter(key: str):
    if not secrets.compare_digest(key.encode(), ACCESS_KEY.encode()):
        time.sleep(1)
        raise HTTPException(404)
    r = RedirectResponse("/admin")
    r.set_cookie("sess", _tok(), max_age=30 * 86400, httponly=True, samesite="lax", secure=True)
    return r

@app.get("/logout")
def logout():
    r = RedirectResponse("/")
    r.delete_cookie("sess")
    return r

HERE = os.path.dirname(os.path.abspath(__file__))

@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request):
    if not authed(request):
        raise HTTPException(404)
    return open(os.path.join(HERE, "admin.html"), encoding="utf-8").read()

