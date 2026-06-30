"""
╔══════════════════════════════════════════════════════════╗
║           XRay Panel - Powered by FastAPI + SQLite       ║
║           VLESS + WS + TLS Subscription Manager          ║
║           Telegram Notifications | Clean IP Manager      ║
╚══════════════════════════════════════════════════════════╝
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import platform
import re
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

import aiosqlite
import httpx
import psutil
from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    Form,
    HTTPException,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
PANEL_VERSION = "2.0.0"
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Admin@12345")
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DOMAIN = os.environ.get("DOMAIN", "localhost:8000")
DB_PATH = os.environ.get("DB_PATH", "/data/panel.db")
PORT = int(os.environ.get("PORT", 8000))
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "")
TG_CHAT_ID = os.environ.get("TG_CHAT_ID", "")

# Ensure DB directory exists
os.makedirs(os.path.dirname(DB_PATH) if os.path.dirname(DB_PATH) else ".", exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("xray-panel")

# ─────────────────────────────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────────────────────────────
async def get_db():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        yield db


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                email TEXT,
                traffic_limit_gb REAL DEFAULT 0,
                used_traffic_bytes INTEGER DEFAULT 0,
                expire_days INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                expire_at TEXT,
                is_active INTEGER DEFAULT 1,
                max_connections INTEGER DEFAULT 0,
                note TEXT DEFAULT '',
                flag TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS clean_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                label TEXT DEFAULT '',
                is_active INTEGER DEFAULT 1,
                added_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_uuid TEXT NOT NULL,
                bytes_used INTEGER DEFAULT 0,
                logged_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS login_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                user_agent TEXT,
                success INTEGER DEFAULT 0,
                logged_at TEXT NOT NULL
            );
        """)

        # Default settings
        defaults = {
            "panel_title": "IranX-Panel",
            "ws_path": "/vless-ws",
            "sni": DOMAIN,
            "host_header": DOMAIN,
            "tls_fingerprint": "chrome",
            "fragment": "",
            "keepalive_enabled": "0",
            "keepalive_interval": "300",
            "keepalive_mode": "simple",
            "tg_enabled": "0",
            "tg_bot_token": TG_BOT_TOKEN,
            "tg_chat_id": TG_CHAT_ID,
            "tg_lang": "fa",
        }
        for k, v in defaults.items():
            await db.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v)
            )
        await db.commit()
        log.info("✅ Database initialized")


async def get_setting(key: str, default: str = "") -> str:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT value FROM settings WHERE key=?", (key,)) as cur:
            row = await cur.fetchone()
            return row[0] if row else default


async def set_setting(key: str, value: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value)
        )
        await db.commit()

# ─────────────────────────────────────────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────────────────────────────────────────
def make_token(username: str) -> str:
    ts = str(int(time.time()))
    msg = f"{username}:{ts}"
    sig = hmac.new(SECRET_KEY.encode(), msg.encode(), hashlib.sha256).hexdigest()
    raw = f"{msg}:{sig}"
    return raw.encode().hex()


def verify_token(token: str) -> Optional[str]:
    try:
        raw = bytes.fromhex(token).decode()
        parts = raw.split(":")
        if len(parts) != 3:
            return None
        username, ts, sig = parts
        age = int(time.time()) - int(ts)
        if age > 86400 * 7:  # 7 days
            return None
        msg = f"{username}:{ts}"
        expected = hmac.new(SECRET_KEY.encode(), msg.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig, expected):
            return username
    except Exception:
        pass
    return None


def require_auth(session: Optional[str] = Cookie(None)):
    if not session or not verify_token(session):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True

# ─────────────────────────────────────────────────────────────────────────────
# TELEGRAM
# ─────────────────────────────────────────────────────────────────────────────
async def send_telegram(message: str):
    token = await get_setting("tg_bot_token")
    chat_id = await get_setting("tg_chat_id")
    enabled = await get_setting("tg_enabled", "0")
    if enabled != "1" or not token or not chat_id:
        return
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat_id, "text": message, "parse_mode": "HTML"},
            )
    except Exception as e:
        log.warning(f"Telegram send failed: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# SUBSCRIPTION LINK BUILDER
# ─────────────────────────────────────────────────────────────────────────────
async def build_vless_link(
    user_uuid: str,
    user_name: str,
    flag: str = "",
    address: str = None,
) -> str:
    from urllib.parse import quote
    domain = DOMAIN
    sni = await get_setting("sni", domain)
    host_header = await get_setting("host_header", domain)
    fp = await get_setting("tls_fingerprint", "chrome")
    fragment = await get_setting("fragment", "")

    # Per-user unique path
    ws_path = f"/ws/{user_uuid}"

    # اگه IP تمیز داده شده، آدرس اتصال عوض میشه ولی SNI و host ثابت میمونه
    connect_addr = address if address else domain

    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "path": ws_path,
        "host": host_header,
        "sni": sni,
        "fp": fp,
        "alpn": "http/1.1",
    }
    if fragment:
        params["fragment"] = fragment

    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    label = f"{flag} {user_name}".strip() if flag else user_name
    return f"vless://{user_uuid}@{connect_addr}:443?{query}#{quote(label)}"


async def build_subscription(user_uuid: str) -> str:
    import base64
    from urllib.parse import quote

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM users WHERE uuid=? AND is_active=1", (user_uuid,)
        ) as cur:
            user = await cur.fetchone()
    if not user:
        return ""

    # Check expiry
    if user["expire_at"]:
        exp = datetime.fromisoformat(user["expire_at"])
        if datetime.now() > exp:
            return ""

    # Check traffic
    limit_bytes = user["traffic_limit_gb"] * 1024 ** 3
    if limit_bytes > 0 and user["used_traffic_bytes"] >= limit_bytes:
        return ""

    # ── Calculate remaining traffic & days ───────────────────────────────────
    lim_gb = float(user["traffic_limit_gb"] or 0)
    used_b = int(user["used_traffic_bytes"] or 0)
    lim_b  = lim_gb * 1024 ** 3
    rem_b  = max(0, lim_b - used_b) if lim_b > 0 else 0
    rem_gb = round(rem_b / 1024 ** 3, 2) if lim_b > 0 else 0
    rem_txt = f"{rem_gb}GB" if lim_b > 0 else "∞"

    days_left_txt = "∞"
    if user["expire_at"]:
        try:
            diff = datetime.fromisoformat(user["expire_at"]) - datetime.now()
            dl = max(0, diff.days)
            days_left_txt = f"{dl}d"
        except Exception:
            pass

    name = user["name"]
    flag = user["flag"] or ""

    # ── Get active clean IPs ──────────────────────────────────────────────────
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT ip, label FROM clean_ips WHERE is_active=1 ORDER BY id"
        ) as cur:
            ips = await cur.fetchall()

    links = []

    # ── 1. Info-only "fake" config — always first in the list ─────────────────
    # This is a dummy vless link whose only purpose is to show subscription
    # info in the client's config name. It uses a loopback address so it
    # never actually connects (clients show it as errored/offline, which
    # is fine — the label is what matters).
    info_label = f"📊 {flag} {name} | 💾 {rem_txt} left | ⏰ {days_left_txt}".strip()
    # Use the real UUID but point at 127.0.0.1 so it never routes real traffic
    from urllib.parse import quote as _quote
    domain = DOMAIN
    sni = await get_setting("sni", domain)
    _ws_path = '/ws/' + user["uuid"]
    info_params = (
        "encryption=none&security=tls&type=ws"
        f"&path={_quote(_ws_path)}"
        f"&host={_quote(sni)}&sni={_quote(sni)}&fp=chrome&alpn=http%2F1.1"
    )
    info_link = f"vless://{user['uuid']}@127.0.0.1:443?{info_params}#{_quote(info_label)}"
    links.append(info_link)

    # ── 2. Real connection configs ────────────────────────────────────────────
    if ips:
        for ip_row in ips:
            ip_addr = ip_row["ip"]
            ip_label = ip_row["label"] or ip_addr
            display_name = f"{flag} {name} | {rem_txt} | {ip_label}".strip()
            link = await build_vless_link(user["uuid"], display_name, address=ip_addr)
            links.append(link)
    else:
        display_name = f"{flag} {name} | {rem_txt}".strip()
        link = await build_vless_link(user["uuid"], display_name, "")
        links.append(link)

    content = "\n".join(links)
    return base64.b64encode(content.encode()).decode()

async def build_subscription_userinfo_header(user_uuid: str) -> str:
    """Build Clash/Sing-box compatible Subscription-Userinfo header.

    Format: upload=<bytes>; download=<bytes>; total=<bytes>; expire=<unix_ts>
    We don't track upload/download separately in this panel, so we report used as download.
    """
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT used_traffic_bytes, traffic_limit_gb, expire_at FROM users WHERE uuid=?",
            (user_uuid,),
        ) as cur:
            u = await cur.fetchone()

    if not u:
        return "upload=0; download=0; total=0; expire=0"

    used = int(u["used_traffic_bytes"] or 0)
    limit_gb = float(u["traffic_limit_gb"] or 0)
    total = int(limit_gb * 1024 ** 3) if limit_gb > 0 else 0

    expire_ts = 0
    if u["expire_at"]:
        try:
            expire_dt = datetime.fromisoformat(u["expire_at"])
            expire_ts = int(expire_dt.replace(tzinfo=timezone.utc).timestamp()) if expire_dt.tzinfo is None else int(expire_dt.timestamp())
        except Exception:
            expire_ts = 0

    # We only track aggregate bytes, so map it to download.
    return f"upload=0; download={used}; total={total}; expire={expire_ts}"


# ─────────────────────────────────────────────────────────────────────────────
# KEEP-ALIVE
# ─────────────────────────────────────────────────────────────────────────────
keepalive_task: Optional[asyncio.Task] = None


async def keepalive_loop():
    while True:
        try:
            enabled = await get_setting("keepalive_enabled", "0")
            if enabled == "1":
                interval = int(await get_setting("keepalive_interval", "300"))
                scheme = "https" if DOMAIN != "localhost:8000" else "http"
                url = f"{scheme}://{DOMAIN}/health"
                async with httpx.AsyncClient(timeout=15) as client:
                    await client.get(url)
                await asyncio.sleep(interval)
            else:
                await asyncio.sleep(60)
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(60)

# ─────────────────────────────────────────────────────────────────────────────
# EXPIRY CHECKER
# ─────────────────────────────────────────────────────────────────────────────
async def check_expiry_loop():
    while True:
        try:
            async with aiosqlite.connect(DB_PATH) as db:
                now = datetime.now().isoformat()
                async with db.execute(
                    "SELECT uuid, name FROM users WHERE expire_at <= ? AND is_active=1 AND expire_at IS NOT NULL",
                    (now,),
                ) as cur:
                    expired = await cur.fetchall()
                if expired:
                    await db.execute(
                        "UPDATE users SET is_active=0 WHERE expire_at <= ? AND is_active=1 AND expire_at IS NOT NULL",
                        (now,),
                    )
                    await db.commit()
                    for u in expired:
                        await send_telegram(
                            f"⏰ <b>اشتراک منقضی شد</b>\n👤 کاربر: <code>{u[1]}</code>"
                        )
        except Exception as e:
            log.warning(f"Expiry check error: {e}")
        await asyncio.sleep(300)

# ─────────────────────────────────────────────────────────────────────────────
# LIFESPAN
# ─────────────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    ka_task = asyncio.create_task(keepalive_loop())
    ex_task = asyncio.create_task(check_expiry_loop())
    log.info(f"🚀 XRay Panel v{PANEL_VERSION} started on port {PORT}")
    yield
    ka_task.cancel()
    ex_task.cancel()

# ─────────────────────────────────────────────────────────────────────────────
# APP
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(title="IranX-Panel", lifespan=lifespan)

# ─────────────────────────────────────────────────────────────────────────────
# ROUTES – PUBLIC
# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# WEBSOCKET VLESS PROXY TUNNEL
# ─────────────────────────────────────────────────────────────────────────────
active_connections: dict = {}
active_connections_lock = asyncio.Lock()


async def pipe(reader, ws, user_uuid: str, direction: str):
    """Pipe data between TCP stream and WebSocket."""
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            await ws.send_bytes(data)
            # Track traffic
            async with aiosqlite.connect(DB_PATH) as db:
                await db.execute(
                    "UPDATE users SET used_traffic_bytes = used_traffic_bytes + ? WHERE uuid=?",
                    (len(data), user_uuid)
                )
                await db.commit()
    except Exception:
        pass


async def pipe_ws_to_tcp(ws: WebSocket, writer, user_uuid: str):
    """Pipe data from WebSocket to TCP stream."""
    try:
        while True:
            data = await ws.receive_bytes()
            if not data:
                break
            writer.write(data)
            await writer.drain()
            async with aiosqlite.connect(DB_PATH) as db:
                await db.execute(
                    "UPDATE users SET used_traffic_bytes = used_traffic_bytes + ? WHERE uuid=?",
                    (len(data), user_uuid)
                )
                await db.commit()
    except Exception:
        pass


@app.websocket("/ws/{user_uuid}")
async def vless_ws_tunnel(websocket: WebSocket, user_uuid: str):
    """
    VLESS over WebSocket proxy endpoint.
    Per-user path: /ws/{uuid}
    Reads VLESS header, opens TCP to destination, bidirectional pipe.
    """
    # Validate user
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM users WHERE uuid=? AND is_active=1", (user_uuid,)
        ) as cur:
            user = await cur.fetchone()

    if not user:
        await websocket.close(code=1008)
        return

    # Check expiry
    if user["expire_at"]:
        exp = datetime.fromisoformat(user["expire_at"])
        if datetime.now() > exp:
            await websocket.close(code=1008)
            return

    # Check traffic limit
    limit_bytes = user["traffic_limit_gb"] * 1024 ** 3
    if limit_bytes > 0 and user["used_traffic_bytes"] >= limit_bytes:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    conn_id = str(uuid.uuid4())
    async with active_connections_lock:
        active_connections[conn_id] = {
            "uuid": user_uuid,
            "name": user["name"],
            "connected_at": datetime.now().isoformat(),
        }

    reader = None
    writer = None

    try:
        # Read first chunk — contains VLESS header
        first_data = await websocket.receive_bytes()
        if not first_data or len(first_data) < 18:
            await websocket.close(code=1003)
            return

        # ── Parse VLESS header ──────────────────────────────────────────────
        # Byte 0:    version (must be 0)
        # Bytes 1-16: UUID (16 bytes)
        # Byte 17:   addons length (skip)
        # Byte 18:   command (1=TCP, 2=UDP, 3=MUX)
        # Byte 19-20: dest port (big-endian)
        # Byte 21:   addr type (1=IPv4, 2=domain, 3=IPv6)
        # ...then address, then payload

        version = first_data[0]
        if version != 0:
            await websocket.close(code=1003)
            return

        offset = 17
        addon_len = first_data[offset]
        offset += 1 + addon_len  # skip addons

        command = first_data[offset]
        offset += 1

        if command not in (1, 2):  # TCP or UDP only
            await websocket.close(code=1003)
            return

        # Port
        port = (first_data[offset] << 8) | first_data[offset + 1]
        offset += 2

        # Address type
        addr_type = first_data[offset]
        offset += 1

        if addr_type == 1:  # IPv4
            host = ".".join(str(b) for b in first_data[offset:offset + 4])
            offset += 4
        elif addr_type == 2:  # Domain
            domain_len = first_data[offset]
            offset += 1
            host = first_data[offset:offset + domain_len].decode("utf-8", errors="replace")
            offset += domain_len
        elif addr_type == 3:  # IPv6
            import socket as _socket
            host = _socket.inet_ntop(_socket.AF_INET6, first_data[offset:offset + 16])
            offset += 16
        else:
            await websocket.close(code=1003)
            return

        # Remaining bytes after header = first payload chunk
        payload = first_data[offset:]

        log.info(f"VLESS tunnel: {user['name']} → {host}:{port}")

        # Open TCP connection to destination
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=10
        )

        # Send VLESS response header (version + addons length 0)
        await websocket.send_bytes(bytes([0, 0]))

        # Send first payload if any
        if payload:
            writer.write(payload)
            await writer.drain()

        # Bidirectional piping
        await asyncio.gather(
            pipe(reader, websocket, user_uuid, "down"),
            pipe_ws_to_tcp(websocket, writer, user_uuid),
            return_exceptions=True
        )

    except asyncio.TimeoutError:
        log.warning(f"VLESS tunnel timeout for {user_uuid}")
    except WebSocketDisconnect:
        pass
    except Exception as e:
        log.warning(f"VLESS tunnel error for {user_uuid}: {e}")
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        try:
            await websocket.close()
        except Exception:
            pass
        async with active_connections_lock:
            active_connections.pop(conn_id, None)


@app.websocket("/ws/{user_uuid}/{path:path}")
async def vless_ws_tunnel_path(websocket: WebSocket, user_uuid: str, path: str):
    """Support custom path per user."""
    await vless_ws_tunnel(websocket, user_uuid)


@app.get("/api/connections")
async def get_connections(auth=Depends(require_auth)):
    async with active_connections_lock:
        return {"count": len(active_connections), "connections": list(active_connections.values())}


# ─────────────────────────────────────────────────────────────────────────────
# HEALTH
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "version": PANEL_VERSION, "time": datetime.now().isoformat()}


@app.get("/sub/{user_uuid}", response_class=PlainTextResponse)
async def subscription(user_uuid: str):
    content = await build_subscription(user_uuid)
    if not content:
        raise HTTPException(status_code=404, detail="User not found or expired")
    userinfo = await build_subscription_userinfo_header(user_uuid)
    return PlainTextResponse(
        content,
        headers={
            "Content-Type": "text/plain; charset=utf-8",
            "Profile-Update-Interval": "6",
            "Subscription-Userinfo": userinfo,
        },
    )


@app.get("/", response_class=RedirectResponse)
async def root():
    return RedirectResponse("/panel")

# ─────────────────────────────────────────────────────────────────────────────
# ROUTES – AUTH
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/login")
async def login(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    ip = request.client.host
    ua = request.headers.get("user-agent", "")
    success = username == ADMIN_USERNAME and password == ADMIN_PASSWORD
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO login_logs (ip, user_agent, success, logged_at) VALUES (?,?,?,?)",
            (ip, ua, 1 if success else 0, datetime.now().isoformat()),
        )
        await db.commit()
    if not success:
        raise HTTPException(status_code=401, detail="نام کاربری یا رمز اشتباه است")
    token = make_token(username)
    response.set_cookie("session", token, httponly=True, samesite="lax", max_age=86400 * 7)
    await send_telegram(f"🔐 <b>ورود به پنل</b>\n🌐 IP: <code>{ip}</code>")
    return {"ok": True}


@app.post("/api/logout")
async def logout(response: Response):
    response.delete_cookie("session")
    return {"ok": True}

# ─────────────────────────────────────────────────────────────────────────────
# ROUTES – USERS (protected)
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/api/users")
async def list_users(auth=Depends(require_auth)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM users ORDER BY created_at DESC") as cur:
            rows = await cur.fetchall()
    result = []
    for r in rows:
        d = dict(r)
        limit_bytes = d["traffic_limit_gb"] * 1024 ** 3
        d["traffic_percent"] = (
            min(100, int(d["used_traffic_bytes"] / limit_bytes * 100))
            if limit_bytes > 0
            else 0
        )
        d["used_traffic_gb"] = round(d["used_traffic_bytes"] / 1024 ** 3, 3)
        result.append(d)
    return result


@app.post("/api/users")
async def create_user(request: Request, auth=Depends(require_auth)):
    data = await request.json()
    user_uuid = str(uuid.uuid4())
    name = data.get("name", "").strip()
    if not name:
        raise HTTPException(400, "نام کاربر الزامی است")
    email = data.get("email", "")
    traffic_gb = float(data.get("traffic_limit_gb", 0))
    expire_days = int(data.get("expire_days", 0))
    max_conn = int(data.get("max_connections", 0))
    flag = data.get("flag", "")
    note = data.get("note", "")
    created_at = datetime.now().isoformat()
    expire_at = (datetime.now() + timedelta(days=expire_days)).isoformat() if expire_days > 0 else None

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO users (uuid, name, email, traffic_limit_gb, expire_days, created_at, expire_at,
               max_connections, flag, note) VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (user_uuid, name, email, traffic_gb, expire_days, created_at, expire_at, max_conn, flag, note),
        )
        await db.commit()

    await send_telegram(
        f"👤 <b>کاربر جدید</b>\n🏷 نام: <code>{name}</code>\n📦 ترافیک: {traffic_gb} GB\n⏰ انقضا: {expire_days} روز"
    )
    return {"ok": True, "uuid": user_uuid}


@app.get("/api/users/{user_uuid}")
async def get_user(user_uuid: str, auth=Depends(require_auth)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM users WHERE uuid=?", (user_uuid,)) as cur:
            row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "کاربر یافت نشد")
    return dict(row)


@app.put("/api/users/{user_uuid}")
async def update_user(user_uuid: str, request: Request, auth=Depends(require_auth)):
    data = await request.json()
    expire_days = int(data.get("expire_days", 0))
    expire_at = (datetime.now() + timedelta(days=expire_days)).isoformat() if expire_days > 0 else None
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """UPDATE users SET name=?, email=?, traffic_limit_gb=?, expire_days=?,
               expire_at=?, max_connections=?, flag=?, note=?, is_active=? WHERE uuid=?""",
            (
                data.get("name"),
                data.get("email", ""),
                float(data.get("traffic_limit_gb", 0)),
                expire_days,
                expire_at,
                int(data.get("max_connections", 0)),
                data.get("flag", ""),
                data.get("note", ""),
                int(data.get("is_active", 1)),
                user_uuid,
            ),
        )
        await db.commit()
    return {"ok": True}


@app.delete("/api/users/{user_uuid}")
async def delete_user(user_uuid: str, auth=Depends(require_auth)):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM users WHERE uuid=?", (user_uuid,))
        await db.commit()
    return {"ok": True}


@app.post("/api/users/{user_uuid}/reset-traffic")
async def reset_traffic(user_uuid: str, auth=Depends(require_auth)):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE users SET used_traffic_bytes=0 WHERE uuid=?", (user_uuid,))
        await db.commit()
    return {"ok": True}


@app.post("/api/users/{user_uuid}/toggle")
async def toggle_user(user_uuid: str, auth=Depends(require_auth)):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT is_active FROM users WHERE uuid=?", (user_uuid,)) as cur:
            row = await cur.fetchone()
        if not row:
            raise HTTPException(404)
        new_state = 0 if row[0] == 1 else 1
        await db.execute("UPDATE users SET is_active=? WHERE uuid=?", (new_state, user_uuid))
        await db.commit()
    return {"ok": True, "is_active": new_state}


@app.get("/api/users/{user_uuid}/sub-link")
async def get_sub_link(user_uuid: str, auth=Depends(require_auth)):
    from urllib.parse import quote
    scheme = "https" if DOMAIN != "localhost:8000" else "http"
    sub_url = f"{scheme}://{DOMAIN}/sub/{user_uuid}"

    # لینک VLESS مستقیم — بدون IP تمیز
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM users WHERE uuid=?", (user_uuid,)) as cur:
            user = await cur.fetchone()
    if not user:
        raise HTTPException(404, "کاربر یافت نشد")

    # Option C: include remaining traffic in label
    limit_bytes = float(user["traffic_limit_gb"] or 0) * 1024 ** 3
    used_bytes = int(user["used_traffic_bytes"] or 0)
    remaining_bytes = max(0, int(limit_bytes - used_bytes)) if limit_bytes > 0 else 0
    remaining_gb = round(remaining_bytes / 1024 ** 3, 2) if limit_bytes > 0 else 0
    remaining_txt = f"{remaining_gb}GB" if limit_bytes > 0 else "∞"

    vless_label = f"{user['flag']} {user['name']} | {remaining_txt} left".strip()
    vless = await build_vless_link(user["uuid"], vless_label, "")

    # لینک‌های IP تمیز (اگه وجود داشت)
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT ip, label FROM clean_ips WHERE is_active=1") as cur:
            ips = await cur.fetchall()

    ip_links = []
    for ip_row in ips:
        ip_lbl = (ip_row['label'] or ip_row['ip'])
        lnk = await build_vless_link(
            user["uuid"],
            f"{user['name']} | {remaining_txt} left | {ip_lbl}",
            user["flag"],
            address=ip_row["ip"],
        )
        ip_links.append({"ip": ip_row["ip"], "label": ip_row["label"], "link": lnk})

    return {
        "sub_link": sub_url,
        "vless_link": vless,
        "ip_links": ip_links,
    }

# ─────────────────────────────────────────────────────────────────────────────
# ROUTES – CLEAN IPs
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/api/ips")
async def list_ips(auth=Depends(require_auth)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM clean_ips ORDER BY added_at DESC") as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


@app.post("/api/ips")
async def add_ip(request: Request, auth=Depends(require_auth)):
    data = await request.json()
    ip = data.get("ip", "").strip()
    label = data.get("label", "").strip()
    if not ip:
        raise HTTPException(400, "IP الزامی است")
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR IGNORE INTO clean_ips (ip, label, added_at) VALUES (?,?,?)",
            (ip, label, datetime.now().isoformat()),
        )
        await db.commit()
    return {"ok": True}


@app.post("/api/ips/bulk")
async def bulk_add_ips(request: Request, auth=Depends(require_auth)):
    data = await request.json()
    ips_text = data.get("ips", "")
    added = 0
    async with aiosqlite.connect(DB_PATH) as db:
        for line in ips_text.splitlines():
            line = line.strip()
            parts = line.split()
            ip = parts[0] if parts else ""
            label = " ".join(parts[1:]) if len(parts) > 1 else ""
            ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|^[a-fA-F0-9:]+$")
            if ip and ip_pattern.match(ip):
                await db.execute(
                    "INSERT OR IGNORE INTO clean_ips (ip, label, added_at) VALUES (?,?,?)",
                    (ip, label, datetime.now().isoformat()),
                )
                added += 1
        await db.commit()
    return {"ok": True, "added": added}


@app.delete("/api/ips/{ip_id}")
async def delete_ip(ip_id: int, auth=Depends(require_auth)):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM clean_ips WHERE id=?", (ip_id,))
        await db.commit()
    return {"ok": True}


@app.post("/api/ips/{ip_id}/toggle")
async def toggle_ip(ip_id: int, auth=Depends(require_auth)):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT is_active FROM clean_ips WHERE id=?", (ip_id,)) as cur:
            row = await cur.fetchone()
        if not row:
            raise HTTPException(404)
        new_state = 0 if row[0] == 1 else 1
        await db.execute("UPDATE clean_ips SET is_active=? WHERE id=?", (new_state, ip_id))
        await db.commit()
    return {"ok": True, "is_active": new_state}

# ─────────────────────────────────────────────────────────────────────────────
# ROUTES – SETTINGS
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/api/settings")
async def get_settings(auth=Depends(require_auth)):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT key, value FROM settings") as cur:
            rows = await cur.fetchall()
    return {r[0]: r[1] for r in rows}


@app.post("/api/settings")
async def update_settings(request: Request, auth=Depends(require_auth)):
    data = await request.json()
    async with aiosqlite.connect(DB_PATH) as db:
        for k, v in data.items():
            await db.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)", (k, str(v))
            )
        await db.commit()
    return {"ok": True}

# ─────────────────────────────────────────────────────────────────────────────
# ROUTES – STATS
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/api/stats")
async def get_stats(auth=Depends(require_auth)):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT COUNT(*) FROM users") as cur:
            total_users = (await cur.fetchone())[0]
        async with db.execute("SELECT COUNT(*) FROM users WHERE is_active=1") as cur:
            active_users = (await cur.fetchone())[0]
        async with db.execute("SELECT COUNT(*) FROM users WHERE is_active=0") as cur:
            inactive_users = (await cur.fetchone())[0]
        async with db.execute(
            "SELECT COUNT(*) FROM users WHERE expire_at <= ? AND is_active=1",
            ((datetime.now() + timedelta(days=3)).isoformat(),),
        ) as cur:
            expiring_soon = (await cur.fetchone())[0]
        async with db.execute("SELECT SUM(used_traffic_bytes) FROM users") as cur:
            total_traffic = (await cur.fetchone())[0] or 0
        async with db.execute("SELECT COUNT(*) FROM clean_ips WHERE is_active=1") as cur:
            active_ips = (await cur.fetchone())[0]

    try:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        net = psutil.net_io_counters()
        sys_info = {
            "cpu": cpu,
            "mem_percent": mem.percent,
            "mem_used_gb": round(mem.used / 1024 ** 3, 2),
            "mem_total_gb": round(mem.total / 1024 ** 3, 2),
            "disk_percent": disk.percent,
            "disk_used_gb": round(disk.used / 1024 ** 3, 2),
            "disk_total_gb": round(disk.total / 1024 ** 3, 2),
            "net_sent_gb": round(net.bytes_sent / 1024 ** 3, 2),
            "net_recv_gb": round(net.bytes_recv / 1024 ** 3, 2),
        }
    except Exception:
        sys_info = {"cpu": 0, "mem_percent": 0, "disk_percent": 0}

    return {
        "total_users": total_users,
        "active_users": active_users,
        "inactive_users": inactive_users,
        "expiring_soon": expiring_soon,
        "total_traffic_gb": round(total_traffic / 1024 ** 3, 3),
        "active_ips": active_ips,
        "system": sys_info,
        "version": PANEL_VERSION,
    }


# ─────────────────────────────────────────────────────────────────────────────
# ROUTES – PANEL (SPA)
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/panel", response_class=HTMLResponse)
@app.get("/panel/{path:path}", response_class=HTMLResponse)
async def panel(request: Request):
    session = request.cookies.get("session")
    is_auth = bool(session and verify_token(session))
    return HTMLResponse(get_html(is_auth))



def get_html(is_auth: bool) -> str:
    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<title>IranX Panel</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root {{
  --bg:      #060b14;
  --surface: #0d1524;
  --surf2:   #111e33;
  --surf3:   #162540;
  --border:  rgba(99,179,237,0.12);
  --bord2:   rgba(99,179,237,0.22);
  --cyan:    #22d3ee;
  --blue:    #3b82f6;
  --violet:  #818cf8;
  --green:   #10b981;
  --red:     #f43f5e;
  --amber:   #f59e0b;
  --txt:     rgba(241,245,249,0.93);
  --txt2:    rgba(148,163,184,0.80);
  --txt3:    rgba(100,116,139,0.75);
  --glow:    0 0 40px rgba(34,211,238,0.18);
  --shadow:  0 12px 48px rgba(0,0,0,0.55);
  --r:       16px;
  --rsm:     10px;
}}
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
html{{height:100%}}
body{{
  font-family:'Vazirmatn',system-ui,sans-serif;
  background:
    radial-gradient(ellipse 900px 600px at 0% 0%,rgba(34,211,238,0.13) 0%,transparent 60%),
    radial-gradient(ellipse 700px 500px at 100% 30%,rgba(59,130,246,0.11) 0%,transparent 60%),
    radial-gradient(ellipse 600px 600px at 60% 100%,rgba(129,140,248,0.09) 0%,transparent 60%),
    var(--bg);
  color:var(--txt);
  min-height:100vh;
  direction:rtl;
  overflow-x:hidden;
}}
::-webkit-scrollbar{{width:5px;height:5px}}
::-webkit-scrollbar-track{{background:var(--surface)}}
::-webkit-scrollbar-thumb{{background:var(--surf3);border-radius:10px}}
::-webkit-scrollbar-thumb:hover{{background:var(--cyan)}}

/* ── LAYOUT ─────────────────────────────────────────────── */
.layout{{display:flex;min-height:100vh}}

/* ── SIDEBAR ────────────────────────────────────────────── */
.sidebar{{
  width:248px;flex-shrink:0;
  background:linear-gradient(180deg,var(--surface) 0%,rgba(13,21,36,0.97) 100%);
  border-left:1px solid var(--border);
  display:flex;flex-direction:column;
  position:fixed;top:0;right:0;height:100vh;
  z-index:200;transition:transform .3s cubic-bezier(.4,0,.2,1);
  backdrop-filter:blur(20px);
}}
.sidebar-head{{
  padding:22px 18px 18px;
  border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:12px;
}}
.logo-box{{
  width:42px;height:42px;border-radius:12px;flex-shrink:0;
  background:linear-gradient(135deg,var(--cyan),var(--blue));
  display:flex;align-items:center;justify-content:center;
  font-size:18px;box-shadow:var(--glow);
}}
.logo-text h2{{font-size:16px;font-weight:800;letter-spacing:-.3px}}
.logo-text span{{font-size:11px;color:var(--txt3);font-weight:400}}

.nav{{flex:1;padding:14px 10px;overflow-y:auto;display:flex;flex-direction:column;gap:2px}}
.nav-lbl{{
  font-size:10px;color:var(--txt3);font-weight:700;
  letter-spacing:.08em;text-transform:uppercase;
  padding:14px 10px 6px;
}}
.nav-item{{
  display:flex;align-items:center;gap:10px;
  padding:10px 14px;border-radius:var(--rsm);
  font-size:13.5px;font-weight:500;color:var(--txt2);
  cursor:pointer;transition:all .18s;
  border:1px solid transparent;
}}
.nav-item:hover{{background:var(--surf2);color:var(--txt);}}
.nav-item.active{{
  background:rgba(34,211,238,0.11);
  color:var(--cyan);
  border-color:rgba(34,211,238,0.20);
  font-weight:600;
}}
.nav-icon{{width:18px;text-align:center;font-size:14px;flex-shrink:0}}

.sidebar-foot{{
  padding:12px 10px;border-top:1px solid var(--border);
}}
.user-row{{
  display:flex;align-items:center;gap:10px;
  padding:10px 12px;border-radius:var(--rsm);
  background:var(--surf2);
}}
.user-ava{{
  width:34px;height:34px;border-radius:50%;flex-shrink:0;
  background:linear-gradient(135deg,var(--cyan),var(--violet));
  display:flex;align-items:center;justify-content:center;
  font-size:13px;font-weight:800;
}}
.user-name{{font-size:13px;font-weight:700}}
.user-role{{font-size:11px;color:var(--txt3)}}
.logout-btn{{
  margin-right:auto;background:none;border:none;
  color:var(--txt3);cursor:pointer;font-size:14px;
  padding:4px;border-radius:6px;transition:color .18s;
}}
.logout-btn:hover{{color:var(--red)}}

/* ── MAIN ───────────────────────────────────────────────── */
.main{{flex:1;margin-right:248px;display:flex;flex-direction:column;min-height:100vh}}

/* ── TOPBAR ─────────────────────────────────────────────── */
.topbar{{
  background:rgba(13,21,36,0.85);backdrop-filter:blur(20px);
  border-bottom:1px solid var(--border);
  padding:0 28px;height:60px;
  display:flex;align-items:center;justify-content:space-between;
  position:sticky;top:0;z-index:100;
}}
.topbar-left{{display:flex;align-items:center;gap:12px}}
.burger{{
  display:none;background:none;border:none;
  color:var(--txt2);font-size:18px;cursor:pointer;padding:4px;
}}
.page-title{{font-size:17px;font-weight:700;letter-spacing:-.3px}}
.page-sub{{font-size:12px;color:var(--txt3);margin-top:1px}}
.topbar-right{{display:flex;gap:8px;align-items:center}}

/* ── CONTENT ────────────────────────────────────────────── */
.content{{padding:24px 28px;flex:1}}

/* ── CARDS ──────────────────────────────────────────────── */
.card{{
  background:rgba(255,255,255,0.028);
  border:1px solid var(--border);
  border-radius:var(--r);
  padding:22px;
  position:relative;overflow:hidden;
}}
.card::before{{
  content:'';position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,rgba(34,211,238,0.3),transparent);
}}
.card-title{{
  font-size:14px;font-weight:700;color:var(--txt);
  margin-bottom:18px;display:flex;align-items:center;gap:8px;
}}
.card-title .ct-icon{{
  width:28px;height:28px;border-radius:8px;
  display:flex;align-items:center;justify-content:center;
  font-size:13px;background:rgba(34,211,238,0.14);color:var(--cyan);
}}

/* ── STAT GRID ──────────────────────────────────────────── */
.stats-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:14px;margin-bottom:20px}}
.stat{{
  background:rgba(255,255,255,0.030);border:1px solid var(--border);
  border-radius:var(--r);padding:18px;
  position:relative;overflow:hidden;
  transition:transform .2s,box-shadow .2s;cursor:default;
}}
.stat:hover{{transform:translateY(-2px);box-shadow:var(--shadow)}}
.stat-stripe{{
  position:absolute;top:0;left:0;right:0;height:2px;
  border-radius:var(--r) var(--r) 0 0;
}}
.stat-ico{{
  width:44px;height:44px;border-radius:12px;
  display:flex;align-items:center;justify-content:center;
  font-size:20px;margin-bottom:14px;
}}
.stat-val{{font-size:30px;font-weight:800;line-height:1;letter-spacing:-.5px}}
.stat-lbl{{font-size:12px;color:var(--txt2);margin-top:5px;font-weight:500}}
.stat-hint{{font-size:11px;color:var(--txt3);margin-top:3px}}

/* cyan */
.s-cyan .stat-stripe{{background:linear-gradient(90deg,var(--cyan),var(--blue))}}
.s-cyan .stat-ico{{background:rgba(34,211,238,0.13);color:var(--cyan)}}
.s-cyan .stat-val{{color:var(--cyan)}}
/* green */
.s-green .stat-stripe{{background:linear-gradient(90deg,var(--green),#34d399)}}
.s-green .stat-ico{{background:rgba(16,185,129,0.13);color:var(--green)}}
.s-green .stat-val{{color:var(--green)}}
/* red */
.s-red .stat-stripe{{background:linear-gradient(90deg,var(--red),#fb7185)}}
.s-red .stat-ico{{background:rgba(244,63,94,0.13);color:var(--red)}}
.s-red .stat-val{{color:var(--red)}}
/* amber */
.s-amber .stat-stripe{{background:linear-gradient(90deg,var(--amber),#fbbf24)}}
.s-amber .stat-ico{{background:rgba(245,158,11,0.13);color:var(--amber)}}
.s-amber .stat-val{{color:var(--amber)}}
/* blue */
.s-blue .stat-stripe{{background:linear-gradient(90deg,var(--blue),var(--violet))}}
.s-blue .stat-ico{{background:rgba(59,130,246,0.13);color:var(--blue)}}
.s-blue .stat-val{{color:var(--blue)}}

/* ── GAUGE ──────────────────────────────────────────────── */
.gauges{{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}}
.gauge-wrap{{text-align:center}}
.gauge-svg{{transform:rotate(-90deg)}}
.gauge-bg{{fill:none;stroke:var(--surf3);stroke-width:8}}
.gauge-fg{{fill:none;stroke-width:8;stroke-linecap:round;transition:stroke-dashoffset .8s}}
.gauge-val{{font-size:15px;font-weight:800;dominant-baseline:middle;text-anchor:middle;transform:rotate(90deg)}}
.gauge-lbl{{font-size:11px;color:var(--txt2);margin-top:6px;font-weight:500}}

/* ── TABLE ──────────────────────────────────────────────── */
.tbl-wrap{{overflow-x:auto;border-radius:var(--rsm)}}
table{{width:100%;border-collapse:collapse;direction:rtl;white-space:nowrap}}
thead th{{
  background:var(--surf2);color:var(--txt3);font-size:11px;
  font-weight:700;padding:11px 14px;text-align:right;
  border-bottom:1px solid var(--border);letter-spacing:.04em;text-transform:uppercase;
}}
tbody td{{
  padding:13px 14px;font-size:13px;color:var(--txt);
  border-bottom:1px solid rgba(99,179,237,0.06);vertical-align:middle;
}}
tbody tr:last-child td{{border-bottom:none}}
tbody tr:hover td{{background:rgba(255,255,255,0.018)}}

/* ── BADGE ──────────────────────────────────────────────── */
.badge{{
  display:inline-flex;align-items:center;gap:4px;
  padding:3px 9px;border-radius:100px;
  font-size:11px;font-weight:700;white-space:nowrap;
}}
.bg{{background:rgba(16,185,129,0.14);color:var(--green)}}
.br{{background:rgba(244,63,94,0.14);color:var(--red)}}
.by{{background:rgba(245,158,11,0.14);color:var(--amber)}}
.bb{{background:rgba(59,130,246,0.14);color:var(--blue)}}
.bv{{background:rgba(129,140,248,0.14);color:var(--violet)}}

/* ── PROGRESS ───────────────────────────────────────────── */
.prog{{height:5px;background:var(--surf3);border-radius:100px;overflow:hidden;margin-top:5px;min-width:80px}}
.prog-bar{{height:100%;border-radius:100px;transition:width .6s}}
.prog-g{{background:linear-gradient(90deg,var(--green),#34d399)}}
.prog-y{{background:linear-gradient(90deg,var(--amber),#fbbf24)}}
.prog-r{{background:linear-gradient(90deg,var(--red),#fb7185)}}

/* ── BUTTONS ────────────────────────────────────────────── */
.btn{{
  display:inline-flex;align-items:center;gap:7px;
  padding:9px 18px;border-radius:var(--rsm);
  font-size:13px;font-weight:600;cursor:pointer;border:none;
  font-family:inherit;transition:all .18s;text-decoration:none;
  white-space:nowrap;
}}
.btn-primary{{
  background:linear-gradient(135deg,var(--cyan),var(--blue));
  color:rgba(6,11,20,0.95);
  box-shadow:0 6px 20px rgba(34,211,238,0.22);
}}
.btn-primary:hover{{transform:translateY(-1px);box-shadow:0 10px 28px rgba(34,211,238,0.28)}}
.btn-sm{{padding:6px 12px;font-size:12px;border-radius:8px}}
.btn-success{{background:rgba(16,185,129,0.14);color:var(--green);border:1px solid rgba(16,185,129,0.28)}}
.btn-success:hover{{background:rgba(16,185,129,0.24)}}
.btn-danger{{background:rgba(244,63,94,0.12);color:var(--red);border:1px solid rgba(244,63,94,0.25)}}
.btn-danger:hover{{background:rgba(244,63,94,0.22)}}
.btn-ghost{{background:var(--surf2);color:var(--txt2);border:1px solid var(--border)}}
.btn-ghost:hover{{background:var(--surf3);color:var(--txt)}}
.btn-amber{{background:rgba(245,158,11,0.13);color:var(--amber);border:1px solid rgba(245,158,11,0.25)}}
.btn-amber:hover{{background:rgba(245,158,11,0.22)}}
.btn-full{{width:100%;justify-content:center;padding:13px;font-size:14px}}
.btn:disabled{{opacity:.45;cursor:not-allowed;transform:none!important;box-shadow:none!important}}

/* ── FORM ───────────────────────────────────────────────── */
.form-row{{display:grid;grid-template-columns:1fr 1fr;gap:14px}}
.fg{{margin-bottom:16px}}
.fg label{{display:block;font-size:12px;color:var(--txt2);margin-bottom:7px;font-weight:600;letter-spacing:.02em}}
.fg input,.fg select,.fg textarea{{
  width:100%;background:var(--surf2);border:1px solid var(--border);
  border-radius:var(--rsm);color:var(--txt);
  padding:10px 14px;font-size:13px;font-family:inherit;
  outline:none;transition:border-color .18s,box-shadow .18s;
  direction:ltr;text-align:right;
}}
.fg input:focus,.fg select:focus,.fg textarea:focus{{
  border-color:var(--cyan);box-shadow:0 0 0 3px rgba(34,211,238,0.14);
}}
.fg textarea{{resize:vertical;min-height:80px}}
.fg select option{{background:var(--surf2)}}

/* ── MODAL ──────────────────────────────────────────────── */
.overlay{{
  position:fixed;inset:0;
  background:rgba(6,11,20,0.75);backdrop-filter:blur(6px);
  z-index:1000;display:flex;align-items:center;justify-content:center;
  padding:16px;animation:fadeIn .18s;
}}
.modal{{
  background:var(--surface);border:1px solid var(--bord2);
  border-radius:20px;width:100%;max-width:560px;max-height:92vh;
  overflow-y:auto;box-shadow:var(--shadow);
  animation:slideUp .25s cubic-bezier(.4,0,.2,1);
}}
.modal-lg{{max-width:680px}}
.m-head{{
  padding:22px 24px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;
}}
.m-title{{font-size:17px;font-weight:800}}
.m-close{{
  width:30px;height:30px;background:var(--surf2);border:none;
  border-radius:8px;color:var(--txt2);cursor:pointer;font-size:15px;
  display:flex;align-items:center;justify-content:center;transition:all .18s;
}}
.m-close:hover{{background:var(--red);color:#fff}}
.m-body{{padding:22px 24px}}
.m-foot{{padding:14px 24px 22px;display:flex;gap:10px;justify-content:flex-end}}

/* ── TOAST ──────────────────────────────────────────────── */
.toast-wrap{{
  position:fixed;bottom:20px;left:20px;z-index:9999;
  display:flex;flex-direction:column;gap:8px;pointer-events:none;
}}
.toast{{
  background:var(--surf2);border:1px solid var(--border);
  border-radius:12px;padding:12px 16px;
  display:flex;align-items:center;gap:10px;
  min-width:260px;max-width:360px;
  box-shadow:var(--shadow);
  animation:slideInLeft .25s;font-size:13px;pointer-events:all;
}}
.toast.ok{{border-color:rgba(16,185,129,0.35)}}
.toast.err{{border-color:rgba(244,63,94,0.35)}}
.t-ico.ok{{color:var(--green)}}
.t-ico.err{{color:var(--red)}}

/* ── COPY BOX ───────────────────────────────────────────── */
.copy-box{{
  background:var(--bg);border:1px solid var(--border);
  border-radius:var(--rsm);padding:11px 14px;
  font-family:monospace;font-size:12.5px;color:var(--cyan);
  word-break:break-all;direction:ltr;text-align:left;
  display:flex;align-items:flex-start;gap:8px;margin-bottom:10px;
}}
.copy-box .cb-txt{{flex:1;line-height:1.5}}
.copy-btn{{
  background:none;border:none;color:var(--txt3);
  cursor:pointer;padding:2px 4px;border-radius:4px;
  font-size:13px;transition:color .18s;flex-shrink:0;
}}
.copy-btn:hover{{color:var(--cyan)}}

/* ── SECTION PAGES ──────────────────────────────────────── */
.page{{display:none}}.page.active{{display:block;animation:fadeIn .2s}}

/* ── TOGGLE ─────────────────────────────────────────────── */
.tog{{position:relative;width:42px;height:22px;display:inline-block;flex-shrink:0}}
.tog input{{opacity:0;width:0;height:0}}
.tog-sl{{
  position:absolute;inset:0;background:var(--surf3);
  border-radius:100px;cursor:pointer;transition:.25s;
  border:1px solid var(--border);
}}
.tog-sl::before{{
  content:'';position:absolute;
  width:16px;height:16px;border-radius:50%;
  background:var(--txt3);top:2px;right:2px;transition:.25s;
}}
.tog input:checked+.tog-sl{{background:rgba(34,211,238,0.25);border-color:var(--cyan)}}
.tog input:checked+.tog-sl::before{{background:var(--cyan);transform:translateX(-20px)}}

/* ── IP CHIP ────────────────────────────────────────────── */
.ip-chip{{
  background:var(--surf2);border:1px solid var(--border);
  border-radius:6px;padding:3px 9px;
  font-family:monospace;font-size:12px;color:var(--cyan);display:inline-block;
}}

/* ── SEARCH ─────────────────────────────────────────────── */
.search{{position:relative;flex:1;max-width:300px}}
.search input{{
  width:100%;background:var(--surf2);border:1px solid var(--border);
  border-radius:var(--rsm);color:var(--txt);
  padding:9px 14px 9px 36px;font-size:13px;
  font-family:inherit;outline:none;direction:rtl;transition:border-color .18s;
}}
.search input:focus{{border-color:var(--cyan)}}
.search-ico{{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--txt3);font-size:13px}}

/* ── EMPTY STATE ────────────────────────────────────────── */
.empty{{text-align:center;padding:56px 20px;color:var(--txt3)}}
.empty-ico{{font-size:44px;margin-bottom:14px;opacity:.45}}
.empty h3{{font-size:17px;color:var(--txt2);margin-bottom:6px}}
.empty p{{font-size:13px}}

/* ── LOGIN ──────────────────────────────────────────────── */
.login-scene{{
  min-height:100vh;display:flex;align-items:center;
  justify-content:center;padding:20px;
}}
.login-box{{
  background:rgba(13,21,36,0.90);border:1px solid var(--bord2);
  border-radius:24px;padding:44px 40px;width:100%;max-width:420px;
  box-shadow:var(--shadow);backdrop-filter:blur(12px);
  animation:fadeIn .35s;
}}
.login-logo{{text-align:center;margin-bottom:32px}}
.login-ico{{
  width:68px;height:68px;border-radius:18px;margin:0 auto 16px;
  background:linear-gradient(135deg,var(--cyan),var(--blue));
  display:flex;align-items:center;justify-content:center;
  font-size:30px;box-shadow:0 12px 36px rgba(34,211,238,0.25);
}}
.login-logo h1{{font-size:22px;font-weight:800;letter-spacing:-.5px}}
.login-logo p{{color:var(--txt3);font-size:13px;margin-top:4px}}

/* ── INFO CARDS (sub link modal) ──────────────────────── */
.info-band{{
  display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:16px;
}}
.info-cell{{
  background:var(--surf2);border:1px solid var(--border);
  border-radius:10px;padding:12px;text-align:center;
}}
.info-cell .iv{{font-size:18px;font-weight:800;color:var(--cyan)}}
.info-cell .il{{font-size:11px;color:var(--txt3);margin-top:3px}}

/* ── ANIMATIONS ─────────────────────────────────────────── */
@keyframes fadeIn{{from{{opacity:0}}to{{opacity:1}}}}
@keyframes slideUp{{from{{opacity:0;transform:translateY(18px)}}to{{opacity:1;transform:translateY(0)}}}}
@keyframes slideInLeft{{from{{opacity:0;transform:translateX(-16px)}}to{{opacity:1;transform:translateX(0)}}}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
.spin{{animation:spin 1s linear infinite}}

/* ── MOBILE ─────────────────────────────────────────────── */
@media(max-width:768px){{
  .sidebar{{transform:translateX(110%);box-shadow:var(--shadow)}}
  .sidebar.open{{transform:translateX(0)}}
  .overlay-backdrop{{display:block}}
  .main{{margin-right:0}}
  .burger{{display:flex}}
  .content{{padding:14px 14px 24px}}
  .topbar{{padding:0 14px}}
  .stats-grid{{grid-template-columns:1fr 1fr}}
  .form-row{{grid-template-columns:1fr}}
  .gauges{{grid-template-columns:1fr 1fr}}
  .m-body{{padding:16px}}
  .m-foot{{padding:12px 16px 20px}}
  .info-band{{grid-template-columns:1fr 1fr}}
}}
@media(max-width:420px){{
  .stats-grid{{grid-template-columns:1fr}}
  .login-box{{padding:32px 22px}}
  .info-band{{grid-template-columns:1fr}}
}}

/* ── MOBILE BACKDROP ────────────────────────────────────── */
.overlay-backdrop{{
  display:none;position:fixed;inset:0;
  background:rgba(6,11,20,0.65);z-index:199;
}}
.overlay-backdrop.show{{display:block}}
</style>
</head>
<body>

{'<div id="login-root"></div>' if not is_auth else '<div id="app-root"></div>'}
<div class="toast-wrap" id="toasts"></div>

<script>
const IS_AUTH = {'true' if is_auth else 'false'};
const VER = '{PANEL_VERSION}';

// ══════════════════════════════════════════════════════
//  UTILS
// ══════════════════════════════════════════════════════
function toast(msg, type='ok'){{
  const w = document.getElementById('toasts');
  const d = document.createElement('div');
  d.className = `toast ${{type}}`;
  d.innerHTML = `<i class="fa ${{type==='ok'?'fa-check-circle':'fa-times-circle'}} t-ico ${{type}}"></i><span>${{msg}}</span>`;
  w.append(d);
  setTimeout(()=>d.remove(),3800);
}}

async function api(method,path,body=null){{
  const o={{method,headers:{{'Content-Type':'application/json'}}}};
  if(body) o.body=JSON.stringify(body);
  const r=await fetch(path,o);
  if(!r.ok){{
    const e=await r.json().catch(()=>({{detail:'خطا'}}));
    throw new Error(e.detail||'خطا');
  }}
  return r.json();
}}

function copy(txt){{
  navigator.clipboard.writeText(txt)
    .then(()=>toast('کپی شد ✓'))
    .catch(()=>{{
      const ta=document.createElement('textarea');
      ta.value=txt;document.body.append(ta);ta.select();
      document.execCommand('copy');ta.remove();toast('کپی شد ✓');
    }});
}}

function fmtBytes(b){{
  if(!b||b===0)return'0 B';
  const u=['B','KB','MB','GB','TB'];let i=0;
  while(b>=1024&&i<u.length-1){{b/=1024;i++;}}
  return b.toFixed(2)+' '+u[i];
}}

function fmtDate(s){{
  if(!s)return'—';
  return new Date(s).toLocaleDateString('fa-IR',{{year:'numeric',month:'short',day:'numeric'}});
}}

function daysLeft(exp){{
  if(!exp)return null;
  return Math.ceil((new Date(exp)-new Date())/86400000);
}}

function confirm2(msg){{return window.confirm(msg)}}

// ══════════════════════════════════════════════════════
//  LOGIN
// ══════════════════════════════════════════════════════
function renderLogin(){{
  document.getElementById('login-root').innerHTML=`
  <div class="login-scene">
    <div class="login-box">
      <div class="login-logo">
        <div class="login-ico">⚡</div>
        <h1>IranX Panel</h1>
        <p>پنل مدیریت VLESS</p>
      </div>
      <form id="lf">
        <div class="fg">
          <label>نام کاربری</label>
          <input name="username" type="text" placeholder="admin" required autocomplete="username">
        </div>
        <div class="fg">
          <label>رمز عبور</label>
          <input name="password" type="password" placeholder="••••••••" required autocomplete="current-password">
        </div>
        <button class="btn btn-primary btn-full" id="lbtn" type="submit">
          <i class="fa fa-sign-in-alt"></i> ورود
        </button>
        <p style="text-align:center;color:var(--txt3);font-size:12px;margin-top:16px" id="lerr"></p>
      </form>
    </div>
  </div>`;
  document.getElementById('lf').onsubmit=async e=>{{
    e.preventDefault();
    const btn=document.getElementById('lbtn');
    const err=document.getElementById('lerr');
    btn.disabled=true;
    btn.innerHTML='<i class="fa fa-spinner spin"></i> در حال ورود...';
    const fd=new FormData(e.target);
    try{{
      const r=await fetch('/api/login',{{method:'POST',body:fd}});
      if(r.ok){{window.location.reload()}}
      else{{
        const j=await r.json().catch(()=>({{detail:'خطا'}}));
        err.textContent=j.detail||'خطا در ورود';
        btn.disabled=false;
        btn.innerHTML='<i class="fa fa-sign-in-alt"></i> ورود';
      }}
    }}catch{{
      err.textContent='خطا در اتصال';
      btn.disabled=false;
      btn.innerHTML='<i class="fa fa-sign-in-alt"></i> ورود';
    }}
  }};
}}

// ══════════════════════════════════════════════════════
//  APP SHELL
// ══════════════════════════════════════════════════════
let curPage='dashboard';
let usersData=[];
let ipsData=[];
let statsData={{}};
let charts={{}};

function renderApp(){{
  document.getElementById('app-root').innerHTML=`
  <div class="overlay-backdrop" id="bk" onclick="closeSidebar()"></div>
  <div class="layout">
    <aside class="sidebar" id="sidebar">
      <div class="sidebar-head">
        <div class="logo-box">⚡</div>
        <div class="logo-text">
          <h2>IranX Panel</h2>
          <span>v${{VER}}</span>
        </div>
      </div>
      <nav class="nav">
        <div class="nav-lbl">منو اصلی</div>
        <div class="nav-item active" data-p="dashboard" onclick="nav('dashboard')">
          <span class="nav-icon"><i class="fa fa-gauge-high"></i></span>داشبورد
        </div>
        <div class="nav-item" data-p="users" onclick="nav('users')">
          <span class="nav-icon"><i class="fa fa-users"></i></span>کاربران
          <span id="badge-users" style="margin-right:auto;background:rgba(34,211,238,0.15);color:var(--cyan);font-size:11px;font-weight:700;padding:2px 8px;border-radius:100px"></span>
        </div>
        <div class="nav-item" data-p="ips" onclick="nav('ips')">
          <span class="nav-icon"><i class="fa fa-network-wired"></i></span>IP تمیز
          <span id="badge-ips" style="margin-right:auto;background:rgba(16,185,129,0.15);color:var(--green);font-size:11px;font-weight:700;padding:2px 8px;border-radius:100px"></span>
        </div>
        <div class="nav-lbl" style="margin-top:4px">سیستم</div>
        <div class="nav-item" data-p="settings" onclick="nav('settings')">
          <span class="nav-icon"><i class="fa fa-sliders"></i></span>تنظیمات
        </div>
      </nav>
      <div class="sidebar-foot">
        <div class="user-row">
          <div class="user-ava">A</div>
          <div>
            <div class="user-name">Admin</div>
            <div class="user-role">مدیر سیستم</div>
          </div>
          <button class="logout-btn" onclick="logout()" title="خروج">
            <i class="fa fa-power-off"></i>
          </button>
        </div>
      </div>
    </aside>

    <div class="main">
      <header class="topbar">
        <div class="topbar-left">
          <button class="burger" onclick="openSidebar()"><i class="fa fa-bars"></i></button>
          <div>
            <div class="page-title" id="pg-title">داشبورد</div>
            <div class="page-sub" id="pg-sub">خلاصه وضعیت سیستم</div>
          </div>
        </div>
        <div class="topbar-right" id="topbar-actions"></div>
      </header>

      <div class="content">
        <div class="page active" id="p-dashboard"></div>
        <div class="page" id="p-users"></div>
        <div class="page" id="p-ips"></div>
        <div class="page" id="p-settings"></div>
      </div>
    </div>
  </div>`;

  loadStats().then(()=>renderDashboard());
  loadUsers().then(()=>{{ if(curPage==='users') renderUsers(); }});
  loadIps().then(()=>{{ if(curPage==='ips') renderIps(); }});
  setInterval(()=>loadStats().then(()=>{{ if(curPage==='dashboard') renderDashboard(); }}),15000);
}}

function openSidebar(){{
  document.getElementById('sidebar').classList.add('open');
  document.getElementById('bk').classList.add('show');
}}
function closeSidebar(){{
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('bk').classList.remove('show');
}}

const PAGES = {{
  dashboard:{{title:'داشبورد',sub:'خلاصه وضعیت سیستم',icon:'fa-gauge-high'}},
  users:{{title:'مدیریت کاربران',sub:'ساخت و ویرایش اشتراک‌ها',icon:'fa-users'}},
  ips:{{title:'IP های تمیز',sub:'مدیریت آدرس‌های Cloudflare',icon:'fa-network-wired'}},
  settings:{{title:'تنظیمات',sub:'پیکربندی پنل و VLESS',icon:'fa-sliders'}},
}};

function nav(page){{
  curPage=page;
  document.querySelectorAll('.nav-item').forEach(el=>{{
    el.classList.toggle('active', el.dataset.p===page);
  }});
  document.querySelectorAll('.page').forEach(el=>el.classList.remove('active'));
  document.getElementById('p-'+page).classList.add('active');
  const pg=PAGES[page];
  document.getElementById('pg-title').textContent=pg.title;
  document.getElementById('pg-sub').textContent=pg.sub;
  closeSidebar();
  if(page==='dashboard') renderDashboard();
  else if(page==='users') renderUsers();
  else if(page==='ips') renderIps();
  else if(page==='settings') renderSettings();
}}

// ══════════════════════════════════════════════════════
//  DATA LOADERS
// ══════════════════════════════════════════════════════
async function loadStats(){{
  try{{statsData=await api('GET','/api/stats');}}catch{{}}
}}
async function loadUsers(){{
  try{{
    usersData=await api('GET','/api/users');
    const b=document.getElementById('badge-users');
    if(b) b.textContent=usersData.filter(u=>u.is_active).length;
  }}catch{{}}
}}
async function loadIps(){{
  try{{
    ipsData=await api('GET','/api/ips');
    const b=document.getElementById('badge-ips');
    if(b) b.textContent=ipsData.filter(i=>i.is_active).length;
  }}catch{{}}
}}

// ══════════════════════════════════════════════════════
//  DASHBOARD
// ══════════════════════════════════════════════════════
function renderDashboard(){{
  const s=statsData;
  if(!s||!s.system) return;
  const sys=s.system;

  const statCards=[
    {{cls:'s-cyan',ico:'fa-users',val:s.total_users||0,lbl:'کل کاربران',hint:`${{s.active_users||0}} فعال`}},
    {{cls:'s-green',ico:'fa-circle-check',val:s.active_users||0,lbl:'کاربران فعال',hint:`${{s.inactive_users||0}} غیرفعال`}},
    {{cls:'s-red',ico:'fa-triangle-exclamation',val:s.expiring_soon||0,lbl:'منقضی می‌شوند',hint:'در ۳ روز آینده'}},
    {{cls:'s-amber',ico:'fa-hard-drive',val:(s.total_traffic_gb||0).toFixed(1)+' GB',lbl:'ترافیک مصرفی',hint:'کل کاربران'}},
    {{cls:'s-blue',ico:'fa-network-wired',val:s.active_ips||0,lbl:'IP تمیز',hint:'فعال'}},
  ];

  const cards=statCards.map(c=>`
  <div class="stat ${{c.cls}}">
    <div class="stat-stripe"></div>
    <div class="stat-ico"><i class="fa ${{c.ico}}"></i></div>
    <div class="stat-val">${{c.val}}</div>
    <div class="stat-lbl">${{c.lbl}}</div>
    <div class="stat-hint">${{c.hint}}</div>
  </div>`).join('');

  const cpu=sys.cpu||0, mem=sys.mem_percent||0, disk=sys.disk_percent||0;

  function gauge(pct,color,label){{
    const r=34,circ=2*Math.PI*r;
    const off=circ*(1-pct/100);
    return `
    <div class="gauge-wrap">
      <svg width="84" height="84" class="gauge-svg" viewBox="0 0 84 84">
        <circle class="gauge-bg" cx="42" cy="42" r="${{r}}"/>
        <circle class="gauge-fg" cx="42" cy="42" r="${{r}}"
          stroke="${{color}}" stroke-dasharray="${{circ}}" stroke-dashoffset="${{off}}"/>
        <text x="42" y="42" class="gauge-val" fill="${{color}}">${{Math.round(pct)}}%</text>
      </svg>
      <div class="gauge-lbl">${{label}}</div>
    </div>`;
  }}

  document.getElementById('p-dashboard').innerHTML=`
  <div class="stats-grid">${{cards}}</div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px">
    <div class="card">
      <div class="card-title">
        <span class="ct-icon"><i class="fa fa-microchip"></i></span>
        وضعیت سیستم
      </div>
      <div class="gauges">
        ${{gauge(cpu,'var(--cyan)','CPU')}}
        ${{gauge(mem,'var(--blue)','RAM')}}
        ${{gauge(disk,'var(--violet)','Disk')}}
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:16px">
        <div style="background:var(--surf2);border-radius:8px;padding:10px 12px">
          <div style="font-size:11px;color:var(--txt3);margin-bottom:3px">RAM</div>
          <div style="font-size:13px;font-weight:700">${{sys.mem_used_gb||0}} / ${{sys.mem_total_gb||0}} GB</div>
        </div>
        <div style="background:var(--surf2);border-radius:8px;padding:10px 12px">
          <div style="font-size:11px;color:var(--txt3);margin-bottom:3px">Disk</div>
          <div style="font-size:13px;font-weight:700">${{sys.disk_used_gb||0}} / ${{sys.disk_total_gb||0}} GB</div>
        </div>
        <div style="background:var(--surf2);border-radius:8px;padding:10px 12px">
          <div style="font-size:11px;color:var(--txt3);margin-bottom:3px">Upload</div>
          <div style="font-size:13px;font-weight:700">${{sys.net_sent_gb||0}} GB</div>
        </div>
        <div style="background:var(--surf2);border-radius:8px;padding:10px 12px">
          <div style="font-size:11px;color:var(--txt3);margin-bottom:3px">Download</div>
          <div style="font-size:13px;font-weight:700">${{sys.net_recv_gb||0}} GB</div>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">
        <span class="ct-icon"><i class="fa fa-users"></i></span>
        آمار کاربران
      </div>
      <div style="display:flex;flex-direction:column;gap:10px">
        <div style="display:flex;align-items:center;justify-content:space-between">
          <span style="font-size:13px;color:var(--txt2)">فعال</span>
          <span class="badge bg">${{s.active_users||0}}</span>
        </div>
        <div style="display:flex;align-items:center;justify-content:space-between">
          <span style="font-size:13px;color:var(--txt2)">غیرفعال</span>
          <span class="badge br">${{s.inactive_users||0}}</span>
        </div>
        <div style="display:flex;align-items:center;justify-content:space-between">
          <span style="font-size:13px;color:var(--txt2)">منقضی شدنی (۳ روز)</span>
          <span class="badge by">${{s.expiring_soon||0}}</span>
        </div>
        <div style="display:flex;align-items:center;justify-content:space-between">
          <span style="font-size:13px;color:var(--txt2)">IP تمیز فعال</span>
          <span class="badge bb">${{s.active_ips||0}}</span>
        </div>
        <div style="display:flex;align-items:center;justify-content:space-between">
          <span style="font-size:13px;color:var(--txt2)">کل ترافیک</span>
          <span style="font-size:13px;font-weight:700;color:var(--cyan)">${{(s.total_traffic_gb||0).toFixed(2)}} GB</span>
        </div>
      </div>
    </div>
  </div>
  <div class="card">
    <div class="card-title">
      <span class="ct-icon"><i class="fa fa-users"></i></span>
      آخرین کاربران فعال
    </div>
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr>
            <th>نام</th><th>ترافیک</th><th>انقضا</th><th>وضعیت</th>
          </tr>
        </thead>
        <tbody>
          ${{(usersData||[]).slice(0,5).map(u=>{{
            const pct = u.traffic_limit_gb>0 ? Math.min(100,Math.round((u.used_traffic_bytes||0)/(u.traffic_limit_gb*1024**3)*100)) : 0;
            const cls = pct>85?'prog-r':pct>60?'prog-y':'prog-g';
            const dl = daysLeft(u.expire_at);
            const exp = dl===null?'<span class="badge bb">∞</span>':dl<3?`<span class="badge br">${{dl}} روز</span>`:dl<10?`<span class="badge by">${{dl}} روز</span>`:`<span class="badge bg">${{dl}} روز</span>`;
            return `<tr>
              <td><span style="font-weight:600">${{u.flag||''}} ${{u.name}}</span></td>
              <td>
                <div style="font-size:12px;color:var(--txt2)">${{fmtBytes(u.used_traffic_bytes||0)}} / ${{u.traffic_limit_gb||'∞'}} GB</div>
                <div class="prog"><div class="prog-bar ${{cls}}" style="width:${{pct}}%"></div></div>
              </td>
              <td>${{exp}}</td>
              <td>${{u.is_active?'<span class="badge bg">● فعال</span>':'<span class="badge br">● غیرفعال</span>'}}</td>
            </tr>`;
          }}).join('')}}
        </tbody>
      </table>
    </div>
    ${{(usersData||[]).length>5?`<div style="text-align:center;margin-top:12px"><button class="btn btn-ghost btn-sm" onclick="nav('users')">مشاهده همه <i class="fa fa-arrow-left"></i></button></div>`:''}}
  </div>`;
}}

// ══════════════════════════════════════════════════════
//  USERS PAGE
// ══════════════════════════════════════════════════════
let userFilter='';

function renderUsers(){{
  const acts=`
  <div class="search">
    <i class="fa fa-search search-ico"></i>
    <input placeholder="جستجوی کاربر..." oninput="filterUsers(this.value)" value="${{userFilter}}">
  </div>
  <button class="btn btn-primary btn-sm" onclick="openAddUser()">
    <i class="fa fa-plus"></i> کاربر جدید
  </button>`;
  document.getElementById('topbar-actions').innerHTML=acts;

  const filtered = usersData.filter(u=>
    u.name.toLowerCase().includes(userFilter.toLowerCase())||
    (u.email||'').toLowerCase().includes(userFilter.toLowerCase())
  );

  const rows=filtered.map(u=>{{
    const lim=u.traffic_limit_gb;
    const used=u.used_traffic_bytes||0;
    const pct=lim>0?Math.min(100,Math.round(used/(lim*1024**3)*100)):0;
    const cls=pct>85?'prog-r':pct>60?'prog-y':'prog-g';
    const dl=daysLeft(u.expire_at);
    const exp=dl===null?'—':dl<0?'<span class="badge br">منقضی</span>':dl<3?`<span class="badge br">${{dl}}d</span>`:dl<10?`<span class="badge by">${{dl}}d</span>`:`<span class="badge bg">${{dl}}d</span>`;
    return `<tr>
      <td>
        <div style="font-weight:700">${{u.flag||''}} ${{u.name}}</div>
        <div style="font-size:11px;color:var(--txt3)">${{u.email||''}}</div>
      </td>
      <td>
        <div style="font-size:12px;color:var(--txt2);margin-bottom:4px">${{fmtBytes(used)}} / ${{lim||'∞'}} GB</div>
        <div class="prog" style="width:100px"><div class="prog-bar ${{cls}}" style="width:${{pct}}%"></div></div>
      </td>
      <td>${{exp}}</td>
      <td>
        <label class="tog">
          <input type="checkbox" ${{u.is_active?'checked':''}} onchange="toggleUser('${{u.uuid}}',this)">
          <span class="tog-sl"></span>
        </label>
      </td>
      <td>
        <div style="display:flex;gap:6px;flex-wrap:wrap">
          <button class="btn btn-sm bb" onclick="showSubLink('${{u.uuid}}','${{u.name}}')">
            <i class="fa fa-link"></i>
          </button>
          <button class="btn btn-sm btn-ghost" onclick="openEditUser('${{u.uuid}}')">
            <i class="fa fa-pen"></i>
          </button>
          <button class="btn btn-sm btn-amber" onclick="resetTraffic('${{u.uuid}}','${{u.name}}')">
            <i class="fa fa-rotate-right"></i>
          </button>
          <button class="btn btn-sm btn-danger" onclick="deleteUser('${{u.uuid}}','${{u.name}}')">
            <i class="fa fa-trash"></i>
          </button>
        </div>
      </td>
    </tr>`;
  }}).join('');

  document.getElementById('p-users').innerHTML=`
  <div class="card">
    <div class="card-title">
      <span class="ct-icon"><i class="fa fa-users"></i></span>
      کاربران (${{filtered.length}})
    </div>
    ${{filtered.length===0?`<div class="empty"><div class="empty-ico">👤</div><h3>کاربری پیدا نشد</h3><p>ابتدا یک کاربر اضافه کنید</p></div>`:
    `<div class="tbl-wrap">
      <table>
        <thead><tr><th>نام / ایمیل</th><th>ترافیک</th><th>انقضا</th><th>فعال</th><th>عملیات</th></tr></thead>
        <tbody>${{rows}}</tbody>
      </table>
    </div>`}}
  </div>`;
}}

function filterUsers(v){{
  userFilter=v;renderUsers();
}}

async function toggleUser(uuid,cb){{
  try{{
    const r=await api('POST',`/api/users/${{uuid}}/toggle`);
    usersData=usersData.map(u=>u.uuid===uuid?{{...u,is_active:r.is_active}}:u);
    toast(r.is_active?'فعال شد':'غیرفعال شد');
  }}catch(e){{toast(e.message,'err');cb.checked=!cb.checked;}}
}}

function openAddUser(){{
  showModal(`<div class="m-head"><span class="m-title">👤 کاربر جدید</span><button class="m-close" onclick="closeModal()">✕</button></div>
  <div class="m-body">
    <div class="form-row">
      <div class="fg"><label>نام *</label><input id="un" placeholder="Ali"></div>
      <div class="fg"><label>ایمیل</label><input id="ue" placeholder="ali@example.com" type="email"></div>
    </div>
    <div class="form-row">
      <div class="fg"><label>حجم (GB) — 0 = نامحدود</label><input id="ut" type="number" min="0" step="0.5" value="0"></div>
      <div class="fg"><label>مدت (روز) — 0 = نامحدود</label><input id="ud" type="number" min="0" value="30"></div>
    </div>
    <div class="form-row">
      <div class="fg"><label>پرچم / لیبل (اختیاری)</label><input id="uf" placeholder="🇮🇷"></div>
      <div class="fg"><label>یادداشت</label><input id="unote" placeholder="..."></div>
    </div>
  </div>
  <div class="m-foot">
    <button class="btn btn-ghost" onclick="closeModal()">انصراف</button>
    <button class="btn btn-primary" onclick="submitAddUser()"><i class="fa fa-check"></i> ذخیره</button>
  </div>`);
}}

async function submitAddUser(){{
  const name=document.getElementById('un').value.trim();
  if(!name)return toast('نام الزامی است','err');
  try{{
    await api('POST','/api/users',{{
      name,
      email:document.getElementById('ue').value,
      traffic_limit_gb:parseFloat(document.getElementById('ut').value)||0,
      expire_days:parseInt(document.getElementById('ud').value)||0,
      flag:document.getElementById('uf').value,
      note:document.getElementById('unote').value,
    }});
    closeModal();toast('کاربر ساخته شد ✓');
    await loadUsers();renderUsers();
  }}catch(e){{toast(e.message,'err');}}
}}

async function openEditUser(uuid){{
  const u=usersData.find(x=>x.uuid===uuid);
  if(!u)return;
  showModal(`<div class="m-head"><span class="m-title">✏️ ویرایش ${{u.name}}</span><button class="m-close" onclick="closeModal()">✕</button></div>
  <div class="m-body">
    <div class="form-row">
      <div class="fg"><label>نام</label><input id="en" value="${{u.name}}"></div>
      <div class="fg"><label>ایمیل</label><input id="ee" value="${{u.email||''}}"></div>
    </div>
    <div class="form-row">
      <div class="fg"><label>حجم (GB)</label><input id="et" type="number" min="0" step="0.5" value="${{u.traffic_limit_gb||0}}"></div>
      <div class="fg"><label>مدت (روز)</label><input id="ed" type="number" min="0" value="${{u.expire_days||0}}"></div>
    </div>
    <div class="form-row">
      <div class="fg"><label>پرچم</label><input id="ef" value="${{u.flag||''}}"></div>
      <div class="fg"><label>وضعیت</label>
        <select id="es">
          <option value="1" ${{u.is_active?'selected':''}}>فعال</option>
          <option value="0" ${{!u.is_active?'selected':''}}>غیرفعال</option>
        </select>
      </div>
    </div>
    <div class="fg"><label>یادداشت</label><textarea id="enote">${{u.note||''}}</textarea></div>
  </div>
  <div class="m-foot">
    <button class="btn btn-ghost" onclick="closeModal()">انصراف</button>
    <button class="btn btn-primary" onclick="submitEditUser('${{uuid}}')"><i class="fa fa-check"></i> ذخیره</button>
  </div>`);
}}

async function submitEditUser(uuid){{
  try{{
    await api('PUT',`/api/users/${{uuid}}`,{{
      name:document.getElementById('en').value.trim(),
      email:document.getElementById('ee').value,
      traffic_limit_gb:parseFloat(document.getElementById('et').value)||0,
      expire_days:parseInt(document.getElementById('ed').value)||0,
      flag:document.getElementById('ef').value,
      is_active:parseInt(document.getElementById('es').value),
      note:document.getElementById('enote').value,
    }});
    closeModal();toast('ذخیره شد ✓');
    await loadUsers();renderUsers();
  }}catch(e){{toast(e.message,'err');}}
}}

async function deleteUser(uuid,name){{
  if(!confirm2(`کاربر "${{name}}" حذف شود?`))return;
  try{{
    await api('DELETE',`/api/users/${{uuid}}`);
    toast('حذف شد');
    await loadUsers();renderUsers();
  }}catch(e){{toast(e.message,'err');}}
}}

async function resetTraffic(uuid,name){{
  if(!confirm2(`ترافیک "${{name}}" ریست شود?`))return;
  try{{
    await api('POST',`/api/users/${{uuid}}/reset-traffic`);
    toast('ترافیک ریست شد');
    await loadUsers();renderUsers();
  }}catch(e){{toast(e.message,'err');}}
}}

async function showSubLink(uuid,name){{
  try{{
    const d=await api('GET',`/api/users/${{uuid}}/sub-link`);
    const u=usersData.find(x=>x.uuid===uuid)||{{}};
    const lim=u.traffic_limit_gb||0;
    const used=u.used_traffic_bytes||0;
    const rem=lim>0?Math.max(0,lim-used/1024**3).toFixed(2):'∞';
    const dl=daysLeft(u.expire_at);
    const daysStr=dl===null?'∞':dl<0?'منقضی شده':`${{dl}} روز`;

    const ipRows=(d.ip_links||[]).map(ip=>`
    <div style="margin-bottom:8px">
      <div style="font-size:11px;color:var(--txt3);margin-bottom:4px">
        <span class="ip-chip">${{ip.ip}}</span>
        ${{ip.label?`<span style="margin-right:6px">${{ip.label}}</span>`:''}}
      </div>
      <div class="copy-box"><span class="cb-txt">${{ip.link}}</span>
        <button class="copy-btn" onclick="copy('${{ip.link}}')"><i class="fa fa-copy"></i></button>
      </div>
    </div>`).join('');

    showModal(`<div class="m-head">
      <span class="m-title">🔗 لینک‌های ${{name}}</span>
      <button class="m-close" onclick="closeModal()">✕</button>
    </div>
    <div class="m-body">
      <div class="info-band">
        <div class="info-cell">
          <div class="iv">${{rem}}</div>
          <div class="il">GB باقی‌مانده</div>
        </div>
        <div class="info-cell">
          <div class="iv">${{daysStr}}</div>
          <div class="il">زمان باقی‌مانده</div>
        </div>
        <div class="info-cell">
          <div class="iv">${{(d.ip_links||[]).length||1}}</div>
          <div class="il">تعداد کانفیگ</div>
        </div>
      </div>

      <div style="margin-bottom:14px">
        <div style="font-size:12px;font-weight:700;color:var(--txt2);margin-bottom:8px">
          <i class="fa fa-link" style="color:var(--cyan)"></i> لینک اشتراک (Sub Link)
        </div>
        <div class="copy-box">
          <span class="cb-txt">${{d.sub_link}}</span>
          <button class="copy-btn" onclick="copy('${{d.sub_link}}')"><i class="fa fa-copy"></i></button>
        </div>
        <div style="font-size:11px;color:var(--txt3)">⚡ این لینک در کلاینت‌هایی مثل Hiddify, v2rayNG, Clash وارد کنید</div>
      </div>

      <div style="margin-bottom:14px">
        <div style="font-size:12px;font-weight:700;color:var(--txt2);margin-bottom:8px">
          <i class="fa fa-bolt" style="color:var(--violet)"></i> کانفیگ مستقیم VLESS
        </div>
        <div class="copy-box"><span class="cb-txt">${{d.vless_link}}</span>
          <button class="copy-btn" onclick="copy('${{d.vless_link}}')"><i class="fa fa-copy"></i></button>
        </div>
      </div>

      ${{ipRows?`<div>
        <div style="font-size:12px;font-weight:700;color:var(--txt2);margin-bottom:8px">
          <i class="fa fa-network-wired" style="color:var(--green)"></i> کانفیگ IP تمیز
        </div>
        ${{ipRows}}
      </div>`:''}}
    </div>
    <div class="m-foot">
      <button class="btn btn-ghost btn-sm" onclick="closeModal()">بستن</button>
      <button class="btn btn-primary btn-sm" onclick="copy('${{d.sub_link}}')">
        <i class="fa fa-copy"></i> کپی Sub Link
      </button>
    </div>`, true);
  }}catch(e){{toast(e.message,'err');}}
}}

// ══════════════════════════════════════════════════════
//  CLEAN IPs PAGE
// ══════════════════════════════════════════════════════
function renderIps(){{
  document.getElementById('topbar-actions').innerHTML=`
  <button class="btn btn-primary btn-sm" onclick="openAddIp()">
    <i class="fa fa-plus"></i> IP جدید
  </button>
  <button class="btn btn-ghost btn-sm" onclick="openBulkIp()">
    <i class="fa fa-list"></i> انبوه
  </button>`;

  const rows=ipsData.map(ip=>`
  <tr>
    <td><span class="ip-chip">${{ip.ip}}</span></td>
    <td>${{ip.label||'—'}}</td>
    <td>${{fmtDate(ip.added_at)}}</td>
    <td>
      <label class="tog">
        <input type="checkbox" ${{ip.is_active?'checked':''}} onchange="toggleIp(${{ip.id}},this)">
        <span class="tog-sl"></span>
      </label>
    </td>
    <td>
      <button class="btn btn-sm btn-danger" onclick="deleteIp(${{ip.id}})">
        <i class="fa fa-trash"></i>
      </button>
    </td>
  </tr>`).join('');

  document.getElementById('p-ips').innerHTML=`
  <div class="card" style="margin-bottom:12px">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
      <span style="font-size:13px;color:var(--txt2)">
        <i class="fa fa-info-circle" style="color:var(--cyan)"></i>
        IP تمیزها در subscription link هر کاربر به صورت یک کانفیگ جدا اضافه می‌شوند.
      </span>
    </div>
  </div>
  <div class="card">
    <div class="card-title">
      <span class="ct-icon"><i class="fa fa-network-wired"></i></span>
      IP های تمیز (${{ipsData.length}})
    </div>
    ${{ipsData.length===0?`<div class="empty"><div class="empty-ico">🌐</div><h3>IP تمیزی ثبت نشده</h3><p>IP های Cloudflare را اضافه کنید</p></div>`:
    `<div class="tbl-wrap">
      <table>
        <thead><tr><th>آدرس IP</th><th>لیبل</th><th>تاریخ</th><th>فعال</th><th>حذف</th></tr></thead>
        <tbody>${{rows}}</tbody>
      </table>
    </div>`}}
  </div>`;
}}

function openAddIp(){{
  showModal(`<div class="m-head"><span class="m-title">🌐 IP جدید</span><button class="m-close" onclick="closeModal()">✕</button></div>
  <div class="m-body">
    <div class="fg"><label>آدرس IP *</label><input id="ip-addr" placeholder="1.2.3.4"></div>
    <div class="fg"><label>لیبل (اختیاری)</label><input id="ip-label" placeholder="CF-1"></div>
  </div>
  <div class="m-foot">
    <button class="btn btn-ghost" onclick="closeModal()">انصراف</button>
    <button class="btn btn-primary" onclick="submitAddIp()"><i class="fa fa-check"></i> اضافه کن</button>
  </div>`);
}}

async function submitAddIp(){{
  const ip=document.getElementById('ip-addr').value.trim();
  if(!ip)return toast('IP الزامی است','err');
  try{{
    await api('POST','/api/ips',{{ip,label:document.getElementById('ip-label').value.trim()}});
    closeModal();toast('IP اضافه شد ✓');
    await loadIps();renderIps();
  }}catch(e){{toast(e.message,'err');}}
}}

function openBulkIp(){{
  showModal(`<div class="m-head"><span class="m-title">📋 اضافه انبوه</span><button class="m-close" onclick="closeModal()">✕</button></div>
  <div class="m-body">
    <div class="fg">
      <label>IP ها (هر خط یک IP، می‌توانید بعد از IP فاصله و لیبل بزنید)</label>
      <textarea id="bulk-ips" style="height:180px;font-family:monospace;direction:ltr;text-align:left" placeholder="1.1.1.1 Cloudflare-1&#10;1.0.0.1 Cloudflare-2&#10;104.16.0.0"></textarea>
    </div>
  </div>
  <div class="m-foot">
    <button class="btn btn-ghost" onclick="closeModal()">انصراف</button>
    <button class="btn btn-primary" onclick="submitBulkIp()"><i class="fa fa-check"></i> اضافه کن</button>
  </div>`);
}}

async function submitBulkIp(){{
  const txt=document.getElementById('bulk-ips').value;
  try{{
    const r=await api('POST','/api/ips/bulk',{{ips:txt}});
    closeModal();toast(`${{r.added}} IP اضافه شد ✓`);
    await loadIps();renderIps();
  }}catch(e){{toast(e.message,'err');}}
}}

async function toggleIp(id,cb){{
  try{{
    const r=await api('POST',`/api/ips/${{id}}/toggle`);
    ipsData=ipsData.map(i=>i.id===id?{{...i,is_active:r.is_active}}:i);
    toast(r.is_active?'فعال شد':'غیرفعال شد');
  }}catch(e){{toast(e.message,'err');cb.checked=!cb.checked;}}
}}

async function deleteIp(id){{
  if(!confirm2('این IP حذف شود?'))return;
  try{{
    await api('DELETE',`/api/ips/${{id}}`);
    toast('حذف شد');
    await loadIps();renderIps();
  }}catch(e){{toast(e.message,'err');}}
}}

// ══════════════════════════════════════════════════════
//  SETTINGS PAGE
// ══════════════════════════════════════════════════════
async function renderSettings(){{
  document.getElementById('topbar-actions').innerHTML='';
  let s={{}};
  try{{s=await api('GET','/api/settings');}}catch{{}}

  document.getElementById('p-settings').innerHTML=`
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
    <div class="card">
      <div class="card-title"><span class="ct-icon"><i class="fa fa-globe"></i></span>تنظیمات VLESS</div>
      <div class="fg"><label>دامنه / SNI</label><input id="s-sni" value="${{s.sni||''}}"></div>
      <div class="fg"><label>Host Header</label><input id="s-host" value="${{s.host_header||''}}"></div>
      <div class="fg"><label>TLS Fingerprint</label>
        <select id="s-fp">
          ${{['chrome','firefox','safari','edge','ios','android','random'].map(v=>`<option ${{s.tls_fingerprint===v?'selected':''}}>${{v}}</option>`).join('')}}
        </select>
      </div>
      <div class="fg"><label>Fragment (اختیاری)</label><input id="s-frag" value="${{s.fragment||''}}"></div>
      <button class="btn btn-primary" onclick="saveVlessSettings()"><i class="fa fa-save"></i> ذخیره</button>
    </div>
    <div class="card">
      <div class="card-title"><span class="ct-icon"><i class="fa fa-robot"></i></span>تلگرام</div>
      <div class="fg"><label>Bot Token</label><input id="s-tgtoken" value="${{s.tg_bot_token||''}}" type="password"></div>
      <div class="fg"><label>Chat ID</label><input id="s-tgchat" value="${{s.tg_chat_id||''}}"></div>
      <div class="fg">
        <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
          <label class="tog">
            <input type="checkbox" id="s-tgen" ${{s.tg_enabled==='1'?'checked':''}}>
            <span class="tog-sl"></span>
          </label>
          فعال‌سازی اعلان تلگرام
        </label>
      </div>
      <button class="btn btn-primary" onclick="saveTgSettings()"><i class="fa fa-save"></i> ذخیره</button>
    </div>
    <div class="card">
      <div class="card-title"><span class="ct-icon"><i class="fa fa-circle-dot"></i></span>Keep-Alive</div>
      <div class="fg">
        <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
          <label class="tog">
            <input type="checkbox" id="s-kaen" ${{s.keepalive_enabled==='1'?'checked':''}}>
            <span class="tog-sl"></span>
          </label>
          فعال‌سازی Keep-Alive
        </label>
      </div>
      <div class="fg"><label>فاصله (ثانیه)</label><input id="s-kaint" type="number" value="${{s.keepalive_interval||300}}"></div>
      <button class="btn btn-primary" onclick="saveKaSettings()"><i class="fa fa-save"></i> ذخیره</button>
    </div>
    <div class="card">
      <div class="card-title"><span class="ct-icon"><i class="fa fa-info"></i></span>اطلاعات پنل</div>
      <div style="display:flex;flex-direction:column;gap:10px">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <span style="color:var(--txt2);font-size:13px">نسخه</span>
          <span class="badge bb">v${{VER}}</span>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:center">
          <span style="color:var(--txt2);font-size:13px">دامنه فعلی</span>
          <span class="ip-chip" style="font-size:11px">${{s.sni||'—'}}</span>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:center">
          <span style="color:var(--txt2);font-size:13px">کل کاربران</span>
          <span style="font-weight:700">${{statsData.total_users||0}}</span>
        </div>
      </div>
    </div>
  </div>`;
}}

async function saveVlessSettings(){{
  try{{
    await api('POST','/api/settings',{{
      sni:document.getElementById('s-sni').value,
      host_header:document.getElementById('s-host').value,
      tls_fingerprint:document.getElementById('s-fp').value,
      fragment:document.getElementById('s-frag').value,
    }});
    toast('تنظیمات VLESS ذخیره شد ✓');
  }}catch(e){{toast(e.message,'err');}}
}}

async function saveTgSettings(){{
  try{{
    await api('POST','/api/settings',{{
      tg_bot_token:document.getElementById('s-tgtoken').value,
      tg_chat_id:document.getElementById('s-tgchat').value,
      tg_enabled:document.getElementById('s-tgen').checked?'1':'0',
    }});
    toast('تنظیمات تلگرام ذخیره شد ✓');
  }}catch(e){{toast(e.message,'err');}}
}}

async function saveKaSettings(){{
  try{{
    await api('POST','/api/settings',{{
      keepalive_enabled:document.getElementById('s-kaen').checked?'1':'0',
      keepalive_interval:document.getElementById('s-kaint').value,
    }});
    toast('Keep-Alive ذخیره شد ✓');
  }}catch(e){{toast(e.message,'err');}}
}}

// ══════════════════════════════════════════════════════
//  MODAL HELPER
// ══════════════════════════════════════════════════════
function showModal(html, large=false){{
  closeModal();
  const ov=document.createElement('div');
  ov.className='overlay';ov.id='modal-ov';
  ov.onclick=e=>{{if(e.target===ov)closeModal()}};
  const m=document.createElement('div');
  m.className='modal'+(large?' modal-lg':'');
  m.innerHTML=html;
  ov.append(m);
  document.body.append(ov);
}}

function closeModal(){{
  document.getElementById('modal-ov')?.remove();
}}

// ══════════════════════════════════════════════════════
//  AUTH
// ══════════════════════════════════════════════════════
async function logout(){{
  await fetch('/api/logout',{{method:'POST'}}).catch(()=>{{}});
  window.location.reload();
}}

// ══════════════════════════════════════════════════════
//  INIT
// ══════════════════════════════════════════════════════
if(IS_AUTH) renderApp();
else renderLogin();
</script>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=False)
