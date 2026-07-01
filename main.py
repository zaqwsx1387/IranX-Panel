"""
╔══════════════════════════════════════════════════════════╗
║           IranX Panel - Powered by FastAPI + SQLite       ║
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
log = logging.getLogger("iranx-panel")

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
                type TEXT DEFAULT 'ip',
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

        # Migration: add `type` column to clean_ips for older databases
        try:
            await db.execute("ALTER TABLE clean_ips ADD COLUMN type TEXT DEFAULT 'ip'")
            await db.commit()
        except Exception:
            pass

        # Migration: add `admin_password_hash` / `admin_username_custom` support handled via settings defaults below

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
            "fake_info_config": "1",
            "admin_password_hash": "",
            "admin_username_custom": "",
            "ui_theme": "dark",
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


def hash_password(password: str) -> str:
    return hashlib.sha256(f"{password}:{SECRET_KEY}".encode()).hexdigest()


async def get_effective_admin_username() -> str:
    custom = await get_setting("admin_username_custom", "")
    return custom or ADMIN_USERNAME


async def verify_admin_password(password: str) -> bool:
    stored_hash = await get_setting("admin_password_hash", "")
    if stored_hash:
        return hmac.compare_digest(hash_password(password), stored_hash)
    return password == ADMIN_PASSWORD

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


def _fmt_remaining_traffic_en(user) -> str:
    limit_bytes = float(user["traffic_limit_gb"] or 0) * 1024 ** 3
    used_bytes = int(user["used_traffic_bytes"] or 0)
    if limit_bytes <= 0:
        return "Unlimited"
    remaining_bytes = max(0, int(limit_bytes - used_bytes))
    remaining_gb = remaining_bytes / 1024 ** 3
    if remaining_gb >= 1:
        return f"{round(remaining_gb, 2)}GB"
    return f"{round(remaining_bytes / 1024 ** 2)}MB"


def _fmt_remaining_days_en(user) -> str:
    if not user["expire_at"]:
        return "Unlimited"
    try:
        exp = datetime.fromisoformat(user["expire_at"])
    except Exception:
        return "Unknown"
    delta = exp - datetime.now()
    days = delta.days
    if days < 0:
        return "Expired"
    if days == 0:
        hours = max(0, int(delta.total_seconds() // 3600))
        return f"{hours}h"
    return f"{days}d"


async def build_fake_info_link(user) -> str:
    """A display-only dummy config with no real functionality. It's only used
    to show remaining traffic/days inside the name shown in the user's client app.
    The technical parameters don't matter since it's never actually connected to."""
    from urllib.parse import quote

    remaining_traffic = _fmt_remaining_traffic_en(user)
    remaining_days = _fmt_remaining_days_en(user)

    label = f"Info | {remaining_traffic} left | {remaining_days} left"

    # Stable uuid per-user (same every time, so the client doesn't duplicate it)
    fake_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"info:{user['uuid']}"))
    domain = DOMAIN
    sni = await get_setting("sni", domain)
    host_header = await get_setting("host_header", domain)

    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "path": "/info",
        "host": host_header,
        "sni": sni,
        "fp": "chrome",
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{fake_uuid}@{domain}:443?{query}#{quote(label)}"


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

    # Get active clean IPs/domains
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT ip, label FROM clean_ips WHERE is_active=1 ORDER BY id"
        ) as cur:
            ips = await cur.fetchall()

    links = []

    # همیشه یک کانفیگ با خود دامنه پنل اضافه میشه (دامنه به‌عنوان یک آدرس تمیز در نظر گرفته میشه)
    domain_name = (await get_setting("sni", DOMAIN)) or DOMAIN
    domain_display = f"{user['flag']} {user['name']} | {domain_name}".strip()
    links.append(await build_vless_link(user["uuid"], domain_display, address=DOMAIN))

    # یک لینک برای هر IP/دامنه تمیز — آدرس اتصال عوض میشه، SNI/host همون دامنه اصلی میمونه
    for ip_row in ips:
        ip_addr = ip_row["ip"]
        ip_label = ip_row["label"] or ip_addr
        display_name = f"{user['flag']} {user['name']} | {ip_label}".strip()
        link = await build_vless_link(
            user["uuid"],
            display_name,
            address=ip_addr,
        )
        links.append(link)

    fake_enabled = await get_setting("fake_info_config", "1")
    if fake_enabled == "1":
        fake_link = await build_fake_info_link(user)
        links.insert(0, fake_link)

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
    log.info(f"🚀 IranX Panel v{PANEL_VERSION} started on port {PORT}")
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
    effective_username = await get_effective_admin_username()
    password_ok = await verify_admin_password(password)
    success = username == effective_username and password_ok
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


@app.post("/api/account/change-password")
async def change_password(request: Request, auth=Depends(require_auth)):
    data = await request.json()
    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")
    if not new_password or len(new_password) < 8:
        raise HTTPException(400, "رمز جدید باید حداقل ۸ کاراکتر باشد")
    if not await verify_admin_password(current_password):
        raise HTTPException(401, "رمز عبور فعلی اشتباه است")
    await set_setting("admin_password_hash", hash_password(new_password))
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

    vless_label = f"{user['flag']} {user['name']} | {DOMAIN}".strip()
    vless = await build_vless_link(user["uuid"], vless_label, "")

    # لینک‌های IP/دامنه تمیز (اگه وجود داشت)
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT ip, label FROM clean_ips WHERE is_active=1") as cur:
            ips = await cur.fetchall()

    ip_links = []
    for ip_row in ips:
        ip_lbl = (ip_row['label'] or ip_row['ip'])
        lnk = await build_vless_link(
            user["uuid"],
            f"{user['name']} | {ip_lbl}",
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
    addr_type = data.get("type", "").strip().lower()
    if not ip:
        raise HTTPException(400, "آدرس الزامی است")
    if addr_type not in ("ip", "domain"):
        ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-fA-F:]+$")
        addr_type = "ip" if ip_pattern.match(ip) else "domain"
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR IGNORE INTO clean_ips (ip, label, type, added_at) VALUES (?,?,?,?)",
            (ip, label, addr_type, datetime.now().isoformat()),
        )
        await db.commit()
    return {"ok": True}


@app.post("/api/ips/bulk")
async def bulk_add_ips(request: Request, auth=Depends(require_auth)):
    data = await request.json()
    ips_text = data.get("ips", "")
    added = 0
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-fA-F:]+$")
    domain_pattern = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")
    async with aiosqlite.connect(DB_PATH) as db:
        for line in ips_text.splitlines():
            line = line.strip()
            parts = line.split()
            addr = parts[0] if parts else ""
            label = " ".join(parts[1:]) if len(parts) > 1 else ""
            if not addr:
                continue
            if ip_pattern.match(addr):
                addr_type = "ip"
            elif domain_pattern.match(addr):
                addr_type = "domain"
            else:
                continue
            await db.execute(
                "INSERT OR IGNORE INTO clean_ips (ip, label, type, added_at) VALUES (?,?,?,?)",
                (addr, label, addr_type, datetime.now().isoformat()),
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
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IranX-Panel</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root {{
    /* Minimal, pro palette (cool slate + electric cyan) */
    --bg: #0b0f17;
    --bg2: #0f1626;
    --bg3: #111b30;
    --card: rgba(255,255,255,0.04);
    --card2: rgba(255,255,255,0.06);
    --border: rgba(148,163,184,0.18);
    --border2: rgba(148,163,184,0.28);
    --accent: #22d3ee;
    --accent2: #60a5fa;
    --accent3: #a78bfa;
    --green: #10b981;
    --red: #fb7185;
    --yellow: #fbbf24;
    --blue: #60a5fa;
    --text: rgba(248,250,252,0.92);
    --text2: rgba(226,232,240,0.72);
    --text3: rgba(148,163,184,0.65);
    --shadow: 0 10px 40px rgba(0,0,0,0.45);
    --radius: 16px;
    --radius-sm: 12px;
  }}

  html[data-theme="light"] {{
    --bg: #f1f5f9;
    --bg2: #ffffff;
    --bg3: #e9eef5;
    --card: rgba(255,255,255,0.75);
    --card2: rgba(255,255,255,0.9);
    --border: rgba(15,23,42,0.10);
    --border2: rgba(15,23,42,0.18);
    --accent: #0891b2;
    --accent2: #2563eb;
    --accent3: #7c3aed;
    --green: #059669;
    --red: #e11d48;
    --yellow: #d97706;
    --blue: #2563eb;
    --text: rgba(15,23,42,0.92);
    --text2: rgba(51,65,85,0.78);
    --text3: rgba(100,116,139,0.75);
    --shadow: 0 10px 40px rgba(15,23,42,0.12);
  }}

  html, body {{ transition: background 0.3s ease, color 0.3s ease; }}
  body, .sidebar, .topbar, .card, .stat-card, .modal, .login-card {{ transition: background 0.3s ease, color 0.3s ease, border-color 0.3s ease, box-shadow 0.3s ease, transform 0.25s ease; }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  
  body {{
    font-family: 'Vazirmatn', system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    background: radial-gradient(1200px 900px at 15% 10%, rgba(34,211,238,0.12), transparent 55%),
                radial-gradient(900px 700px at 85% 20%, rgba(96,165,250,0.10), transparent 55%),
                radial-gradient(900px 700px at 40% 95%, rgba(167,139,250,0.08), transparent 55%),
                var(--bg);
    color: var(--text);
    min-height: 100vh;
    direction: rtl;
  }}

  /* SCROLLBAR */
  ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
  ::-webkit-scrollbar-track {{ background: var(--bg2); }}
  ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 10px; }}
  ::-webkit-scrollbar-thumb:hover {{ background: var(--accent); }}

  /* LOGIN PAGE */
  .login-page {{
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    background: transparent;
    position: relative;
    overflow: hidden;
  }}
  .login-page::before {{
    content: '';
    position: absolute;
    width: 600px; height: 600px;
    background: radial-gradient(circle, rgba(34,211,238,0.16) 0%, transparent 70%);
    top: -100px; right: -100px;
    pointer-events: none;
    animation: floatBg 9s ease-in-out infinite;
  }}
  .login-page::after {{
    content: '';
    position: absolute;
    width: 400px; height: 400px;
    background: radial-gradient(circle, rgba(16,185,129,0.08) 0%, transparent 70%);
    bottom: -50px; left: -50px;
    pointer-events: none;
    animation: floatBg 11s ease-in-out infinite reverse;
  }}
  .login-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 48px 40px;
    width: 420px;
    max-width: 95vw;
    box-shadow: var(--shadow);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    position: relative;
    z-index: 1;
    animation: popIn 0.5s cubic-bezier(0.16,1,0.3,1);
  }}
  .login-logo {{
    text-align: center;
    margin-bottom: 32px;
  }}
  .login-logo .icon {{
    width: 72px; height: 72px;
    background: linear-gradient(135deg, var(--accent), var(--green));
    border-radius: 20px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 32px;
    margin-bottom: 16px;
    box-shadow: 0 10px 40px rgba(34,211,238,0.18);
    animation: glowPulse 2.8s ease-in-out infinite;
  }}
  .login-logo h1 {{ font-size: 24px; font-weight: 700; color: var(--text); }}
  .login-logo p {{ color: var(--text2); font-size: 14px; margin-top: 4px; }}

  /* FORM */
  .form-group {{ margin-bottom: 20px; }}
  .form-group label {{ display: block; font-size: 14px; color: var(--text2); margin-bottom: 8px; font-weight: 500; }}
  .form-group input, .form-group select, .form-group textarea {{
    width: 100%;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--text);
    padding: 12px 16px;
    font-size: 14px;
    font-family: inherit;
    transition: border-color 0.2s, box-shadow 0.2s;
    outline: none;
    direction: ltr;
    text-align: right;
  }}
  .form-group input:focus, .form-group select:focus, .form-group textarea:focus {{
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(34,211,238,0.16);
  }}
  .form-group textarea {{ resize: vertical; min-height: 80px; }}
  .form-group select option {{ background: var(--bg2); }}

  /* BUTTONS */
  .btn {{
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 10px 20px;
    border-radius: var(--radius-sm);
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    border: none;
    transition: transform 0.15s cubic-bezier(0.16,1,0.3,1), box-shadow 0.2s ease, background 0.2s ease, color 0.2s ease;
    font-family: inherit;
    text-decoration: none;
  }}
  .btn:active {{ transform: scale(0.96); }}
  .btn-primary {{
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    color: rgba(3,7,18,0.92);
    box-shadow: 0 10px 26px rgba(34,211,238,0.18);
    border: 1px solid rgba(34,211,238,0.22);
  }}
  .btn-primary:hover {{ transform: translateY(-1px); box-shadow: 0 14px 34px rgba(34,211,238,0.22); }}
  .btn-success {{ background: rgba(16,185,129,0.15); color: var(--green); border: 1px solid rgba(16,185,129,0.3); }}
  .btn-success:hover {{ background: rgba(16,185,129,0.25); transform: translateY(-1px); }}
  .btn-danger {{ background: rgba(239,68,68,0.15); color: var(--red); border: 1px solid rgba(239,68,68,0.3); }}
  .btn-danger:hover {{ background: rgba(239,68,68,0.25); transform: translateY(-1px); }}
  .btn-secondary {{ background: var(--bg3); color: var(--text2); border: 1px solid var(--border); }}
  .btn-secondary:hover {{ background: var(--border); color: var(--text); transform: translateY(-1px); }}
  .btn-warning {{ background: rgba(245,158,11,0.15); color: var(--yellow); border: 1px solid rgba(245,158,11,0.3); }}
  .btn-warning:hover {{ background: rgba(245,158,11,0.25); transform: translateY(-1px); }}
  .btn-full {{ width: 100%; justify-content: center; padding: 14px; font-size: 16px; }}
  .btn-sm {{ padding: 6px 12px; font-size: 12px; border-radius: 6px; }}
  .btn:disabled {{ opacity: 0.5; cursor: not-allowed; transform: none !important; }}

  /* LAYOUT */
  .app {{ display: flex; min-height: 100vh; }}
  
  /* SIDEBAR */
  .sidebar {{
    width: 260px;
    background: var(--bg2);
    border-left: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    position: fixed;
    top: 0; right: 0;
    height: 100vh;
    z-index: 100;
    transition: transform 0.3s;
  }}
  .sidebar-logo {{
    padding: 24px 20px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 12px;
  }}
  .sidebar-logo .logo-icon {{
    width: 44px; height: 44px;
    background: linear-gradient(135deg, var(--accent), var(--green));
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
    flex-shrink: 0;
  }}
  .sidebar-logo h2 {{ font-size: 18px; font-weight: 700; color: var(--text); }}
  .sidebar-logo small {{ font-size: 11px; color: var(--text3); }}
  
  .sidebar-nav {{ flex: 1; padding: 16px 12px; overflow-y: auto; }}
  .nav-section {{ margin-bottom: 24px; }}
  .nav-section-title {{
    font-size: 11px;
    color: var(--text3);
    font-weight: 600;
    padding: 0 8px;
    margin-bottom: 8px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  .nav-item {{
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 12px;
    border-radius: var(--radius-sm);
    color: var(--text2);
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    transition: background 0.25s ease, color 0.25s ease, border-color 0.25s ease, transform 0.15s ease;
    margin-bottom: 2px;
    user-select: none;
  }}
  .nav-item:hover {{ background: var(--bg3); color: var(--text); transform: translateX(-2px); }}
  .nav-item:active {{ transform: scale(0.98); }}
  .nav-item.active {{ background: rgba(34,211,238,0.12); color: var(--accent); border: 1px solid rgba(34,211,238,0.18); }}
  .nav-item .nav-icon {{ width: 20px; text-align: center; font-size: 15px; transition: transform 0.25s cubic-bezier(0.34,1.56,0.64,1); }}
  .nav-item:hover .nav-icon {{ transform: scale(1.18); }}
  
  .sidebar-footer {{
    padding: 16px 12px;
    border-top: 1px solid var(--border);
  }}
  .user-info {{
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 12px;
    border-radius: var(--radius-sm);
    background: var(--bg3);
  }}
  .user-avatar {{
    width: 36px; height: 36px;
    background: linear-gradient(135deg, var(--accent), var(--green));
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 14px;
    font-weight: 700;
  }}
  .user-name {{ font-size: 14px; font-weight: 600; }}
  .user-role {{ font-size: 12px; color: var(--text3); }}
  
  /* MAIN CONTENT */
  .main {{
    flex: 1;
    margin-right: 260px;
    display: flex;
    flex-direction: column;
    min-height: 100vh;
  }}
  
  /* TOPBAR */
  .topbar {{
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    padding: 16px 28px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: sticky;
    top: 0;
    z-index: 50;
  }}
  .topbar-title {{
    font-size: 20px;
    font-weight: 700;
    color: var(--text);
  }}
  .topbar-subtitle {{
    font-size: 13px;
    color: var(--text2);
    margin-top: 2px;
  }}
  .topbar-actions {{ display: flex; gap: 10px; align-items: center; }}
  
  /* CONTENT */
  .content {{ padding: 28px; flex: 1; }}
  
  /* CARDS */
  .card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 24px;
    margin-bottom: 24px;
    backdrop-filter: blur(18px);
    -webkit-backdrop-filter: blur(18px);
    transition: transform 0.25s cubic-bezier(0.16,1,0.3,1), box-shadow 0.25s ease, border-color 0.25s ease;
  }}
  .card:hover {{
    transform: translateY(-3px);
    box-shadow: var(--shadow);
    border-color: var(--border2);
  }}
  .card-title {{
    font-size: 16px;
    font-weight: 700;
    color: var(--text);
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    gap: 8px;
  }}
  
  /* STAT CARDS */
  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
  }}
  .stat-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 20px;
    position: relative;
    overflow: hidden;
    backdrop-filter: blur(18px);
    -webkit-backdrop-filter: blur(18px);
    transition: transform 0.3s cubic-bezier(0.16,1,0.3,1), box-shadow 0.3s ease, border-color 0.3s ease;
  }}
  .stat-card:hover {{ transform: translateY(-4px) scale(1.012); box-shadow: var(--shadow); border-color: var(--border2); }}
  .stat-card:hover .stat-icon {{ transform: scale(1.1) rotate(-4deg); }}
  .stat-icon {{ transition: transform 0.35s cubic-bezier(0.34,1.56,0.64,1); }}
  .stat-card::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
  }}
  .stat-card.accent::before {{ background: linear-gradient(90deg, var(--accent), var(--accent2)); }}
  .stat-card.green::before {{ background: linear-gradient(90deg, var(--green), #34d399); }}
  .stat-card.red::before {{ background: linear-gradient(90deg, var(--red), #f87171); }}
  .stat-card.yellow::before {{ background: linear-gradient(90deg, var(--yellow), #fbbf24); }}
  .stat-card.blue::before {{ background: linear-gradient(90deg, var(--blue), #60a5fa); }}
  
  .stat-icon {{
    width: 48px; height: 48px;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 22px;
    margin-bottom: 16px;
  }}
  .stat-icon.accent {{ background: rgba(34,211,238,0.14); color: var(--accent); }}
  .stat-icon.green {{ background: rgba(16,185,129,0.14); color: var(--green); }}
  .stat-icon.red {{ background: rgba(251,113,133,0.14); color: var(--red); }}
  .stat-icon.yellow {{ background: rgba(251,191,36,0.14); color: var(--yellow); }}
  .stat-icon.blue {{ background: rgba(96,165,250,0.14); color: var(--blue); }}
  
  .stat-value {{ font-size: 32px; font-weight: 800; color: var(--text); line-height: 1; }}
  .stat-label {{ font-size: 13px; color: var(--text2); margin-top: 6px; font-weight: 500; }}
  .stat-sub {{ font-size: 12px; color: var(--text3); margin-top: 4px; }}
  
  /* TABLE */
  .table-wrapper {{ overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; direction: rtl; }}
  th {{
    background: var(--bg3);
    color: var(--text2);
    font-size: 12px;
    font-weight: 600;
    padding: 12px 16px;
    text-align: right;
    white-space: nowrap;
    border-bottom: 1px solid var(--border);
  }}
  td {{
    padding: 14px 16px;
    color: var(--text);
    font-size: 13px;
    border-bottom: 1px solid rgba(42,53,85,0.5);
    vertical-align: middle;
  }}
  tr:last-child td {{ border-bottom: none; }}
  td {{ transition: background 0.15s ease; }}
  tr:hover td {{ background: rgba(255,255,255,0.035); }}
  
  /* BADGES */
  .badge {{
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 3px 10px;
    border-radius: 100px;
    font-size: 12px;
    font-weight: 600;
    white-space: nowrap;
  }}
  .badge-green {{ background: rgba(16,185,129,0.15); color: var(--green); }}
  .badge-red {{ background: rgba(239,68,68,0.15); color: var(--red); }}
  .badge-yellow {{ background: rgba(245,158,11,0.15); color: var(--yellow); }}
  .badge-blue {{ background: rgba(96,165,250,0.14); color: var(--blue); }}
  .badge-purple {{ background: rgba(167,139,250,0.14); color: var(--accent3); }}
  
  /* PROGRESS */
  .progress {{
    height: 6px;
    background: var(--bg3);
    border-radius: 100px;
    overflow: hidden;
    margin-top: 6px;
  }}
  .progress-bar {{
    height: 100%;
    border-radius: 100px;
    transition: width 0.5s;
  }}
  .progress-bar.green {{ background: linear-gradient(90deg, var(--green), #34d399); }}
  .progress-bar.yellow {{ background: linear-gradient(90deg, var(--yellow), #fbbf24); }}
  .progress-bar.red {{ background: linear-gradient(90deg, var(--red), #f87171); }}
  
  /* MODAL */
  .modal-overlay {{
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.7);
    backdrop-filter: blur(4px);
    z-index: 1000;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
    animation: fadeIn 0.2s;
  }}
  .modal {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 20px;
    width: 100%;
    max-width: 560px;
    max-height: 90vh;
    overflow-y: auto;
    box-shadow: 0 20px 60px rgba(0,0,0,0.5);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    animation: popIn 0.28s cubic-bezier(0.16,1,0.3,1);
  }}
  .modal-header {{
    padding: 24px 28px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
  }}
  .modal-title {{ font-size: 18px; font-weight: 700; color: var(--text); }}
  .modal-close {{
    width: 32px; height: 32px;
    background: var(--bg3);
    border: none;
    border-radius: 8px;
    color: var(--text2);
    cursor: pointer;
    font-size: 16px;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.2s;
  }}
  .modal-close:hover {{ background: var(--red); color: white; transform: rotate(90deg); }}
  .modal-body {{ padding: 24px 28px; }}
  .modal-footer {{ padding: 16px 28px 24px; display: flex; gap: 10px; justify-content: flex-end; }}
  
  /* TOAST */
  .toast-container {{
    position: fixed;
    bottom: 24px;
    left: 24px;
    z-index: 9999;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }}
  .toast {{
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 14px 18px;
    display: flex;
    align-items: center;
    gap: 10px;
    min-width: 280px;
    box-shadow: var(--shadow);
    animation: slideInLeft 0.3s ease;
    font-size: 14px;
  }}
  .toast.success {{ border-color: rgba(16,185,129,0.3); }}
  .toast.error {{ border-color: rgba(239,68,68,0.3); }}
  .toast-icon.success {{ color: var(--green); }}
  .toast-icon.error {{ color: var(--red); }}
  
  /* SEARCH */
  .search-bar {{
    position: relative;
    flex: 1;
    max-width: 340px;
  }}
  .search-bar input {{
    width: 100%;
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 10px;
    color: var(--text);
    padding: 10px 16px 10px 40px;
    font-size: 14px;
    font-family: inherit;
    outline: none;
    direction: rtl;
    transition: border-color 0.2s;
  }}
  .search-bar input:focus {{ border-color: var(--accent); }}
  .search-bar .search-icon {{
    position: absolute;
    left: 12px;
    top: 50%;
    transform: translateY(-50%);
    color: var(--text3);
  }}
  
  /* SYSTEM HEALTH */
  .health-grid {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 16px;
  }}
  .health-item {{ text-align: center; }}
  .health-circle {{
    width: 80px; height: 80px;
    border-radius: 50%;
    background: conic-gradient(var(--accent) 0%, var(--bg3) 0%);
    display: flex;
    align-items: center;
    justify-content: center;
    margin: 0 auto 8px;
    font-size: 16px;
    font-weight: 700;
    position: relative;
  }}
  .health-circle::before {{
    content: '';
    position: absolute;
    inset: 6px;
    border-radius: 50%;
    background: var(--card);
  }}
  .health-circle span {{ position: relative; z-index: 1; font-size: 14px; }}
  .health-label {{ font-size: 12px; color: var(--text2); font-weight: 500; }}
  
  /* CHART CONTAINER */
  .chart-container {{ position: relative; height: 220px; }}
  
  /* TWO-COL GRID */
  .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }}
  .grid-3 {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; }}
  
  /* COPY BTN */
  .copy-btn {{
    background: none;
    border: none;
    color: var(--text3);
    cursor: pointer;
    padding: 4px;
    border-radius: 4px;
    transition: color 0.2s;
    font-size: 13px;
  }}
  .copy-btn:hover {{ color: var(--accent); }}
  
  /* CODE BLOCK */
  .code-block {{
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px 16px;
    font-family: monospace;
    font-size: 13px;
    color: var(--accent3);
    word-break: break-all;
    display: flex;
    align-items: flex-start;
    gap: 10px;
    direction: ltr;
  }}
  .code-block .code-text {{ flex: 1; }}
  
  /* SECTION TABS */
  .page {{ display: none; }}
  .page.active {{ display: block; animation: pageIn 0.4s cubic-bezier(0.16,1,0.3,1); }}
  
  /* TOGGLE */
  .toggle {{
    position: relative;
    width: 44px;
    height: 24px;
    display: inline-block;
  }}
  .toggle input {{ opacity: 0; width: 0; height: 0; }}
  .toggle-slider {{
    position: absolute;
    inset: 0;
    background: var(--bg3);
    border-radius: 100px;
    cursor: pointer;
    transition: 0.3s;
    border: 1px solid var(--border);
  }}
  .toggle-slider::before {{
    content: '';
    position: absolute;
    width: 18px; height: 18px;
    border-radius: 50%;
    background: var(--text3);
    top: 2px; right: 2px;
    transition: 0.3s;
  }}
  .toggle input:checked + .toggle-slider {{ background: rgba(99,102,241,0.3); border-color: var(--accent); }}
  .toggle input:checked + .toggle-slider::before {{ background: var(--accent); transform: translateX(-20px); }}

  /* CHIP */
  .chip-input-wrapper {{ display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }}
  .chip {{
    background: rgba(99,102,241,0.15);
    color: var(--accent2);
    border-radius: 6px;
    padding: 3px 10px;
    font-size: 12px;
    font-family: monospace;
    display: flex;
    align-items: center;
    gap: 4px;
  }}
  .chip-remove {{ cursor: pointer; color: var(--text3); font-size: 11px; }}
  .chip-remove:hover {{ color: var(--red); }}

  /* EMPTY STATE */
  .empty-state {{
    text-align: center;
    padding: 60px 20px;
    color: var(--text3);
  }}
  .empty-state .empty-icon {{ font-size: 48px; margin-bottom: 16px; opacity: 0.5; }}
  .empty-state h3 {{ font-size: 18px; color: var(--text2); margin-bottom: 8px; }}
  .empty-state p {{ font-size: 14px; }}

  /* ANIMATIONS */
  @keyframes fadeIn {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
  @keyframes slideUp {{ from {{ opacity: 0; transform: translateY(20px); }} to {{ opacity: 1; transform: translateY(0); }} }}
  @keyframes slideInLeft {{ from {{ opacity: 0; transform: translateX(-20px); }} to {{ opacity: 1; transform: translateX(0); }} }}
  @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
  .spin {{ animation: spin 1s linear infinite; }}
  @keyframes pageIn {{ from {{ opacity: 0; transform: translateY(10px) scale(0.99); }} to {{ opacity: 1; transform: translateY(0) scale(1); }} }}
  @keyframes rowIn {{ from {{ opacity: 0; transform: translateX(8px); }} to {{ opacity: 1; transform: translateX(0); }} }}
  @keyframes popIn {{ from {{ opacity: 0; transform: scale(0.85); }} to {{ opacity: 1; transform: scale(1); }} }}
  @keyframes shimmer {{ 0% {{ background-position: -400px 0; }} 100% {{ background-position: 400px 0; }} }}
  @keyframes glowPulse {{ 0%,100% {{ box-shadow: 0 0 0 0 rgba(34,211,238,0.35); }} 50% {{ box-shadow: 0 0 0 6px rgba(34,211,238,0); }} }}
  @keyframes floatBg {{ 0%,100% {{ transform: translate(0,0); }} 50% {{ transform: translate(10px,-14px); }} }}

  tbody tr {{ animation: rowIn 0.35s ease both; }}
  tbody tr:nth-child(1) {{ animation-delay: 0.02s; }}
  tbody tr:nth-child(2) {{ animation-delay: 0.05s; }}
  tbody tr:nth-child(3) {{ animation-delay: 0.08s; }}
  tbody tr:nth-child(4) {{ animation-delay: 0.11s; }}
  tbody tr:nth-child(5) {{ animation-delay: 0.14s; }}
  tbody tr:nth-child(6) {{ animation-delay: 0.17s; }}
  tbody tr:nth-child(7) {{ animation-delay: 0.20s; }}
  tbody tr:nth-child(8) {{ animation-delay: 0.23s; }}
  tbody tr:nth-child(n+9) {{ animation-delay: 0.26s; }}

  .stats-grid .stat-card {{ animation: slideUp 0.45s ease both; }}
  .stats-grid .stat-card:nth-child(1) {{ animation-delay: 0.02s; }}
  .stats-grid .stat-card:nth-child(2) {{ animation-delay: 0.08s; }}
  .stats-grid .stat-card:nth-child(3) {{ animation-delay: 0.14s; }}
  .stats-grid .stat-card:nth-child(4) {{ animation-delay: 0.20s; }}
  .stats-grid .stat-card:nth-child(5) {{ animation-delay: 0.26s; }}
  .stats-grid .stat-card:nth-child(6) {{ animation-delay: 0.32s; }}

  /* SKELETON LOADER */
  .skeleton {{
    border-radius: var(--radius-sm);
    background: linear-gradient(90deg, var(--bg3) 0px, rgba(255,255,255,0.06) 40px, var(--bg3) 80px);
    background-size: 800px 100%;
    animation: shimmer 1.4s linear infinite;
  }}
  .skeleton-line {{ height: 14px; margin-bottom: 10px; }}
  .skeleton-card {{ height: 110px; border-radius: var(--radius); }}
  
  /* RESPONSIVE */
  @media (max-width: 768px) {{
    .sidebar {{ transform: translateX(100%); }}
    .sidebar.open {{ transform: translateX(0); }}
    .main {{ margin-right: 0; }}
    .grid-2 {{ grid-template-columns: 1fr; }}
    .health-grid {{ grid-template-columns: 1fr; }}
    .content {{ padding: 16px; }}
    .topbar {{ padding: 12px 16px; }}
    .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
  }}
  
  .mobile-menu-btn {{
    display: none;
    background: none;
    border: none;
    color: var(--text);
    font-size: 20px;
    cursor: pointer;
    padding: 4px;
  }}
  @media (max-width: 768px) {{ .mobile-menu-btn {{ display: flex; }} }}
  
  .sidebar-overlay {{
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.5);
    z-index: 99;
  }}
  .sidebar-overlay.active {{ display: block; }}
  
  /* FLAG EMOJI */
  .flag {{ font-style: normal; margin-left: 4px; }}
  
  /* IP TABLE */
  .ip-chip {{
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 3px 10px;
    font-family: monospace;
    font-size: 12px;
    color: var(--accent3);
  }}
</style>
</head>
<body>

{"" if is_auth else '<div id="login-wrapper"></div>'}
{"" if not is_auth else '<div id="app-wrapper"></div>'}

<div class="toast-container" id="toast-container"></div>

<script>
const IS_AUTH = {'true' if is_auth else 'false'};

// ─── THEME ──────────────────────────────────────────────────────────────────
function apply_theme(theme) {{
  document.documentElement.setAttribute('data-theme', theme === 'light' ? 'light' : 'dark');
  const btn = document.getElementById('theme-toggle-btn');
  if (btn) btn.innerHTML = theme === 'light' ? '<i class="fa fa-sun"></i>' : '<i class="fa fa-moon"></i>';
}}
function toggle_theme() {{
  const current = localStorage.getItem('panel-theme') || 'dark';
  const next = current === 'light' ? 'dark' : 'light';
  localStorage.setItem('panel-theme', next);
  apply_theme(next);
}}
apply_theme(localStorage.getItem('panel-theme') || 'dark');

// ─── UTILITIES ────────────────────────────────────────────────────────────────
function toast(msg, type='success') {{
  const c = document.getElementById('toast-container');
  const t = document.createElement('div');
  t.className = `toast ${{type}}`;
  t.innerHTML = `<span class="toast-icon ${{type}}"><i class="fa ${{type==='success'?'fa-check-circle':'fa-exclamation-circle'}}"></i></span><span>${{msg}}</span>`;
  c.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}}

async function api(method, path, body=null) {{
  const opts = {{ method, headers: {{'Content-Type':'application/json'}} }};
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(path, opts);
  if (!r.ok) {{
    const e = await r.json().catch(() => ({{detail:'خطا'}}));
    throw new Error(e.detail || 'خطا');
  }}
  return r.json();
}}

function confirm_dialog(msg) {{
  return new Promise(res => {{
    const ok = window.confirm(msg);
    res(ok);
  }});
}}

function copy_text(text) {{
  navigator.clipboard.writeText(text).then(() => toast('کپی شد ✓')).catch(() => {{
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
    toast('کپی شد ✓');
  }});
}}

function format_bytes(b) {{
  if (!b) return '0 B';
  const u = ['B','KB','MB','GB','TB'];
  let i = 0;
  while (b >= 1024 && i < u.length-1) {{ b /= 1024; i++; }}
  return b.toFixed(2) + ' ' + u[i];
}}

function format_date(s) {{
  if (!s) return '—';
  const d = new Date(s);
  return d.toLocaleDateString('fa-IR', {{ year:'numeric', month:'short', day:'numeric' }});
}}

function days_left(expire_at) {{
  if (!expire_at) return null;
  const diff = new Date(expire_at) - new Date();
  return Math.ceil(diff / 86400000);
}}

// ─── LOGIN PAGE ───────────────────────────────────────────────────────────────
function render_login() {{
  document.getElementById('login-wrapper').innerHTML = `
  <div class="login-page">
    <div class="login-card">
      <div class="login-logo">
        <div class="icon">⚡</div>
        <h1>IranX Panel</h1>
        <p>مدیریت اشتراک VLESS</p>
      </div>
      <form id="login-form">
        <div class="form-group">
          <label>نام کاربری</label>
          <input name="username" type="text" placeholder="admin" required autocomplete="username">
        </div>
        <div class="form-group">
          <label>رمز عبور</label>
          <input name="password" type="password" placeholder="••••••••" required autocomplete="current-password">
        </div>
        <button type="submit" class="btn btn-primary btn-full" id="login-btn">
          <i class="fa fa-sign-in-alt"></i> ورود به پنل
        </button>
      </form>
    </div>
  </div>`;
  
  document.getElementById('login-form').onsubmit = async (e) => {{
    e.preventDefault();
    const btn = document.getElementById('login-btn');
    btn.disabled = true;
    btn.innerHTML = '<i class="fa fa-spinner spin"></i> در حال ورود...';
    const fd = new FormData(e.target);
    try {{
      const r = await fetch('/api/login', {{ method:'POST', body: fd }});
      if (r.ok) {{ window.location.reload(); }}
      else {{
        const err = await r.json();
        toast(err.detail || 'خطا در ورود', 'error');
        btn.disabled = false;
        btn.innerHTML = '<i class="fa fa-sign-in-alt"></i> ورود به پنل';
      }}
    }} catch(e) {{
      toast('خطا در اتصال', 'error');
      btn.disabled = false;
      btn.innerHTML = '<i class="fa fa-sign-in-alt"></i> ورود به پنل';
    }}
  }};
}}

// ─── MAIN APP ─────────────────────────────────────────────────────────────────
let current_page = 'dashboard';
let users_data = [];
let ips_data = [];
let charts = {{}};

function render_app() {{
  document.getElementById('app-wrapper').innerHTML = `
  <div class="sidebar-overlay" id="sidebar-overlay" onclick="toggle_sidebar()"></div>
  <div class="app">
    <aside class="sidebar" id="sidebar">
      <div class="sidebar-logo">
        <div class="logo-icon">⚡</div>
        <div>
          <h2>IranX Panel</h2>
          <small>v{PANEL_VERSION}</small>
        </div>
      </div>
      <nav class="sidebar-nav">
        <div class="nav-section">
          <div class="nav-section-title">منو</div>
          <div class="nav-item active" data-page="dashboard" onclick="navigate('dashboard')">
            <span class="nav-icon"><i class="fa fa-chart-line"></i></span> داشبورد
          </div>
          <div class="nav-item" data-page="users" onclick="navigate('users')">
            <span class="nav-icon"><i class="fa fa-users"></i></span> کاربران
          </div>
          <div class="nav-item" data-page="ips" onclick="navigate('ips')">
            <span class="nav-icon"><i class="fa fa-network-wired"></i></span> IP / دامنه تمیز
          </div>
          <div class="nav-item" data-page="settings" onclick="navigate('settings')">
            <span class="nav-icon"><i class="fa fa-cog"></i></span> تنظیمات
          </div>
        </div>
      </nav>
      <div class="sidebar-footer">
        <div class="user-info">
          <div class="user-avatar">A</div>
          <div>
            <div class="user-name">Admin</div>
            <div class="user-role">مدیر سیستم</div>
          </div>
          <button onclick="logout()" class="btn btn-danger btn-sm" style="margin-right:auto" title="خروج">
            <i class="fa fa-sign-out-alt"></i>
          </button>
        </div>
      </div>
    </aside>
    
    <main class="main">
      <div class="topbar">
        <button class="mobile-menu-btn" onclick="toggle_sidebar()"><i class="fa fa-bars"></i></button>
        <div>
          <div class="topbar-title" id="page-title">داشبورد</div>
          <div class="topbar-subtitle" id="page-subtitle">خوش آمدید</div>
        </div>
        <div class="topbar-actions">
          <button class="btn btn-secondary btn-sm" id="theme-toggle-btn" onclick="toggle_theme()" title="تغییر تم">
            <i class="fa fa-moon"></i>
          </button>
          <button class="btn btn-secondary btn-sm" onclick="refresh_page()">
            <i class="fa fa-sync"></i>
          </button>
        </div>
      </div>
      
      <div class="content">
        <div id="page-dashboard" class="page active"></div>
        <div id="page-users" class="page"></div>
        <div id="page-ips" class="page"></div>
        <div id="page-settings" class="page"></div>
      </div>
    </main>
  </div>`;
  
  render_dashboard();
  navigate('dashboard');
}}

function toggle_sidebar() {{
  document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('sidebar-overlay').classList.toggle('active');
}}

async function logout() {{
  await fetch('/api/logout', {{method:'POST'}});
  window.location.reload();
}}

function navigate(page) {{
  current_page = page;
  document.querySelectorAll('.nav-item').forEach(el => {{
    el.classList.toggle('active', el.dataset.page === page);
  }});
  document.querySelectorAll('.page').forEach(el => {{
    el.classList.toggle('active', el.id === 'page-' + page);
  }});
  const titles = {{
    dashboard: ['داشبورد', 'وضعیت کلی سیستم'],
    users: ['کاربران', 'مدیریت کاربران و اشتراک‌ها'],
    ips: ['IP / دامنه تمیز', 'مدیریت آدرس‌های IP و دامنه'],
    settings: ['تنظیمات', 'پیکربندی پنل']
  }};
  document.getElementById('page-title').textContent = titles[page]?.[0] || page;
  document.getElementById('page-subtitle').textContent = titles[page]?.[1] || '';
  
  // Close mobile sidebar
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebar-overlay').classList.remove('active');
  
  if (page === 'dashboard') render_dashboard();
  else if (page === 'users') render_users();
  else if (page === 'ips') render_ips();
  else if (page === 'settings') render_settings();
}}

function refresh_page() {{ navigate(current_page); }}

function animate_counters(scope) {{
  const els = (scope || document).querySelectorAll('.stat-value[data-count]');
  els.forEach(el => {{
    const raw = el.dataset.count;
    const target = parseFloat(raw) || 0;
    const decimals = raw.includes('.') ? raw.split('.')[1].length : 0;
    const duration = 700;
    const start = performance.now();
    function tick(now) {{
      const p = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = (target * eased).toFixed(decimals);
      if (p < 1) requestAnimationFrame(tick);
      else el.textContent = target.toFixed(decimals);
    }}
    requestAnimationFrame(tick);
  }});
}}

// ─── DASHBOARD ─────────────────────────────────────────────────────────────
async function render_dashboard() {{
  const el = document.getElementById('page-dashboard');
  el.innerHTML = `<div class="stats-grid">${{Array(6).fill(0).map(()=>`<div class="skeleton skeleton-card"></div>`).join('')}}</div>
    <div class="grid-2"><div class="skeleton" style="height:280px;border-radius:16px"></div><div class="skeleton" style="height:280px;border-radius:16px"></div></div>`;
  
  try {{
    const stats = await api('GET', '/api/stats');
    const sys = stats.system || {{}};
    
    el.innerHTML = `
    <div class="stats-grid">
      <div class="stat-card accent">
        <div class="stat-icon accent"><i class="fa fa-users"></i></div>
        <div class="stat-value" data-count="${{stats.total_users}}">0</div>
        <div class="stat-label">کل کاربران</div>
      </div>
      <div class="stat-card green">
        <div class="stat-icon green"><i class="fa fa-user-check"></i></div>
        <div class="stat-value" data-count="${{stats.active_users}}">0</div>
        <div class="stat-label">کاربران فعال</div>
      </div>
      <div class="stat-card red">
        <div class="stat-icon red"><i class="fa fa-user-times"></i></div>
        <div class="stat-value" data-count="${{stats.inactive_users}}">0</div>
        <div class="stat-label">کاربران غیرفعال</div>
      </div>
      <div class="stat-card yellow">
        <div class="stat-icon yellow"><i class="fa fa-clock"></i></div>
        <div class="stat-value" data-count="${{stats.expiring_soon}}">0</div>
        <div class="stat-label">در حال انقضا</div>
        <div class="stat-sub">۳ روز آینده</div>
      </div>
      <div class="stat-card blue">
        <div class="stat-icon blue"><i class="fa fa-database"></i></div>
        <div class="stat-value" data-count="${{stats.total_traffic_gb.toFixed(1)}}">0</div>
        <div class="stat-label">کل ترافیک مصرفی (GB)</div>
      </div>
      <div class="stat-card accent">
        <div class="stat-icon accent"><i class="fa fa-network-wired"></i></div>
        <div class="stat-value" data-count="${{stats.active_ips}}">0</div>
        <div class="stat-label">IP فعال</div>
      </div>
    </div>
    
    <div class="grid-2">
      <div class="card">
        <div class="card-title"><i class="fa fa-heartbeat" style="color:var(--green)"></i> سلامت سیستم</div>
        <div class="health-grid">
          <div class="health-item">
            <div class="health-circle" style="background: conic-gradient(#6366f1 ${{sys.cpu||0}}%, var(--bg3) 0%)">
              <span>${{(sys.cpu||0).toFixed(0)}}%</span>
            </div>
            <div class="health-label">CPU</div>
          </div>
          <div class="health-item">
            <div class="health-circle" style="background: conic-gradient(#10b981 ${{sys.mem_percent||0}}%, var(--bg3) 0%)">
              <span>${{(sys.mem_percent||0).toFixed(0)}}%</span>
            </div>
            <div class="health-label">RAM</div>
          </div>
          <div class="health-item">
            <div class="health-circle" style="background: conic-gradient(#f59e0b ${{sys.disk_percent||0}}%, var(--bg3) 0%)">
              <span>${{(sys.disk_percent||0).toFixed(0)}}%</span>
            </div>
            <div class="health-label">Disk</div>
          </div>
        </div>
        <div style="margin-top:20px;display:grid;grid-template-columns:1fr 1fr;gap:12px">
          <div style="background:var(--bg3);padding:12px;border-radius:8px;font-size:13px">
            <div style="color:var(--text2);margin-bottom:4px">RAM</div>
            <div>${{sys.mem_used_gb||0}} / ${{sys.mem_total_gb||0}} GB</div>
          </div>
          <div style="background:var(--bg3);padding:12px;border-radius:8px;font-size:13px">
            <div style="color:var(--text2);margin-bottom:4px">Disk</div>
            <div>${{sys.disk_used_gb||0}} / ${{sys.disk_total_gb||0}} GB</div>
          </div>
          <div style="background:var(--bg3);padding:12px;border-radius:8px;font-size:13px">
            <div style="color:var(--text2);margin-bottom:4px">ارسال شبکه</div>
            <div>${{sys.net_sent_gb||0}} GB</div>
          </div>
          <div style="background:var(--bg3);padding:12px;border-radius:8px;font-size:13px">
            <div style="color:var(--text2);margin-bottom:4px">دریافت شبکه</div>
            <div>${{sys.net_recv_gb||0}} GB</div>
          </div>
        </div>
      </div>
      
      <div class="card">
        <div class="card-title"><i class="fa fa-chart-pie" style="color:var(--accent)"></i> توزیع کاربران</div>
        <div class="chart-container">
          <canvas id="users-chart"></canvas>
        </div>
      </div>
    </div>
    
    <div class="card">
      <div class="card-title"><i class="fa fa-list" style="color:var(--blue)"></i> کاربران اخیر</div>
      <div id="recent-users-table"></div>
    </div>`;
    
    // Chart
    const ctx = document.getElementById('users-chart');
    if (ctx) {{
      if (charts.users) charts.users.destroy();
      charts.users = new Chart(ctx, {{
        type: 'doughnut',
        data: {{
          labels: ['فعال', 'غیرفعال', 'در حال انقضا'],
          datasets: [{{ 
            data: [stats.active_users, stats.inactive_users, stats.expiring_soon],
            backgroundColor: ['#10b981','#ef4444','#f59e0b'],
            borderWidth: 0,
            hoverOffset: 8
          }}]
        }},
        options: {{
          responsive: true, maintainAspectRatio: false,
          plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#94a3b8', padding: 16 }} }} }},
          cutout: '65%'
        }}
      }});
    }}
    
    // Recent users
    const users = await api('GET', '/api/users');
    users_data = users;
    const recent = users.slice(0, 5);
    const rtd = document.getElementById('recent-users-table');
    if (recent.length === 0) {{
      rtd.innerHTML = '<div class="empty-state"><div class="empty-icon">👥</div><h3>کاربری وجود ندارد</h3></div>';
    }} else {{
      rtd.innerHTML = `
      <div class="table-wrapper">
      <table>
        <thead><tr>
          <th>نام</th><th>ترافیک</th><th>انقضا</th><th>وضعیت</th>
        </tr></thead>
        <tbody>
          ${{recent.map(u => `
          <tr>
            <td><span class="flag">${{u.flag}}</span>${{u.name}}</td>
            <td>
              <div>${{u.used_traffic_gb}} / ${{u.traffic_limit_gb||'∞'}} GB</div>
              <div class="progress"><div class="progress-bar ${{u.traffic_percent<60?'green':u.traffic_percent<85?'yellow':'red'}}" style="width:${{u.traffic_percent}}%"></div></div>
            </td>
            <td>${{format_date(u.expire_at)}}</td>
            <td><span class="badge ${{u.is_active?'badge-green':'badge-red'}}">${{u.is_active?'✓ فعال':'✗ غیرفعال'}}</span></td>
          </tr>`).join('')}}
        </tbody>
      </table>
      </div>`;
    }}
    
    animate_counters(el);
    
  }} catch(e) {{
    el.innerHTML = `<div class="card"><p style="color:var(--red)">${{e.message}}</p></div>`;
  }}
}}

// ─── USERS PAGE ─────────────────────────────────────────────────────────────
async function render_users() {{
  const el = document.getElementById('page-users');
  el.innerHTML = `
  <div class="card" style="margin-bottom:20px">
    <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
      <div class="search-bar">
        <i class="fa fa-search search-icon"></i>
        <input type="text" id="users-search" placeholder="جستجو در کاربران..." oninput="filter_users()">
      </div>
      <button class="btn btn-primary" onclick="show_add_user_modal()">
        <i class="fa fa-plus"></i> کاربر جدید
      </button>
    </div>
  </div>
  <div class="card">
    <div id="users-table-wrapper"><div style="text-align:center;padding:40px;color:var(--text2)"><i class="fa fa-spinner spin fa-2x"></i></div></div>
  </div>`;
  
  await load_users();
}}

let users_filtered = [];

async function load_users() {{
  try {{
    users_data = await api('GET', '/api/users');
    users_filtered = [...users_data];
    render_users_table();
  }} catch(e) {{
    toast(e.message, 'error');
  }}
}}

function filter_users() {{
  const q = document.getElementById('users-search')?.value?.toLowerCase() || '';
  users_filtered = users_data.filter(u => u.name.toLowerCase().includes(q) || u.uuid.includes(q) || (u.email||'').toLowerCase().includes(q));
  render_users_table();
}}

function render_users_table() {{
  const el = document.getElementById('users-table-wrapper');
  if (!el) return;
  if (users_filtered.length === 0) {{
    el.innerHTML = `<div class="empty-state"><div class="empty-icon">👥</div><h3>کاربری یافت نشد</h3><p>کاربر جدید اضافه کنید</p></div>`;
    return;
  }}
  el.innerHTML = `
  <div class="table-wrapper">
  <table>
    <thead><tr>
      <th>نام</th><th>UUID</th><th>ترافیک</th><th>انقضا</th><th>وضعیت</th><th>عملیات</th>
    </tr></thead>
    <tbody>
      ${{users_filtered.map(u => {{
        const dl = days_left(u.expire_at);
        const dl_badge = dl === null ? '' : dl <= 0 ? '<span class="badge badge-red">منقضی</span>' : dl <= 3 ? `<span class="badge badge-yellow">${{dl}} روز</span>` : `<span class="badge badge-green">${{dl}} روز</span>`;
        return `<tr>
          <td>
            <div style="display:flex;align-items:center;gap:8px">
              <div style="width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,#6366f1,#10b981);display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px;flex-shrink:0">${{u.name[0].toUpperCase()}}</div>
              <div>
                <div style="font-weight:600"><span class="flag">${{u.flag}}</span>${{u.name}}</div>
                ${{u.email ? `<div style="font-size:11px;color:var(--text3)">${{u.email}}</div>` : ''}}
              </div>
            </div>
          </td>
          <td>
            <div style="display:flex;align-items:center;gap:6px">
              <code style="font-size:11px;color:var(--text3)">${{u.uuid.substring(0,8)}}...</code>
              <button class="copy-btn" onclick="copy_text('${{u.uuid}}')" title="کپی UUID"><i class="fa fa-copy"></i></button>
            </div>
          </td>
          <td>
            <div style="min-width:120px">
              <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px">
                <span>${{u.used_traffic_gb}} GB</span>
                <span style="color:var(--text3)">${{u.traffic_limit_gb > 0 ? u.traffic_limit_gb + ' GB' : '∞'}}</span>
              </div>
              <div class="progress">
                <div class="progress-bar ${{u.traffic_percent<60?'green':u.traffic_percent<85?'yellow':'red'}}" style="width:${{u.traffic_percent}}%"></div>
              </div>
            </div>
          </td>
          <td>${{dl_badge}} ${{format_date(u.expire_at)}}</td>
          <td>
            <label class="toggle">
              <input type="checkbox" ${{u.is_active?'checked':''}} onchange="toggle_user('${{u.uuid}}',this)">
              <span class="toggle-slider"></span>
            </label>
          </td>
          <td>
            <div style="display:flex;gap:6px;flex-wrap:wrap">
              <button class="btn btn-secondary btn-sm" onclick="show_sub_link('${{u.uuid}}','${{u.name}}')" title="لینک اشتراک"><i class="fa fa-link"></i></button>
              <button class="btn btn-warning btn-sm" onclick="reset_traffic('${{u.uuid}}','${{u.name}}')" title="ریست ترافیک"><i class="fa fa-redo"></i></button>
              <button class="btn btn-success btn-sm" onclick="show_edit_user_modal('${{u.uuid}}')" title="ویرایش"><i class="fa fa-edit"></i></button>
              <button class="btn btn-danger btn-sm" onclick="delete_user('${{u.uuid}}','${{u.name}}')" title="حذف"><i class="fa fa-trash"></i></button>
            </div>
          </td>
        </tr>`;
      }}).join('')}}
    </tbody>
  </table>
  </div>`;
}}

// Add user modal
function show_add_user_modal() {{
  show_user_modal(null);
}}

async function show_edit_user_modal(uuid) {{
  const user = users_data.find(u => u.uuid === uuid);
  if (!user) return;
  show_user_modal(user);
}}

function show_user_modal(user) {{
  const is_edit = !!user;
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
  <div class="modal">
    <div class="modal-header">
      <div class="modal-title">${{is_edit ? '✏️ ویرایش کاربر' : '➕ کاربر جدید'}}</div>
      <button class="modal-close" onclick="this.closest('.modal-overlay').remove()"><i class="fa fa-times"></i></button>
    </div>
    <div class="modal-body">
      <div class="grid-2">
        <div class="form-group">
          <label>نام کاربر *</label>
          <input id="m-name" type="text" value="${{user?.name||''}}" placeholder="Ali">
        </div>
        <div class="form-group">
          <label>ایمیل</label>
          <input id="m-email" type="email" value="${{user?.email||''}}" placeholder="ali@example.com">
        </div>
      </div>
      <div class="grid-2">
        <div class="form-group">
          <label>حجم ترافیک (GB) — 0 = نامحدود</label>
          <input id="m-traffic" type="number" value="${{user?.traffic_limit_gb||0}}" min="0" step="0.5">
        </div>
        <div class="form-group">
          <label>مدت اشتراک (روز) — 0 = بدون انقضا</label>
          <input id="m-expire" type="number" value="${{user?.expire_days||0}}" min="0">
        </div>
      </div>
      <div class="grid-2">
        <div class="form-group">
          <label>حداکثر اتصال همزمان — 0 = نامحدود</label>
          <input id="m-conn" type="number" value="${{user?.max_connections||0}}" min="0">
        </div>
        <div class="form-group">
          <label>پرچم کشور (ایموجی)</label>
          <input id="m-flag" type="text" value="${{user?.flag||''}}" placeholder="🇩🇪">
        </div>
      </div>
      <div class="form-group">
        <label>یادداشت</label>
        <textarea id="m-note">${{user?.note||''}}</textarea>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-secondary" onclick="this.closest('.modal-overlay').remove()">انصراف</button>
      <button class="btn btn-primary" onclick="save_user('${{user?.uuid||''}}')">
        <i class="fa fa-save"></i> ${{is_edit ? 'ذخیره' : 'ایجاد'}}
      </button>
    </div>
  </div>`;
  document.body.appendChild(overlay);
}}

async function save_user(uuid) {{
  const data = {{
    name: document.getElementById('m-name').value.trim(),
    email: document.getElementById('m-email').value.trim(),
    traffic_limit_gb: parseFloat(document.getElementById('m-traffic').value)||0,
    expire_days: parseInt(document.getElementById('m-expire').value)||0,
    max_connections: parseInt(document.getElementById('m-conn').value)||0,
    flag: document.getElementById('m-flag').value.trim(),
    note: document.getElementById('m-note').value.trim(),
    is_active: 1,
  }};
  if (!data.name) {{ toast('نام الزامی است','error'); return; }}
  try {{
    if (uuid) {{ await api('PUT', `/api/users/${{uuid}}`, data); toast('کاربر ویرایش شد'); }}
    else {{ await api('POST', '/api/users', data); toast('کاربر ایجاد شد'); }}
    document.querySelector('.modal-overlay')?.remove();
    await load_users();
  }} catch(e) {{ toast(e.message,'error'); }}
}}

async function toggle_user(uuid, el) {{
  try {{
    await api('POST', `/api/users/${{uuid}}/toggle`);
    toast(el.checked ? 'کاربر فعال شد' : 'کاربر غیرفعال شد');
    await load_users();
  }} catch(e) {{ toast(e.message,'error'); el.checked = !el.checked; }}
}}

async function reset_traffic(uuid, name) {{
  if (!await confirm_dialog(`ترافیک ${{name}} ریست شود؟`)) return;
  try {{
    await api('POST', `/api/users/${{uuid}}/reset-traffic`);
    toast('ترافیک ریست شد');
    await load_users();
  }} catch(e) {{ toast(e.message,'error'); }}
}}

async function delete_user(uuid, name) {{
  if (!await confirm_dialog(`کاربر ${{name}} حذف شود؟`)) return;
  try {{
    await api('DELETE', `/api/users/${{uuid}}`);
    toast('کاربر حذف شد');
    await load_users();
  }} catch(e) {{ toast(e.message,'error'); }}
}}

async function show_sub_link(uuid, name) {{
  try {{
    const data = await api('GET', `/api/users/${{uuid}}/sub-link`);
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `
    <div class="modal">
      <div class="modal-header">
        <div class="modal-title">🔗 لینک اشتراک — ${{name}}</div>
        <button class="modal-close" onclick="this.closest('.modal-overlay').remove()"><i class="fa fa-times"></i></button>
      </div>
      <div class="modal-body">
        <div class="form-group">
          <label>لینک اشتراک (Subscription URL)</label>
          <div class="code-block">
            <span class="code-text">${{data.sub_link}}</span>
            <button class="copy-btn" onclick="copy_text('${{data.sub_link}}')"><i class="fa fa-copy fa-lg"></i></button>
          </div>
        </div>
        <div class="form-group">
          <label>لینک VLESS مستقیم</label>
          <div class="code-block">
            <span class="code-text" style="font-size:11px;word-break:break-all">${{data.vless_link}}</span>
            <button class="copy-btn" onclick="copy_text('${{data.vless_link}}')"><i class="fa fa-copy fa-lg"></i></button>
          </div>
        </div>
        <div style="background:rgba(99,102,241,0.1);border:1px solid rgba(99,102,241,0.2);border-radius:8px;padding:12px;font-size:13px;color:var(--text2)">
          <i class="fa fa-info-circle" style="color:var(--accent)"></i>
          لینک اشتراک را در کلاینت‌هایی مثل v2rayNG، Nekobox یا هشت‌پا وارد کنید.
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" onclick="this.closest('.modal-overlay').remove()">بستن</button>
        <button class="btn btn-primary" onclick="copy_text('${{data.sub_link}}')"><i class="fa fa-copy"></i> کپی لینک</button>
      </div>
    </div>`;
    document.body.appendChild(overlay);
  }} catch(e) {{ toast(e.message,'error'); }}
}}

// ─── IPs PAGE ──────────────────────────────────────────────────────────────
async function render_ips() {{
  const el = document.getElementById('page-ips');
  el.innerHTML = `
  <div class="card" style="margin-bottom:20px">
    <div style="display:flex;gap:12px;flex-wrap:wrap">
      <button class="btn btn-primary" onclick="show_add_ip_modal()"><i class="fa fa-plus"></i> افزودن IP / دامنه</button>
      <button class="btn btn-secondary" onclick="show_bulk_ip_modal()"><i class="fa fa-list"></i> افزودن انبوه</button>
    </div>
  </div>
  <div class="card">
    <div class="card-title"><i class="fa fa-network-wired" style="color:var(--blue)"></i> آدرس‌های تمیز ثبت شده</div>
    <div id="ips-table-wrapper"><div style="text-align:center;padding:40px;color:var(--text2)"><i class="fa fa-spinner spin fa-2x"></i></div></div>
  </div>`;
  await load_ips();
}}

async function load_ips() {{
  try {{
    ips_data = await api('GET', '/api/ips');
    render_ips_table();
  }} catch(e) {{ toast(e.message,'error'); }}
}}

function render_ips_table() {{
  const el = document.getElementById('ips-table-wrapper');
  if (!el) return;
  if (ips_data.length === 0) {{
    el.innerHTML = `<div class="empty-state"><div class="empty-icon">🌐</div><h3>آدرسی وجود ندارد</h3><p>IP یا دامنه تمیز اضافه کنید تا در لینک‌های اشتراک استفاده شوند</p></div>`;
    return;
  }}
  el.innerHTML = `
  <div class="table-wrapper">
  <table>
    <thead><tr><th>نوع</th><th>آدرس</th><th>برچسب</th><th>تاریخ افزوده</th><th>وضعیت</th><th>عملیات</th></tr></thead>
    <tbody>
      ${{ips_data.map(ip => `<tr>
        <td>${{ip.type==='domain'?'<span class="badge badge-purple"><i class="fa fa-globe"></i> دامنه</span>':'<span class="badge badge-blue"><i class="fa fa-server"></i> IP</span>'}}</td>
        <td><span class="ip-chip">${{ip.ip}}</span></td>
        <td>${{ip.label || '<span style="color:var(--text3)">—</span>'}}</td>
        <td>${{format_date(ip.added_at)}}</td>
        <td><label class="toggle"><input type="checkbox" ${{ip.is_active?'checked':''}} onchange="toggle_ip(${{ip.id}},this)"><span class="toggle-slider"></span></label></td>
        <td>
          <div style="display:flex;gap:6px">
            <button class="btn btn-secondary btn-sm" onclick="copy_text('${{ip.ip}}')" title="کپی"><i class="fa fa-copy"></i></button>
            <button class="btn btn-danger btn-sm" onclick="delete_ip(${{ip.id}},'${{ip.ip}}')" title="حذف"><i class="fa fa-trash"></i></button>
          </div>
        </td>
      </tr>`).join('')}}
    </tbody>
  </table>
  </div>`;
}}

function show_add_ip_modal() {{
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
  <div class="modal">
    <div class="modal-header">
      <div class="modal-title">➕ افزودن IP / دامنه تمیز</div>
      <button class="modal-close" onclick="this.closest('.modal-overlay').remove()"><i class="fa fa-times"></i></button>
    </div>
    <div class="modal-body">
      <div class="form-group"><label>نوع</label>
        <select id="ip-type">
          <option value="ip">آدرس IP</option>
          <option value="domain">دامنه</option>
        </select>
      </div>
      <div class="form-group"><label>آدرس *</label><input id="ip-addr" type="text" placeholder="1.2.3.4 یا clean.example.com" dir="ltr"></div>
      <div class="form-group"><label>برچسب (اختیاری)</label><input id="ip-label" type="text" placeholder="فرانکفورت"></div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-secondary" onclick="this.closest('.modal-overlay').remove()">انصراف</button>
      <button class="btn btn-primary" onclick="add_ip()"><i class="fa fa-save"></i> ذخیره</button>
    </div>
  </div>`;
  document.body.appendChild(overlay);
}}

async function add_ip() {{
  const ip = document.getElementById('ip-addr')?.value?.trim();
  const label = document.getElementById('ip-label')?.value?.trim() || '';
  const type = document.getElementById('ip-type')?.value || 'ip';
  if (!ip) {{ toast('آدرس الزامی است','error'); return; }}
  try {{
    await api('POST', '/api/ips', {{ip, label, type}});
    toast('آدرس اضافه شد');
    document.querySelector('.modal-overlay')?.remove();
    await load_ips();
  }} catch(e) {{ toast(e.message,'error'); }}
}}

function show_bulk_ip_modal() {{
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
  <div class="modal">
    <div class="modal-header">
      <div class="modal-title">📋 افزودن انبوه IP / دامنه</div>
      <button class="modal-close" onclick="this.closest('.modal-overlay').remove()"><i class="fa fa-times"></i></button>
    </div>
    <div class="modal-body">
      <div class="form-group">
        <label>آدرس‌ها (هر خط یک IP یا دامنه)</label>
        <textarea id="bulk-ips" placeholder="1.2.3.4 آلمان&#10;clean.example.com هلند&#10;9.10.11.12" style="min-height:150px;direction:ltr"></textarea>
        <small style="color:var(--text3);font-size:12px;margin-top:4px;display:block">فرمت: آدرس فضا برچسب (برچسب اختیاری است) — نوع (IP یا دامنه) به‌صورت خودکار تشخیص داده میشه</small>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-secondary" onclick="this.closest('.modal-overlay').remove()">انصراف</button>
      <button class="btn btn-primary" onclick="bulk_add_ips()"><i class="fa fa-upload"></i> افزودن همه</button>
    </div>
  </div>`;
  document.body.appendChild(overlay);
}}

async function bulk_add_ips() {{
  const ips = document.getElementById('bulk-ips')?.value || '';
  try {{
    const r = await api('POST', '/api/ips/bulk', {{ips}});
    toast(`${{r.added}} IP اضافه شد`);
    document.querySelector('.modal-overlay')?.remove();
    await load_ips();
  }} catch(e) {{ toast(e.message,'error'); }}
}}

async function toggle_ip(id, el) {{
  try {{
    await api('POST', `/api/ips/${{id}}/toggle`);
    toast(el.checked ? 'IP فعال شد' : 'IP غیرفعال شد');
    await load_ips();
  }} catch(e) {{ toast(e.message,'error'); el.checked = !el.checked; }}
}}

async function delete_ip(id, ip) {{
  if (!await confirm_dialog(`IP ${{ip}} حذف شود؟`)) return;
  try {{
    await api('DELETE', `/api/ips/${{id}}`);
    toast('IP حذف شد');
    await load_ips();
  }} catch(e) {{ toast(e.message,'error'); }}
}}

// ─── SETTINGS PAGE ──────────────────────────────────────────────────────────
async function render_settings() {{
  const el = document.getElementById('page-settings');
  el.innerHTML = `<div style="text-align:center;padding:40px;color:var(--text2)"><i class="fa fa-spinner spin fa-2x"></i></div>`;
  
  try {{
    const s = await api('GET', '/api/settings');
    
    el.innerHTML = `
    <div class="grid-2">
      <div>
        <div class="card">
          <div class="card-title"><i class="fa fa-sliders-h" style="color:var(--accent)"></i> تنظیمات پنل</div>
          <div class="form-group"><label>عنوان پنل</label><input id="s-title" value="${{s.panel_title||'IranX Panel'}}"></div>
        </div>
        
        <div class="card">
          <div class="card-title"><i class="fa fa-network-wired" style="color:var(--blue)"></i> تنظیمات اتصال</div>
          <div class="form-group"><label>مسیر WebSocket</label><input id="s-wspath" value="${{s.ws_path||'/vless-ws'}}" dir="ltr"></div>
          <div class="form-group"><label>دامنه (DOMAIN)</label><input id="s-domain" value="${{s.sni||''}}" dir="ltr" placeholder="example.com"></div>
          <div class="form-group"><label>Host Header</label><input id="s-host" value="${{s.host_header||''}}" dir="ltr"></div>
          <div class="form-group"><label>TLS Fingerprint</label>
            <select id="s-fp">
              ${{['chrome','firefox','safari','ios','android','edge','360','qq'].map(v=>`<option value="${{v}}" ${{s.tls_fingerprint===v?'selected':''}}>${{v}}</option>`).join('')}}
            </select>
          </div>
          <div class="form-group"><label>Fragment (اختیاری)</label><input id="s-fragment" value="${{s.fragment||''}}" dir="ltr" placeholder="100-200"></div>
          <div class="form-group" style="display:flex;align-items:center;justify-content:space-between">
            <label style="margin:0">نمایش کانفیگ اطلاعاتی (حجم/زمان باقیمانده)</label>
            <label class="toggle"><input id="s-fakeinfo" type="checkbox" ${{s.fake_info_config!=='0'?'checked':''}}><span class="toggle-slider"></span></label>
          </div>
          <p style="font-size:12px;color:var(--text3);margin-top:-8px">یک کانفیگ نمایشی غیرفعال در ابتدای سابسکریپشن هر کاربر اضافه می‌شود که نام آن حجم و زمان باقیمانده را نشان می‌دهد.</p></div>
        
        <div class="card">
          <div class="card-title"><i class="fa fa-heartbeat" style="color:var(--green)"></i> Keep-Alive</div>
          <div class="form-group" style="display:flex;align-items:center;justify-content:space-between">
            <label style="margin:0">فعال‌سازی Keep-Alive</label>
            <label class="toggle"><input id="s-ka" type="checkbox" ${{s.keepalive_enabled==='1'?'checked':''}}><span class="toggle-slider"></span></label>
          </div>
          <div class="form-group"><label>فاصله زمانی (ثانیه)</label><input id="s-kai" type="number" value="${{s.keepalive_interval||300}}" min="60"></div>
          <div class="form-group"><label>حالت</label>
            <select id="s-kam">
              <option value="simple" ${{s.keepalive_mode==='simple'?'selected':''}}>Simple</option>
              <option value="advanced" ${{s.keepalive_mode==='advanced'?'selected':''}}>Advanced</option>
            </select>
          </div>
        </div>
      </div>
      
      <div>
        <div class="card">
          <div class="card-title"><i class="fa fa-paper-plane" style="color:var(--yellow)"></i> ربات تلگرام</div>
          <div class="form-group" style="display:flex;align-items:center;justify-content:space-between">
            <label style="margin:0">ارسال نوتیفیکیشن</label>
            <label class="toggle"><input id="s-tg" type="checkbox" ${{s.tg_enabled==='1'?'checked':''}}><span class="toggle-slider"></span></label>
          </div>
          <div class="form-group"><label>توکن ربات</label><input id="s-tgtoken" value="${{s.tg_bot_token||''}}" dir="ltr" placeholder="123456:ABC..."></div>
          <div class="form-group"><label>Chat ID</label><input id="s-tgchat" value="${{s.tg_chat_id||''}}" dir="ltr" placeholder="-100..."></div>
          <div class="form-group"><label>زبان پیام‌ها</label>
            <select id="s-tglang">
              <option value="fa" ${{s.tg_lang==='fa'?'selected':''}}>فارسی</option>
              <option value="en" ${{s.tg_lang==='en'?'selected':''}}>English</option>
            </select>
          </div>
          <button class="btn btn-secondary" onclick="test_telegram()"><i class="fa fa-paper-plane"></i> تست ارسال</button>
        </div>
        
        <div class="card">
          <div class="card-title"><i class="fa fa-info-circle" style="color:var(--text2)"></i> اطلاعات سیستم</div>
          <div style="display:grid;gap:12px">
            <div style="background:var(--bg3);padding:12px;border-radius:8px;font-size:13px">
              <span style="color:var(--text2)">نسخه پنل: </span><span style="color:var(--accent2);font-weight:600">v{PANEL_VERSION}</span>
            </div>
            <div style="background:var(--bg3);padding:12px;border-radius:8px;font-size:13px">
              <span style="color:var(--text2)">دامنه: </span><code style="color:var(--accent3)">{DOMAIN}</code>
            </div>
            <div style="background:var(--bg3);padding:12px;border-radius:8px;font-size:13px">
              <span style="color:var(--text2)">پروتکل: </span><span>VLESS + WS + TLS</span>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-title"><i class="fa fa-palette" style="color:var(--accent3)"></i> ظاهر پنل</div>
          <div class="form-group" style="margin-bottom:0">
            <label>تم پنل</label>
            <div style="display:flex;gap:10px">
              <button type="button" id="theme-opt-dark" class="btn btn-secondary" style="flex:1;justify-content:center" onclick="set_theme_option('dark')"><i class="fa fa-moon"></i> تیره</button>
              <button type="button" id="theme-opt-light" class="btn btn-secondary" style="flex:1;justify-content:center" onclick="set_theme_option('light')"><i class="fa fa-sun"></i> روشن</button>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-title"><i class="fa fa-shield-alt" style="color:var(--red)"></i> امنیت حساب</div>
          <div class="form-group"><label>رمز عبور فعلی</label><input id="s-cur-pass" type="password" dir="ltr" placeholder="••••••••"></div>
          <div class="form-group"><label>رمز عبور جدید</label><input id="s-new-pass" type="password" dir="ltr" placeholder="حداقل ۸ کاراکتر"></div>
          <div class="form-group"><label>تکرار رمز عبور جدید</label><input id="s-new-pass2" type="password" dir="ltr" placeholder="حداقل ۸ کاراکتر"></div>
          <button class="btn btn-danger" style="width:100%" onclick="change_password()"><i class="fa fa-key"></i> تغییر رمز عبور</button>
        </div>
        
        <button class="btn btn-primary" onclick="save_settings()" style="width:100%">
          <i class="fa fa-save"></i> ذخیره تنظیمات
        </button>
      </div>
    </div>`;
    set_theme_option(localStorage.getItem('panel-theme') || 'dark', true);
  }} catch(e) {{
    el.innerHTML = `<div class="card"><p style="color:var(--red)">${{e.message}}</p></div>`;
  }}
}}

function set_theme_option(theme, skip_apply) {{
  if (!skip_apply) {{
    localStorage.setItem('panel-theme', theme);
    apply_theme(theme);
  }}
  const d = document.getElementById('theme-opt-dark');
  const l = document.getElementById('theme-opt-light');
  if (d && l) {{
    d.classList.toggle('btn-primary', theme !== 'light');
    d.classList.toggle('btn-secondary', theme === 'light');
    l.classList.toggle('btn-primary', theme === 'light');
    l.classList.toggle('btn-secondary', theme !== 'light');
  }}
}}

async function change_password() {{
  const current_password = document.getElementById('s-cur-pass')?.value || '';
  const new_password = document.getElementById('s-new-pass')?.value || '';
  const new_password2 = document.getElementById('s-new-pass2')?.value || '';
  if (!current_password) {{ toast('رمز عبور فعلی را وارد کنید','error'); return; }}
  if (new_password.length < 8) {{ toast('رمز جدید باید حداقل ۸ کاراکتر باشد','error'); return; }}
  if (new_password !== new_password2) {{ toast('تکرار رمز عبور مطابقت ندارد','error'); return; }}
  try {{
    await api('POST', '/api/account/change-password', {{current_password, new_password}});
    toast('رمز عبور با موفقیت تغییر کرد ✓');
    document.getElementById('s-cur-pass').value = '';
    document.getElementById('s-new-pass').value = '';
    document.getElementById('s-new-pass2').value = '';
  }} catch(e) {{ toast(e.message,'error'); }}
}}

async function save_settings() {{
  try {{
    await api('POST', '/api/settings', {{
      panel_title: document.getElementById('s-title')?.value,
      ws_path: document.getElementById('s-wspath')?.value,
      sni: document.getElementById('s-domain')?.value,
      host_header: document.getElementById('s-host')?.value,
      tls_fingerprint: document.getElementById('s-fp')?.value,
      fragment: document.getElementById('s-fragment')?.value,
      fake_info_config: document.getElementById('s-fakeinfo')?.checked ? '1' : '0',
      keepalive_enabled: document.getElementById('s-ka')?.checked ? '1' : '0',
      keepalive_interval: document.getElementById('s-kai')?.value,
      keepalive_mode: document.getElementById('s-kam')?.value,
      tg_enabled: document.getElementById('s-tg')?.checked ? '1' : '0',
      tg_bot_token: document.getElementById('s-tgtoken')?.value,
      tg_chat_id: document.getElementById('s-tgchat')?.value,
      tg_lang: document.getElementById('s-tglang')?.value,
    }});
    toast('تنظیمات ذخیره شد ✓');
  }} catch(e) {{ toast(e.message,'error'); }}
}}

async function test_telegram() {{
  try {{
    await save_settings();
    await api('POST', '/api/settings', {{tg_enabled: '1'}});
    await fetch('/api/stats'); // trigger a ping
    toast('پیام تست ارسال شد (اگر توکن صحیح باشد)');
  }} catch(e) {{ toast(e.message,'error'); }}
}}

// ─── INIT ─────────────────────────────────────────────────────────────────
if (IS_AUTH) {{ render_app(); }}
else {{ render_login(); }}
</script>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=False)
