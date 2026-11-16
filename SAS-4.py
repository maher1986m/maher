"""SAS RADIUS server and NAS management API.

Run with:
    uvicorn SAS-4:app --host 0.0.0.0 --port 8000

The RADIUS listener starts with the API and listens on UDP 1812/1813.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import select
import socket
import sqlite3
import threading
import webbrowser
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import Cookie, FastAPI, Header, HTTPException, Response, status # type: ignore
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field # type: ignore
from pyrad import dictionary, packet, server # type: ignore


BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = Path(os.getenv("SAS_DATABASE", BASE_DIR / "sas.db"))
API_KEY = os.getenv("SAS_API_KEY", "change-this-api-key")
ADMIN_USERNAME = os.getenv("SAS_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("SAS_ADMIN_PASSWORD", "admin123")
RADIUS_DICTIONARY = Path(os.getenv("RADIUS_DICTIONARY", BASE_DIR / "dictionary"))
RADIUS_AUTH_PORT = int(os.getenv("RADIUS_AUTH_PORT", "1812"))
RADIUS_ACCT_PORT = int(os.getenv("RADIUS_ACCT_PORT", "1813"))
WEB_PORT = int(os.getenv("WEB_PORT", "8000"))
PUBLIC_WEB_HOST = os.getenv("SAS_PUBLIC_HOST", "127.0.0.1")

logging.basicConfig(level=os.getenv("SAS_LOG_LEVEL", "INFO"))
log = logging.getLogger("sas-radius")


@contextmanager
def db() -> Any:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def init_database() -> None:
    with db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS nas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                ip_address TEXT NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                activated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                expires_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS router_proxies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                host TEXT NOT NULL,
                service TEXT NOT NULL DEFAULT 'pppoe',
                api_port INTEGER NOT NULL DEFAULT 8728,
                api_username TEXT NOT NULL,
                api_password TEXT NOT NULL,
                location TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS router_pools (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                router_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                ranges TEXT NOT NULL,
                comment TEXT,
                remote_id TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(router_id, name),
                FOREIGN KEY(router_id) REFERENCES router_proxies(id) ON DELETE CASCADE
            );
            """
        )
        columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}
        if "activated_at" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN activated_at TEXT")
            connection.execute("UPDATE users SET activated_at = CURRENT_TIMESTAMP WHERE activated_at IS NULL")
        if "expires_at" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN expires_at TEXT")
        if "pool_name" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN pool_name TEXT")
        router_columns = {row[1] for row in connection.execute("PRAGMA table_info(router_proxies)")}
        if "radius_address" not in router_columns:
            connection.execute("ALTER TABLE router_proxies ADD COLUMN radius_address TEXT")
        if "radius_secret" not in router_columns:
            connection.execute("ALTER TABLE router_proxies ADD COLUMN radius_secret TEXT")


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000)
    return f"pbkdf2_sha256$210000${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt_hex, digest_hex = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds)
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def open_external_browser(url: str) -> None:
    """Open the dashboard in the operating system's default browser."""
    try:
        if os.name == "nt":
            os.startfile(url)  # type: ignore[attr-defined]
        else:
            webbrowser.open(url)
    except OSError:
        webbrowser.open(url)


class NASCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    ip_address: str
    secret: str = Field(min_length=8, max_length=128)


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)
    activation_months: int = Field(default=1, ge=1, le=36)
    pool_name: str | None = Field(default=None, max_length=80)


class RouterProxyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    host: str
    service: str = Field(default="pppoe", min_length=1, max_length=40)
    api_port: int = Field(default=8728, ge=1, le=65535)
    api_username: str = Field(min_length=1, max_length=80)
    api_password: str = Field(min_length=1, max_length=200)
    location: str | None = Field(default=None, max_length=80)
    radius_address: str = Field(min_length=1, max_length=80)
    radius_secret: str = Field(min_length=8, max_length=128)


class PoolCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    ranges: str = Field(min_length=1, max_length=500)
    comment: str | None = Field(default=None, max_length=200)


class LoginCreate(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)


class RadiusServer(server.Server):
    def __init__(self) -> None:
        super().__init__(
            addresses=["0.0.0.0"],
            dict=dictionary.Dictionary(str(RADIUS_DICTIONARY)),
            authport=RADIUS_AUTH_PORT,
            acctport=RADIUS_ACCT_PORT,
        )

    def reload_nas(self) -> None:
        with db() as connection:
            rows = connection.execute(
                "SELECT name, ip_address, secret FROM nas WHERE enabled = 1"
            ).fetchall()
        self.hosts.clear()
        for row in rows:
            self.hosts[row["ip_address"]] = server.RemoteHost(
                row["ip_address"], row["secret"].encode(), row["name"]
            )
        log.info("Loaded %d NAS device(s)", len(rows))

    def Run(self) -> None:
        """Run the RADIUS loop with select.select, which works on Windows."""
        # pyrad's default Run() uses select.poll(), unavailable on Windows.
        # Keep the socket classification that _ProcessInput() expects.
        self._realauthfds = [fd.fileno() for fd in self.authfds]
        self._realacctfds = [fd.fileno() for fd in self.acctfds]
        self._realcoafds = [fd.fileno() for fd in self.coafds]
        fdmap = {
            fd.fileno(): fd
            for fd in (*self.authfds, *self.acctfds, *self.coafds)
        }
        while True:
            readable, _, _ = select.select(list(fdmap.values()), [], [], 1.0)
            for fd in readable:
                try:
                    self._ProcessInput(fd)
                except Exception:
                    log.exception("Error processing RADIUS packet")

    def HandleAuthPacket(self, pkt: Any) -> None:
        username = str(pkt.get("User-Name", [""])[0])
        encrypted_password = pkt.get("User-Password", [b""])[0]
        supplied_password = pkt.PwDecrypt(encrypted_password) if encrypted_password else ""

        with db() as connection:
            row = connection.execute(
                "SELECT password_hash, enabled, expires_at, pool_name FROM users WHERE username = ?",
                (username,),
            ).fetchone()

        accepted = bool(
            row
            and row["enabled"]
            and (not row["expires_at"] or row["expires_at"] >= datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
            and verify_password(supplied_password, row["password_hash"])
        )
        reply = self.CreateReplyPacket(pkt)
        if accepted:
            reply.code = packet.AccessAccept
            reply["Service-Type"] = 2  # Framed-User
            if row["pool_name"]:
                reply["Framed-Pool"] = row["pool_name"]
            log.info("RADIUS accept for user %s", username)
        else:
            reply.code = packet.AccessReject
            reply["Reply-Message"] = "Invalid username or password"
            log.warning("RADIUS reject for user %s", username)
        self.SendReplyPacket(pkt.fd, reply)

    def HandleAcctPacket(self, pkt: Any) -> None:
        username = str(pkt.get("User-Name", [""])[0])
        session_id = str(pkt.get("Acct-Session-Id", [""])[0])
        log.info("Accounting packet: user=%s session=%s", username, session_id)
        reply = self.CreateReplyPacket(pkt)
        reply.code = packet.AccountingResponse
        self.SendReplyPacket(pkt.fd, reply)


class RadiusManager:
    def __init__(self) -> None:
        self.radius = RadiusServer()
        self.radius.reload_nas()
        self.thread = threading.Thread(target=self.radius.Run, daemon=True)

    def start(self) -> None:
        self.thread.start()
        log.info("RADIUS listening on UDP %s/%s", RADIUS_AUTH_PORT, RADIUS_ACCT_PORT)

    def reload(self) -> None:
        self.radius.reload_nas()


init_database()
radius_manager = RadiusManager()
app = FastAPI(title="SAS RADIUS", version="1.0.0")

LOGIN_PAGE = """<!doctype html>
<html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>تسجيل الدخول - SAS RADIUS</title>
<style>body{margin:0;background:#edf3f8;font-family:Tahoma,Arial;color:#34444f;display:grid;place-items:center;min-height:100vh}.box{width:min(390px,calc(100% - 36px));background:#fff;border-radius:16px;padding:32px;box-shadow:0 8px 25px #b8c5cf}.logo{text-align:center;color:#f45116;font-size:34px;font-weight:900}.logo small{display:block;color:#aaa;font-size:14px}.box h1{text-align:center;font-size:22px;color:#3f5260;margin:22px 0}.box label{display:block;font-weight:700;margin:14px 0 7px}.box input{width:100%;box-sizing:border-box;padding:12px;border:1px solid #d4dde3;border-radius:7px;font:inherit}.btn{width:100%;border:0;border-radius:7px;background:#f45116;color:#fff;padding:12px;margin-top:22px;font:inherit;font-weight:700;cursor:pointer}.error{color:#c43d3d;text-align:center;margin-top:14px;min-height:20px}</style></head>
<body><main class="box"><div class="logo">SAS<small>RADIUS</small></div><h1>تسجيل الدخول إلى لوحة التحكم</h1><form id="login"><label>اسم المستخدم</label><input name="username" autocomplete="username" required><label>كلمة المرور</label><input name="password" type="password" autocomplete="current-password" required><button class="btn">دخول</button><div id="error" class="error"></div></form></main>
<script>document.querySelector('#login').addEventListener('submit',async e=>{e.preventDefault();const r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.fromEntries(new FormData(e.target).entries()))});const d=await r.json();if(r.ok)location.reload();else document.querySelector('#error').textContent=d.detail||'بيانات الدخول غير صحيحة';});</script></body></html>"""


def require_api_key(x_api_key: str | None, sas_session: str | None = None) -> None:
    supplied_key = x_api_key or sas_session
    if not supplied_key or not hmac.compare_digest(supplied_key, API_KEY):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


@app.on_event("startup")
def startup() -> None:
    radius_manager.start()
    if os.getenv("OPEN_BROWSER", "1") == "1":
        threading.Timer(
            0.5,
            lambda: open_external_browser(f"http://{PUBLIC_WEB_HOST}:{WEB_PORT}/"),
        ).start()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "sas-radius"}


@app.get("/", response_class=HTMLResponse)
def dashboard(sas_session: str | None = Cookie(default=None)) -> HTMLResponse:
    if not sas_session or not hmac.compare_digest(sas_session, API_KEY):
        return HTMLResponse(LOGIN_PAGE)
    dashboard_file = BASE_DIR / "dashboard.html"
    page = HTMLResponse(dashboard_file.read_text(encoding="utf-8"))
    page.set_cookie("sas_session", API_KEY, httponly=True, samesite="lax")
    return page


@app.post("/login")
def login(item: LoginCreate, response: Response) -> dict[str, str]:
    if not (hmac.compare_digest(item.username, ADMIN_USERNAME) and hmac.compare_digest(item.password, ADMIN_PASSWORD)):
        raise HTTPException(status_code=401, detail="اسم المستخدم أو كلمة المرور غير صحيحة")
    response.set_cookie("sas_session", API_KEY, httponly=True, samesite="lax")
    return {"status": "ok"}


@app.get("/dashboard/stats")
def dashboard_stats() -> dict[str, int]:
    with db() as connection:
        users = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        active_users = connection.execute(
            "SELECT COUNT(*) FROM users WHERE enabled = 1 AND (expires_at IS NULL OR expires_at >= CURRENT_TIMESTAMP)"
        ).fetchone()[0]
        nas_count = connection.execute("SELECT COUNT(*) FROM nas").fetchone()[0]
        active_nas = connection.execute(
            "SELECT COUNT(*) FROM nas WHERE enabled = 1"
        ).fetchone()[0]
    return {
        "users": users,
        "active_users": active_users,
        "nas_count": nas_count,
        "active_nas": active_nas,
    }


@app.get("/nas")
def list_nas(x_api_key: str | None = Header(default=None), sas_session: str | None = Cookie(default=None)) -> list[dict[str, Any]]:
    require_api_key(x_api_key, sas_session)
    with db() as connection:
        rows = connection.execute(
            "SELECT id, name, ip_address, enabled, created_at FROM nas ORDER BY id DESC"
        ).fetchall()
    return [dict(row) for row in rows]


@app.post("/nas", status_code=201)
def add_nas(item: NASCreate, x_api_key: str | None = Header(default=None), sas_session: str | None = Cookie(default=None)) -> dict[str, Any]:
    require_api_key(x_api_key, sas_session)
    try:
        with db() as connection:
            cursor = connection.execute(
                "INSERT INTO nas(name, ip_address, secret) VALUES (?, ?, ?)",
                (item.name, item.ip_address, item.secret),
            )
            nas_id = cursor.lastrowid
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="NAS name or IP already exists") from exc
    radius_manager.reload()
    return {"id": nas_id, "name": item.name, "ip_address": item.ip_address}


@app.delete("/nas/{nas_id}")
def delete_nas(nas_id: int, x_api_key: str | None = Header(default=None), sas_session: str | None = Cookie(default=None)) -> dict[str, bool]:
    require_api_key(x_api_key, sas_session)
    with db() as connection:
        cursor = connection.execute("DELETE FROM nas WHERE id = ?", (nas_id,))
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="NAS not found")
    radius_manager.reload()
    return {"deleted": True}


@app.post("/users", status_code=201)
def add_user(item: UserCreate, x_api_key: str | None = Header(default=None), sas_session: str | None = Cookie(default=None)) -> dict[str, Any]:
    require_api_key(x_api_key, sas_session)
    activated_at = datetime.now(timezone.utc)
    expires_at = activated_at + timedelta(days=30 * item.activation_months)
    try:
        with db() as connection:
            cursor = connection.execute(
                "INSERT INTO users(username, password_hash, activated_at, expires_at, pool_name) VALUES (?, ?, ?, ?, ?)",
                (item.username, hash_password(item.password), activated_at.strftime("%Y-%m-%d %H:%M:%S"), expires_at.strftime("%Y-%m-%d %H:%M:%S"), item.pool_name),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Username already exists") from exc
    return {"id": cursor.lastrowid, "username": item.username, "pool_name": item.pool_name, "expires_at": expires_at.strftime("%Y-%m-%d %H:%M:%S")}


@app.get("/users")
def list_users(x_api_key: str | None = Header(default=None), sas_session: str | None = Cookie(default=None)) -> list[dict[str, Any]]:
    require_api_key(x_api_key, sas_session)
    with db() as connection:
        rows = connection.execute(
            "SELECT id, username, enabled, pool_name, activated_at, expires_at, created_at FROM users ORDER BY id DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def test_router_api(item: RouterProxyCreate) -> None:
    """Verify RouterOS API credentials before storing a proxy router."""
    try:
        from routeros_api import RouterOsApiPool  # type: ignore
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="حزمة MikroTik API غير مثبتة") from exc
    pool = None
    try:
        pool = RouterOsApiPool(
            host=item.host,
            username=item.api_username,
            password=item.api_password,
            port=item.api_port,
            plaintext_login=True,
        )
        api = pool.get_api()
        api.get_resource("/system/resource").get()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"فشل الاتصال بـ MikroTik API: {exc}") from exc
    finally:
        if pool is not None:
            pool.disconnect()


def build_routeros_script(item: RouterProxyCreate) -> str:
    """Build a copy/paste RouterOS script for the SAS RADIUS connection."""
    service = item.service if item.service in {"ppp", "hotspot", "login", "api"} else "ppp"
    radius_services = "ppp,hotspot" if service == "pppoe" else service
    return f'''# SAS RADIUS - {item.name}
# انسخ هذا السكربت والصقه في Terminal داخل MikroTik
:local sasRadius "{item.radius_address}"
:local sasSecret "{item.radius_secret}"
/radius remove [find where address=$sasRadius]
/radius add address=$sasRadius secret=$sasSecret service={radius_services} timeout=1s
/ppp aaa set use-radius=yes accounting=yes interim-update=5m
/ip hotspot profile set [find] use-radius=yes
:put "SAS RADIUS configured successfully"
'''


def open_router_api(router_id: int) -> tuple[Any, Any, dict[str, Any]]:
    """Open a RouterOS API connection and return (pool, api, router row)."""
    try:
        from routeros_api import RouterOsApiPool  # type: ignore
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="حزمة MikroTik API غير مثبتة") from exc
    with db() as connection:
        row = connection.execute(
            "SELECT * FROM router_proxies WHERE id = ? AND enabled = 1", (router_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="الراوتر غير موجود أو غير فعال")
    try:
        pool = RouterOsApiPool(
            host=row["host"],
            username=row["api_username"],
            password=row["api_password"],
            port=row["api_port"],
            plaintext_login=True,
        )
        api = pool.get_api()
        api.get_resource("/system/resource").get()
        return pool, api, dict(row)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"فشل الاتصال بالراوتر: {exc}") from exc


@app.get("/routers")
def list_router_proxies(x_api_key: str | None = Header(default=None), sas_session: str | None = Cookie(default=None)) -> list[dict[str, Any]]:
    require_api_key(x_api_key, sas_session)
    with db() as connection:
        rows = connection.execute(
            "SELECT id, name, host, service, api_port, api_username, location, radius_address, enabled, created_at "
            "FROM router_proxies ORDER BY id DESC"
        ).fetchall()
    return [dict(row) for row in rows]


@app.post("/routers", status_code=201)
def add_router_proxy(item: RouterProxyCreate, x_api_key: str | None = Header(default=None), sas_session: str | None = Cookie(default=None)) -> dict[str, Any]:
    require_api_key(x_api_key, sas_session)
    test_router_api(item)
    try:
        with db() as connection:
            cursor = connection.execute(
                "INSERT INTO router_proxies(name, host, service, api_port, api_username, api_password, location, radius_address, radius_secret) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (item.name, item.host, item.service, item.api_port, item.api_username, item.api_password, item.location, item.radius_address, item.radius_secret),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="اسم الراوتر مستخدم مسبقًا") from exc
    return {"id": cursor.lastrowid, "name": item.name, "host": item.host, "service": item.service, "script": build_routeros_script(item)}


@app.get("/routers/{router_id}/script")
def get_router_script(router_id: int, x_api_key: str | None = Header(default=None), sas_session: str | None = Cookie(default=None)) -> dict[str, str]:
    require_api_key(x_api_key, sas_session)
    with db() as connection:
        row = connection.execute("SELECT * FROM router_proxies WHERE id = ?", (router_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="الراوتر غير موجود")
    item = RouterProxyCreate(
        name=row["name"], host=row["host"], service=row["service"], api_port=row["api_port"],
        api_username=row["api_username"], api_password=row["api_password"], location=row["location"],
        radius_address=row["radius_address"] or "", radius_secret=row["radius_secret"] or "temporary-secret",
    )
    return {"script": build_routeros_script(item)}


@app.delete("/routers/{router_id}")
def delete_router_proxy(router_id: int, x_api_key: str | None = Header(default=None), sas_session: str | None = Cookie(default=None)) -> dict[str, bool]:
    require_api_key(x_api_key, sas_session)
    with db() as connection:
        connection.execute("DELETE FROM router_pools WHERE router_id = ?", (router_id,))
        cursor = connection.execute("DELETE FROM router_proxies WHERE id = ?", (router_id,))
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="الراوتر غير موجود")
    return {"deleted": True}


@app.get("/pools")
def list_saved_pools(x_api_key: str | None = Header(default=None), sas_session: str | None = Cookie(default=None)) -> list[dict[str, Any]]:
    require_api_key(x_api_key, sas_session)
    with db() as connection:
        rows = connection.execute(
            "SELECT p.id, p.name, p.ranges, p.comment, p.router_id, r.name AS router_name "
            "FROM router_pools p JOIN router_proxies r ON r.id = p.router_id "
            "ORDER BY p.id DESC"
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/routers/{router_id}/pools")
def list_router_pools(router_id: int, x_api_key: str | None = Header(default=None), sas_session: str | None = Cookie(default=None)) -> list[dict[str, Any]]:
    require_api_key(x_api_key, sas_session)
    pool, api, _ = open_router_api(router_id)
    try:
        return api.get_resource("/ip/pool").get()
    finally:
        pool.disconnect()


@app.post("/routers/{router_id}/pools", status_code=201)
def add_router_pool(router_id: int, item: PoolCreate, x_api_key: str | None = Header(default=None), sas_session: str | None = Cookie(default=None)) -> dict[str, Any]:
    require_api_key(x_api_key, sas_session)
    pool, api, router = open_router_api(router_id)
    try:
        remote = api.get_resource("/ip/pool").add(
            name=item.name,
            ranges=item.ranges,
            comment=item.comment or "",
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"تعذر إنشاء الـ Pool على MikroTik: {exc}") from exc
    finally:
        pool.disconnect()
    remote_id = remote.get(".id") if isinstance(remote, dict) else None
    try:
        with db() as connection:
            cursor = connection.execute(
                "INSERT INTO router_pools(router_id, name, ranges, comment, remote_id) VALUES (?, ?, ?, ?, ?)",
                (router_id, item.name, item.ranges, item.comment, remote_id),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="اسم الـ Pool مستخدم مسبقًا لهذا الراوتر") from exc
    return {"id": cursor.lastrowid, "router_id": router_id, "router_name": router["name"], "name": item.name, "ranges": item.ranges}


if __name__ == "__main__":
    import uvicorn

    # Avoid a traceback when a previous SAS instance is already serving the web API.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.5)
        port_is_busy = probe.connect_ex(("127.0.0.1", WEB_PORT)) == 0
    if port_is_busy:
        log.warning(
            "Web server is already running on port %s. "
            "Use http://%s:%s or stop the previous instance first.",
            PUBLIC_WEB_HOST,
            WEB_PORT,
            WEB_PORT,
        )
        if os.getenv("OPEN_BROWSER", "1") == "1":
            open_external_browser(f"http://{PUBLIC_WEB_HOST}:{WEB_PORT}/")
    else:
        # Pass the app object directly so running this file does not import it twice.
        uvicorn.run(app, host="0.0.0.0", port=WEB_PORT, reload=False)
