#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verifier.py — сайт + API + раздача файлов + админка и срок действия ключа.
Стандартная библиотека только. Python 3.9+.

Функциональность:
- /            → index.html из static_dir
- /admin       → admin.html из static_dir (Basic Auth)
- /downloads/* → файлы из downloads_dir (attachment)
- POST {api_prefix}{verify_endpoint} → проверка ключа с учётом срока действия
- /admin-api/* → управление ключами/файлами/конфигом (Basic Auth)

Безопасность админки:
- Basic Auth. Установите ADMIN_USER и ADMIN_PASSWORD (или --admin-user + --admin-pass-file).
- Если пароль не задан — /admin и /admin-api отключены (403).
- Заголовки: X-Frame-Options: DENY, Cross-Origin-Resource-Policy: same-origin.

Срок действия ключа:
- duration_days (NULL = бессрочный).
- first_activated_at фиксируется при первой успешной проверке.
- EXPIRED: 200 { ok:false, code:"EXPIRED", message:"Key expired" }.

Запуск локально:
  python backend/verifier.py serve --host 127.0.0.1 --port 8000 ^
    --static-dir ./frontend --downloads-dir ./downloads
"""
from __future__ import annotations

import argparse
import base64
import hmac
import io
import json
import mimetypes
import os
import pathlib
import signal
import sqlite3
import sys
import threading
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterable, Optional, Tuple

# ------------------------------- Константы -----------------------------------

DEFAULT_DB_PATH = "keys.db"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
DEFAULT_API_PREFIX = "/api"
DEFAULT_VERIFY_ENDPOINT = "/verify-key"
MAX_REQUEST_BYTES = 4096
MAX_UPLOAD_BYTES = 512 * 1024 * 1024  # 512 MiB

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
DEFAULT_STATIC_DIR = (SCRIPT_DIR / ".." / "frontend").resolve()
DEFAULT_DOWNLOADS_DIR = (SCRIPT_DIR / ".." / "downloads").resolve()

# ---------------------- Утилиты нормализации/валидации -----------------------

def normalize_key(value: str) -> str:
    """Нормализует ключ: верхний регистр, только A–Z/0–9. Пустая строка -> ''."""
    if not isinstance(value, str):
        return ""
    up = value.upper()
    return "".join(ch for ch in up if ch.isalnum())

# ------------------------------- Хранилище -----------------------------------

class KeyStore:
    """SQLite-хранилище ключей + конфиг.

    Таблицы:
      keys(key_norm TEXT PRIMARY KEY,
           duration_days INTEGER NULL,
           first_activated_at INTEGER NULL,
           created_at INTEGER NULL)
      config(key TEXT PRIMARY KEY, value TEXT NOT NULL)
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._tls = threading.local()
        self._init_db()

    # ---- соединение ----
    def _get_conn(self) -> sqlite3.Connection:
        conn: Optional[sqlite3.Connection] = getattr(self._tls, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                self._db_path,
                isolation_level=None,  # autocommit
                check_same_thread=False,
                detect_types=0,
            )
            self._apply_pragmas(conn)
            setattr(self._tls, "conn", conn)
        return conn

    @staticmethod
    def _apply_pragmas(conn: sqlite3.Connection) -> None:
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL;")
        cur.execute("PRAGMA synchronous=NORMAL;")
        cur.execute("PRAGMA temp_store=MEMORY;")
        cur.execute("PRAGMA cache_size=-1024;")  # ~1MB
        cur.execute("PRAGMA foreign_keys=OFF;")
        cur.close()

    # ---- инициализация/миграция ----
    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS keys (
              key_norm TEXT PRIMARY KEY,
              duration_days INTEGER NULL,
              first_activated_at INTEGER NULL,
              created_at INTEGER NULL
            ) WITHOUT ROWID;
            """
        )
        # Миграции по keys
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(keys);")
        cols = {row[1] for row in cur.fetchall()}

        if "duration_days" not in cols:
            conn.execute("ALTER TABLE keys ADD COLUMN duration_days INTEGER NULL;")

        if "first_activated_at" not in cols:
            conn.execute("ALTER TABLE keys ADD COLUMN first_activated_at INTEGER NULL;")

        if "created_at" not in cols:
            # Без DEFAULT из выражения — для совместимости со старыми SQLite
            conn.execute("ALTER TABLE keys ADD COLUMN created_at INTEGER NULL;")
            conn.execute("UPDATE keys SET created_at = CAST(strftime('%s','now') AS INTEGER) WHERE created_at IS NULL;")

        # Таблица config гарантированно создаётся
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS config (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            ) WITHOUT ROWID;
            """
        )

        cur.close()
        conn.execute("PRAGMA optimize;")

    # ---- ключи ----
    def add_many(self, keys: Iterable[str], duration_days: Optional[int]) -> Tuple[int, int]:
        now = int(time.time())
        conn = self._get_conn()
        inserted = 0
        skipped = 0
        with conn:
            cur = conn.cursor()
            for raw in keys:
                nkey = normalize_key(raw)
                if not nkey:
                    skipped += 1
                    continue
                try:
                    cur.execute(
                        "INSERT OR IGNORE INTO keys(key_norm,duration_days,first_activated_at,created_at) VALUES (?,?,NULL,?)",
                        (nkey, duration_days, now),
                    )
                    if cur.rowcount == 1:
                        inserted += 1
                    else:
                        # Дубликат: при необходимости обновим duration_days
                        if duration_days is not None:
                            cur.execute("UPDATE keys SET duration_days=? WHERE key_norm=?", (duration_days, nkey))
                        skipped += 1
                except sqlite3.DatabaseError:
                    skipped += 1
            cur.close()
        return inserted, skipped

    def has_and_touch_activation(self, key: str, now_ts: int) -> Tuple[bool, Optional[int], Optional[int]]:
        """Возвращает (exists, duration_days, first_activated_at_after).
        При первой проверке фиксирует first_activated_at, если был NULL.
        """
        nkey = normalize_key(key)
        if not nkey:
            return False, None, None
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "UPDATE keys SET first_activated_at = COALESCE(first_activated_at, ?) WHERE key_norm = ?",
            (now_ts, nkey),
        )
        cur.execute("SELECT duration_days, first_activated_at FROM keys WHERE key_norm=?", (nkey,))
        row = cur.fetchone()
        cur.close()
        if not row:
            return False, None, None
        duration_days, first_activated_at = row[0], row[1]
        return True, (None if duration_days is None else int(duration_days)), (None if first_activated_at is None else int(first_activated_at))

    def list_keys(self, q: Optional[str]) -> Tuple[int, list[dict]]:
        conn = self._get_conn()
        cur = conn.cursor()
        if q:
            like = f"%{normalize_key(q)}%"
            cur.execute("SELECT key_norm,duration_days,first_activated_at,created_at FROM keys WHERE key_norm LIKE ? ORDER BY created_at DESC", (like,))
        else:
            cur.execute("SELECT key_norm,duration_days,first_activated_at,created_at FROM keys ORDER BY created_at DESC")
        rows = cur.fetchall()
        cur.execute("SELECT COUNT(*) FROM keys")
        total = int(cur.fetchone()[0])
        cur.close()

        items = []
        now_ts = int(time.time())
        for key_norm, duration_days, first_activated_at, created_at in rows:
            duration_days = None if duration_days is None else int(duration_days)
            first_activated_at = None if first_activated_at is None else int(first_activated_at)
            expires_at = None
            is_expired = False
            if duration_days is not None and first_activated_at is not None:
                expires_at = first_activated_at + duration_days * 86400
                is_expired = now_ts >= expires_at
            items.append({
                "keyNorm": key_norm,
                "durationDays": duration_days,
                "firstActivatedAt": first_activated_at,
                "expiresAt": expires_at,
                "isExpired": is_expired,
                "createdAt": int(created_at) if created_at is not None else None,
            })
        return total, items

    def patch_key(self, key_norm: str, duration_days: Optional[Optional[int]], reset_activation: bool) -> bool:
        nkey = normalize_key(key_norm)
        conn = self._get_conn()
        cur = conn.cursor()
        if reset_activation and duration_days is not None:
            cur.execute("UPDATE keys SET first_activated_at=NULL, duration_days=? WHERE key_norm=?", (duration_days, nkey))
        elif reset_activation:
            cur.execute("UPDATE keys SET first_activated_at=NULL WHERE key_norm=?", (nkey,))
        elif duration_days is not None:
            cur.execute("UPDATE keys SET duration_days=? WHERE key_norm=?", (duration_days, nkey))
        else:
            cur.close()
            return False
        ok = cur.rowcount > 0
        cur.close()
        return ok

    def delete_key(self, key_norm: str) -> bool:
        nkey = normalize_key(key_norm)
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM keys WHERE key_norm=?", (nkey,))
        ok = cur.rowcount > 0
        cur.close()
        return ok

    # ---- config ----
    def get_config(self, key: str) -> Optional[str]:
        conn = self._get_conn()
        cur = conn.cursor()
        try:
            cur.execute("SELECT value FROM config WHERE key=?", (key,))
            row = cur.fetchone()
            return row[0] if row else None
        except sqlite3.OperationalError:
            # На случай, если таблица ещё не создана (защита от падения)
            return None
        finally:
            cur.close()

    def set_config(self, key: str, value: Optional[str]) -> None:
        conn = self._get_conn()
        with conn:
            if value is None:
                conn.execute("DELETE FROM config WHERE key=?", (key,))
            else:
                conn.execute(
                    "INSERT INTO config(key,value) VALUES(?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (key, value),
                )

# ------------------------------- Настройки -----------------------------------

class Settings:
    def __init__(
        self,
        api_prefix: str,
        verify_endpoint: str,
        static_dir: pathlib.Path,
        downloads_dir: pathlib.Path,
        download_url: Optional[str],
        download_file: Optional[str],
        cors_origin: Optional[str],
        admin_user: Optional[str],
        admin_password: Optional[str],
    ):
        api_prefix = api_prefix if api_prefix.startswith("/") else "/" + api_prefix
        verify_endpoint = verify_endpoint if verify_endpoint.startswith("/") else "/" + verify_endpoint
        self.api_prefix = api_prefix.rstrip("/")
        self.verify_endpoint = verify_endpoint
        self.verify_path = self.api_prefix + self.verify_endpoint
        self.static_dir = static_dir
        self.downloads_dir = downloads_dir
        self.download_url = download_url
        self.download_file = download_file
        self.cors_origin = cors_origin
        self.admin_user = admin_user
        self.admin_password = admin_password
        if not self.download_url and not self.download_file and (self.downloads_dir / "package.zip").is_file():
            self.download_file = "package.zip"

    @property
    def admin_enabled(self) -> bool:
        return bool(self.admin_user and self.admin_password)

# --------------------------------- HTTP утилы --------------------------------

def guess_mime(path: pathlib.Path) -> str:
    typ, _ = mimetypes.guess_type(str(path))
    return typ or "application/octet-stream"

def safe_under(base: pathlib.Path, requested: pathlib.Path) -> Optional[pathlib.Path]:
    try:
        req = requested.resolve(strict=False)
        base = base.resolve(strict=True)
        if base in req.parents or req == base:
            return req
        return None
    except Exception:
        return None

def parse_basic_auth(header: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if not header or not header.startswith("Basic "):
        return None, None
    try:
        raw = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8")
        if ":" not in raw:
            return None, None
        user, pwd = raw.split(":", 1)
        return user, pwd
    except Exception:
        return None, None

# --------------------------------- Handler -----------------------------------

def make_handler(keystore: KeyStore, settings: Settings):
    index_path = settings.static_dir / "index.html"
    admin_path = settings.static_dir / "admin.html"

    class Handler(BaseHTTPRequestHandler):
        server_version = "KeyVerifier/2.2"
        sys_version = ""

        def _set_common_headers(self, status: int, content_type: str = "application/json") -> None:
            self.send_response(status)
            if settings.cors_origin:
                self.send_header("Access-Control-Allow-Origin", settings.cors_origin)
                self.send_header("Vary", "Origin")
            self.send_header("Content-Type", content_type + "; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.end_headers()

        def _send_json(self, status: int, payload: dict) -> None:
            body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            self._set_common_headers(status, "application/json")
            self.wfile.write(body)

        def _read_json_body(self, limit: int = MAX_REQUEST_BYTES):
            cl_header = self.headers.get("Content-Length", "")
            if not cl_header.isdigit():
                return None, "Missing or invalid Content-Length"
            length = int(cl_header)
            if length <= 0 or length > limit:
                return None, "Request entity too large"
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw.decode("utf-8"))
                if not isinstance(payload, dict):
                    return None, "Body must be a JSON object"
                return payload, None
            except Exception:
                return None, "Malformed JSON"

        def _require_admin(self) -> bool:
            if not settings.admin_enabled:
                self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "code": "ADMIN_DISABLED", "message": "Admin is disabled. Set ADMIN_USER/ADMIN_PASSWORD or flags."})
                return False
            user, pwd = parse_basic_auth(self.headers.get("Authorization"))
            if user is None:
                self.send_response(HTTPStatus.UNAUTHORIZED)
                self.send_header("WWW-Authenticate", "Basic realm=admin, charset=\"UTF-8\"")
                self.end_headers()
                return False
            ok = hmac.compare_digest(user, settings.admin_user) and hmac.compare_digest(pwd, settings.admin_password)
            if not ok:
                self.send_response(HTTPStatus.UNAUTHORIZED)
                self.send_header("WWW-Authenticate", "Basic realm=admin, charset=\"UTF-8\"")
                self.end_headers()
                return False
            return True

        # ---------- CORS preflight ----------
        def do_OPTIONS(self) -> None:
            if settings.cors_origin:
                self.send_response(HTTPStatus.NO_CONTENT)
                self.send_header("Access-Control-Allow-Origin", settings.cors_origin)
                self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
                self.send_header("Access-Control-Max-Age", "600")
                self.end_headers()
            else:
                self.send_response(HTTPStatus.NO_CONTENT)
                self.end_headers()

        # ---------- GET ----------
        def do_GET(self) -> None:
            if self.path == "/healthz":
                self._set_common_headers(HTTPStatus.OK, "text/plain")
                self.wfile.write(b"ok")
                return

            if self.path == "/admin":
                if not self._require_admin():
                    return
                if admin_path.is_file():
                    try:
                        self.send_response(HTTPStatus.OK)
                        self.send_header("Content-Type", "text/html; charset=utf-8")
                        self.send_header("Cache-Control", "no-store")
                        self.send_header("X-Frame-Options", "DENY")
                        self.end_headers()
                        with open(admin_path, "rb") as f:
                            self.wfile.write(f.read())
                    except Exception as e:
                        sys.stderr.write(f"[error] admin: {e}\n")
                        self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Cannot read admin.html")
                else:
                    self.send_error(HTTPStatus.NOT_FOUND, "admin.html not found")
                return

            if self.path.startswith("/downloads/"):
                rel = self.path[len("/downloads/"):]
                dest = safe_under(settings.downloads_dir, settings.downloads_dir / urllib.parse.unquote(rel))
                if not dest or not dest.is_file():
                    self.send_error(HTTPStatus.NOT_FOUND, "File not found")
                    return
                try:
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", guess_mime(dest))
                    self.send_header("Content-Length", str(dest.stat().st_size))
                    self.send_header("Content-Disposition", f'attachment; filename="{dest.name}"')
                    self.end_headers()
                    with open(dest, "rb") as f:
                        while True:
                            chunk = f.read(64 * 1024)
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                    return
                except BrokenPipeError:
                    return
                except Exception as e:
                    sys.stderr.write(f"[error] download: {e}\n")
                    self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "I/O error")
                    return

            if self.path == "/" or self.path.startswith("/index.html"):
                if index_path.is_file():
                    try:
                        self.send_response(HTTPStatus.OK)
                        self.send_header("Content-Type", "text/html; charset=utf-8")
                        self.send_header("Cache-Control", "no-store")
                        self.end_headers()
                        with open(index_path, "rb") as f:
                            self.wfile.write(f.read())
                    except Exception as e:
                        sys.stderr.write(f"[error] index: {e}\n")
                        self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Cannot read index.html")
                    return
                else:
                    self.send_error(HTTPStatus.NOT_FOUND, "index.html not found")
                    return

            if self.path.startswith("/admin-api/"):
                if not self._require_admin():
                    return
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path == "/admin-api/keys":
                    qs = urllib.parse.parse_qs(parsed.query or "")
                    q = qs.get("q", [None])[0]
                    total, items = keystore.list_keys(q)
                    self._send_json(HTTPStatus.OK, {"total": total, "items": items})
                    return
                if parsed.path == "/admin-api/files":
                    items = []
                    try:
                        for p in sorted(settings.downloads_dir.glob("*")):
                            if p.is_file():
                                st = p.stat()
                                items.append({"name": p.name, "size": int(st.st_size), "mtime": int(st.st_mtime)})
                        self._send_json(HTTPStatus.OK, {"items": items})
                    except Exception as e:
                        sys.stderr.write(f"[error] list files: {e}\n")
                        self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "message": "Cannot list files"})
                    return
                if parsed.path == "/admin-api/config":
                    default_file = keystore.get_config("default_download_file")
                    self._send_json(HTTPStatus.OK, {"defaultDownloadFile": default_file})
                    return
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "code": "NOT_FOUND", "message": "No such admin endpoint"})
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "code": "NOT_FOUND", "message": "No such endpoint"})

        # ---------- POST/PATCH/DELETE ----------
        def do_POST(self) -> None:
            if self.path == settings.verify_path:
                payload, err = self._read_json_body()
                if err:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "code": "BAD_REQUEST", "message": err})
                    return
                product_key = payload.get("productKey")
                if not isinstance(product_key, str) or not product_key.strip():
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "code": "BAD_REQUEST", "message": "Field 'productKey' is required"})
                    return
                now_ts = int(time.time())
                exists, duration_days, first_activated = keystore.has_and_touch_activation(product_key, now_ts)
                if not exists:
                    self._send_json(HTTPStatus.OK, {"ok": False, "code": "INVALID_KEY", "message": "Key not recognized"})
                    return
                if duration_days is not None and first_activated is not None:
                    expires_at = first_activated + duration_days * 86400
                    if now_ts >= expires_at:
                        self._send_json(HTTPStatus.OK, {"ok": False, "code": "EXPIRED", "message": "Key expired"})
                        return
                resp = {"ok": True}
                if settings.download_url:
                    resp["url"] = settings.download_url
                else:
                    default_file = keystore.get_config("default_download_file")
                    if default_file:
                        resp["file"] = default_file
                    elif settings.download_file:
                        resp["file"] = settings.download_file
                self._send_json(HTTPStatus.OK, resp)
                return

            if self.path.startswith("/admin-api/"):
                if not self._require_admin():
                    return
                if self.path == "/admin-api/keys":
                    payload, err = self._read_json_body(limit=1_000_000)
                    if err:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "message": err}); return
                    keys = payload.get("keys") or []
                    duration = payload.get("durationDays")
                    if duration is not None:
                        try:
                            duration = int(duration)
                        except Exception:
                            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "message": "durationDays must be int or null"}); return
                        if duration <= 0:
                            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "message": "durationDays must be > 0"}); return
                    inserted, skipped = keystore.add_many(keys, duration)
                    self._send_json(HTTPStatus.OK, {"inserted": inserted, "skipped": skipped})
                    return
                if self.path == "/admin-api/files":
                    ctype = self.headers.get('Content-Type','')
                    if not ctype.startswith('multipart/form-data'):
                        self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "message": "multipart/form-data expected"}); return
                    cl_header = self.headers.get('Content-Length','0')
                    if not cl_header.isdigit():
                        self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "message": "Missing Content-Length"}); return
                    length = int(cl_header)
                    if length <= 0 or length > MAX_UPLOAD_BYTES:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "message": "Upload too large"}); return
                    env = {'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': ctype, 'CONTENT_LENGTH': str(length)}
                    fp = io.BytesIO(self.rfile.read(length))
                    import cgi  # stdlib (deprecated, но доступен)
                    form = cgi.FieldStorage(fp=fp, environ=env, keep_blank_values=True)
                    fileitem = form['file'] if 'file' in form else None
                    if not fileitem or not fileitem.filename:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "message": "Field 'file' is required"}); return
                    name = pathlib.Path(fileitem.filename).name
                    dest = safe_under(settings.downloads_dir, settings.downloads_dir / name)
                    if not dest:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "message": "Invalid file name"}); return
                    try:
                        settings.downloads_dir.mkdir(parents=True, exist_ok=True)
                        with open(dest, 'wb') as f:
                            f.write(fileitem.file.read())
                        self._send_json(HTTPStatus.OK, {"ok": True, "name": name})
                    except Exception as e:
                        sys.stderr.write(f"[error] upload: {e}\n")
                        self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "message": "Upload failed"})
                    return
                if self.path == "/admin-api/config":
                    payload, err = self._read_json_body()
                    if err:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "message": err}); return
                    val = payload.get("defaultDownloadFile")
                    if val not in (None, ""):
                        p = safe_under(settings.downloads_dir, settings.downloads_dir / val)
                        if not p or not p.is_file():
                            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "message": "File does not exist in downloads"}); return
                        keystore.set_config("default_download_file", val)
                    else:
                        keystore.set_config("default_download_file", None)
                    self._send_json(HTTPStatus.OK, {"ok": True})
                    return

            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "code": "NOT_FOUND", "message": "No such endpoint"})

        def do_PATCH(self) -> None:
            if not self.path.startswith("/admin-api/"):
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "message": "Not found"}); return
            if not self._require_admin():
                return
            if self.path.startswith("/admin-api/keys/"):
                key = urllib.parse.unquote(self.path[len("/admin-api/keys/"):])
                payload, err = self._read_json_body()
                if err:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "message": err}); return
                reset = bool(payload.get("resetActivation", False))
                duration = payload.get("durationDays", None)
                if duration is not None:
                    try:
                        duration = int(duration)
                    except Exception:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "message": "durationDays must be int or null"}); return
                    if duration <= 0:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "message": "durationDays must be > 0"}); return
                ok = keystore.patch_key(key, duration, reset)
                if not ok:
                    self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "message": "Key not found or nothing to update"})
                else:
                    self._send_json(HTTPStatus.OK, {"ok": True})
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "message": "No such admin endpoint"})

        def do_DELETE(self) -> None:
            if not self.path.startswith("/admin-api/"):
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "message": "Not found"}); return
            if not self._require_admin():
                return
            if self.path.startswith("/admin-api/keys/"):
                key = urllib.parse.unquote(self.path[len("/admin-api/keys/"):])
                ok = keystore.delete_key(key)
                if not ok:
                    self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "message": "Key not found"})
                else:
                    self._send_json(HTTPStatus.OK, {"ok": True})
                return
            if self.path.startswith("/admin-api/files/"):
                name = urllib.parse.unquote(self.path[len("/admin-api/files/"):])
                p = safe_under(settings.downloads_dir, settings.downloads_dir / name)
                if not p or not p.is_file():
                    self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "message": "File not found"}); return
                try:
                    p.unlink()
                    self._send_json(HTTPStatus.OK, {"ok": True})
                except Exception as e:
                    sys.stderr.write(f"[error] delete: {e}\n")
                    self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "message": "Delete failed"})
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "message": "No such admin endpoint"})

        def log_message(self, fmt: str, *args) -> None:
            sys.stderr.write(f"[{self.log_date_time_string()}] {self.address_string()} {fmt % args}\n")

    return Handler

# ----------------------------------- CLI -------------------------------------

def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Product key verifier (site + API + downloads + admin)",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--db", default=DEFAULT_DB_PATH, help="Path to SQLite database file")

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_add = sub.add_parser("add", help="Add keys (from args and/or stdin)")
    p_add.add_argument("keys", nargs="*", help="Keys to add")
    p_add.add_argument("--stdin", action="store_true", help="Read keys from STDIN (one per line)")
    p_add.add_argument("--duration-days", type=int, default=None, help="Set duration (days) for added keys")

    sub.add_parser("count", help="Print number of keys")
    sub.add_parser("vacuum", help="Compact database (VACUUM)")

    p_srv = sub.add_parser("serve", help="Run HTTP server (serves site, downloads, API, and admin)")
    p_srv.add_argument("--host", default=DEFAULT_HOST, help="Bind host")
    p_srv.add_argument("--port", type=int, default=DEFAULT_PORT, help="Bind port")
    p_srv.add_argument("--api-prefix", default=DEFAULT_API_PREFIX, help="API prefix")
    p_srv.add_argument("--verify-endpoint", default=DEFAULT_VERIFY_ENDPOINT, help="Verify endpoint path")
    p_srv.add_argument("--static-dir", default=str(DEFAULT_STATIC_DIR), help="Directory with index.html and admin.html")
    p_srv.add_argument("--downloads-dir", default=str(DEFAULT_DOWNLOADS_DIR), help="Directory with downloadable files")
    p_srv.add_argument("--download-url", default=None, help="Absolute URL to return on success (takes precedence)")
    p_srv.add_argument("--download-file", default=None, help="Relative file name under downloads-dir to return on success")
    p_srv.add_argument("--cors-origin", default=None, help="CORS Access-Control-Allow-Origin (not needed on one-port setup)")
    p_srv.add_argument("--admin-user", default=os.getenv("ADMIN_USER") or None, help="Admin username (or env ADMIN_USER)")
    p_srv.add_argument("--admin-pass", default=os.getenv("ADMIN_PASSWORD") or None, help="Admin password (or env ADMIN_PASSWORD)")
    p_srv.add_argument("--admin-pass-file", default=None, help="Path to file containing admin password")

    return parser.parse_args(argv)

# ---- команды ----

def cmd_add(store: KeyStore, keys: Iterable[str], from_stdin: bool, duration_days: Optional[int]) -> int:
    collected: list[str] = []
    collected.extend(keys)
    if from_stdin:
        for line in sys.stdin:
            collected.append(line.rstrip("\r\n"))
    if duration_days is not None and duration_days <= 0:
        print("duration-days must be > 0", file=sys.stderr); return 2
    inserted, skipped = store.add_many(collected, duration_days)
    total = inserted + skipped
    print(f"Processed: {total}  Inserted: {inserted}  Skipped: {skipped}")
    return 0

def cmd_count(store: KeyStore) -> int:
    print(store.count()); return 0

def cmd_vacuum(store: KeyStore) -> int:
    store.vacuum(); print("VACUUM done."); return 0

def cmd_serve(
    store: KeyStore,
    host: str, port: int,
    api_prefix: str, verify_endpoint: str,
    static_dir: str, downloads_dir: str,
    download_url: Optional[str], download_file: Optional[str],
    cors_origin: Optional[str],
    admin_user: Optional[str], admin_pass: Optional[str], admin_pass_file: Optional[str]
) -> int:
    static_path = pathlib.Path(static_dir)
    downloads_path = pathlib.Path(downloads_dir)

    if admin_pass_file:
        try:
            admin_pass = pathlib.Path(admin_pass_file).read_text(encoding='utf-8').strip()
        except Exception as e:
            print(f"Failed to read admin-pass-file: {e}", file=sys.stderr); return 2

    settings = Settings(
        api_prefix=api_prefix, verify_endpoint=verify_endpoint,
        static_dir=static_path, downloads_dir=downloads_path,
        download_url=download_url, download_file=download_file,
        cors_origin=cors_origin, admin_user=admin_user, admin_password=admin_pass
    )

    handler_cls = make_handler(store, settings)
    httpd = ThreadingHTTPServer((host, port), handler_cls)
    httpd.daemon_threads = True

    def _graceful_shutdown(signum, frame):
        del signum, frame
        sys.stderr.write("Shutting down...\n"); httpd.shutdown()

    signal.signal(signal.SIGINT, _graceful_shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _graceful_shutdown)

    bind = f"{host}:{port}"
    sys.stderr.write(f"Serving on http://{bind}  (verify at {settings.verify_path})\n")
    if not settings.admin_enabled:
        sys.stderr.write("[warn] Admin is DISABLED. Set ADMIN_USER/ADMIN_PASSWORD or --admin-user/--admin-pass-file to enable /admin.\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0

# ----------------------------------- main ------------------------------------

def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)
    store = KeyStore(args.db)

    if args.cmd == "add":
        return cmd_add(store, args.keys, args.stdin, args.duration_days)
    if args.cmd == "count":
        return cmd_count(store)
    if args.cmd == "vacuum":
        return cmd_vacuum(store)
    if args.cmd == "serve":
        return cmd_serve(
            store,
            host=args.host, port=args.port,
            api_prefix=args.api_prefix, verify_endpoint=args.verify_endpoint,
            static_dir=args.static_dir, downloads_dir=args.downloads_dir,
            download_url=args.download_url, download_file=args.download_file,
            cors_origin=args.cors_origin,
            admin_user=args.admin_user, admin_pass=args.admin_pass, admin_pass_file=args.admin_pass_file
        )
    print("Unknown command", file=sys.stderr); return 2

if __name__ == "__main__":
    sys.exit(main())
