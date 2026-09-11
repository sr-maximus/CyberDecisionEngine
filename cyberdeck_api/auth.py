"""Opt-in, server-enforced authentication for a shared trusted workspace.

No browser storage, caller role header or licensing record confers authority.
Sessions and login throttles persist across worker/container restarts in SQLite.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import JSONResponse

COOKIE = "__Host-cde_session"
IDLE_SECONDS = 30 * 60
MAX_SECONDS = 8 * 60 * 60
ROLES = {"super_admin", "analyst"}


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600_000)
    return f"pbkdf2_sha256$600000${salt}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt, expected = encoded.split("$")
        if algorithm != "pbkdf2_sha256" or int(rounds) != 600_000:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds))
        return hmac.compare_digest(actual.hex(), expected)
    except (ValueError, TypeError):
        return False


def public_user(user: dict) -> dict:
    return {"id": user["id"], "username": user["username"], "fullName": user.get("fullName", user["username"]),
            "role": user["role"], "permissions": (["platform:superadmin", "users:manage", "settings:write"]
            if user["role"] == "super_admin" else []) + ["analysis:run", "reports:view", "surface:view"],
            "createdAt": user.get("createdAt", ""), "passwordHash": "", "mfaEnabled": False}


class AuthMiddleware:
    def __init__(self, app):
        self.app = app
        self.enabled = os.environ.get("CDE_AUTH_ENABLED", "false").lower() == "true"
        self.origin = os.environ.get("CDE_PUBLIC_ORIGIN", "").rstrip("/")
        self.users_file = Path(os.environ.get("CDE_AUTH_USERS_FILE", "/run/secrets/auth_users.json"))
        self.db_path = Path(os.environ.get("CDE_AUTH_STATE_FILE", "data/auth-sessions.sqlite"))
        self.ready = False
        # Fixed valid dummy digest keeps nonexistent-user password checks comparable.
        self.dummy = "pbkdf2_sha256$600000$" + "00" * 16 + "$" + "00" * 32
        if self.enabled:
            parsed = urlsplit(self.origin)
            if parsed.scheme != "https" or not parsed.netloc or parsed.path or parsed.query or parsed.fragment:
                raise RuntimeError("Public authentication requires a canonical HTTPS CDE_PUBLIC_ORIGIN")
            self._users()  # Fail startup when identity configuration is missing or invalid.
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            with self._db() as db:
                db.executescript("""
                    CREATE TABLE IF NOT EXISTS sessions (
                      token TEXT PRIMARY KEY, uid TEXT NOT NULL, credential TEXT NOT NULL,
                      csrf TEXT NOT NULL, issued REAL NOT NULL, touched REAL NOT NULL);
                    CREATE TABLE IF NOT EXISTS attempts (
                      bucket TEXT PRIMARY KEY, count INTEGER NOT NULL, reset REAL NOT NULL);
                """)
            self.db_path.chmod(0o600)
            self.ready = True

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.db_path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def _users(self) -> list[dict]:
        users = json.loads(self.users_file.read_text())["users"]
        if not users or not any(u.get("role") == "super_admin" and not u.get("disabled") for u in users):
            raise ValueError("An active server administrator is required")
        ids, names = set(), set()
        for user in users:
            name = user["username"]
            if not re.fullmatch(r"[a-z0-9_.-]{3,64}", name) or user["role"] not in ROLES:
                raise ValueError("Invalid server account")
            if user["id"] in ids or name in names:
                raise ValueError("Duplicate server account")
            if not re.fullmatch(r"pbkdf2_sha256\$600000\$[0-9a-f]{32}\$[0-9a-f]{64}", user["passwordHash"]):
                raise ValueError("Invalid password digest")
            ids.add(user["id"])
            names.add(name)
        return users

    @staticmethod
    def _error(status: int, message: str):
        return JSONResponse({"detail": message}, status_code=status, headers={"Cache-Control": "no-store"})

    def _attempt(self, buckets: list[tuple[str, int]], now: float) -> bool:
        """Reserve attempts atomically, before expensive hashing, including concurrent requests."""
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM attempts WHERE reset <= ?", (now,))
            for bucket, limit in buckets:
                row = db.execute("SELECT count FROM attempts WHERE bucket=?", (bucket,)).fetchone()
                if row and row[0] >= limit:
                    return False
            for bucket, _ in buckets:
                db.execute("INSERT INTO attempts VALUES (?, 1, ?) ON CONFLICT(bucket) DO UPDATE SET count=count+1", (bucket, now + 900))
        return True

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            if self.enabled and scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
                return
            return await self.app(scope, receive, send)
        request = Request(scope, receive)
        path, method = request.url.path.rstrip("/") or "/", request.method
        if path == "/api/auth/mode" and method == "GET":
            return await JSONResponse({"enabled": self.enabled}, headers={"Cache-Control": "no-store"})(scope, receive, send)
        if not self.enabled:
            return await self.app(scope, receive, send)
        if path == "/api/health" and method == "GET":
            return await JSONResponse({"status": "ok"})(scope, receive, send)
        try:
            users = self._users()
        except (OSError, ValueError, KeyError, TypeError):
            return await self._error(503, "Authentication is unavailable")(scope, receive, send)
        origin = request.headers.get("origin")
        if (origin and origin != self.origin) or request.headers.get("sec-fetch-site") == "cross-site":
            return await self._error(403, "Origin is not allowed")(scope, receive, send)
        if method not in {"GET", "HEAD", "OPTIONS"} and origin != self.origin:
            return await self._error(403, "A same-origin request is required")(scope, receive, send)
        now = time.time()
        if path == "/api/auth/login" and method == "POST":
            if request.headers.get("content-type", "").split(";")[0] != "application/json":
                return await self._error(415, "JSON is required")(scope, receive, send)
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 4096:
                    return await self._error(413, "Login request is too large")(scope, receive, send)
            try:
                payload = json.loads(body)
                username = str(payload.get("username", "")).strip().lower()[:64]
                password = payload.get("password", "")
                if not isinstance(password, str) or len(password) > 1024:
                    raise ValueError()
            except (ValueError, AttributeError):
                return await self._error(400, "Invalid login request")(scope, receive, send)
            # request.client is set by Uvicorn's explicitly trusted proxy, never by a caller role/IP header.
            ip = request.client.host if request.client else "unknown"
            buckets = [("ip:" + ip, 30), ("user:" + username, 10)]
            if not self._attempt(buckets, now):
                return await self._error(429, "Too many attempts. Wait 15 minutes")(scope, receive, send)
            user = next((u for u in users if u["username"] == username and not u.get("disabled")), None)
            valid = await asyncio.to_thread(verify_password, password, user["passwordHash"] if user else self.dummy)
            if not valid or not user:
                return await self._error(401, "Invalid username or password")(scope, receive, send)
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            digest = hashlib.sha256(token.encode()).hexdigest()
            with self._db() as db:
                db.execute("DELETE FROM sessions WHERE issued < ? OR touched < ?", (now - MAX_SECONDS, now - IDLE_SECONDS))
                db.execute("DELETE FROM attempts WHERE bucket=?", ("user:" + username,))
                old = request.cookies.get(COOKIE, "")
                db.execute("DELETE FROM sessions WHERE token=?", (hashlib.sha256(old.encode()).hexdigest(),))
                db.execute("INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?)", (digest, user["id"], user["passwordHash"], csrf, now, now))
            response = JSONResponse({"user": public_user(user), "csrfToken": csrf}, headers={"Cache-Control": "no-store"})
            response.set_cookie(COOKIE, token, max_age=MAX_SECONDS, httponly=True, secure=True, samesite="strict", path="/")
            return await response(scope, receive, send)
        digest = hashlib.sha256(request.cookies.get(COOKIE, "").encode()).hexdigest()
        with self._db() as db:
            session = db.execute("SELECT * FROM sessions WHERE token=?", (digest,)).fetchone()
        user = next((u for u in users if session and u["id"] == session["uid"] and not u.get("disabled")), None)
        if not session or not user or user["passwordHash"] != session["credential"] or now - session["issued"] >= MAX_SECONDS or now - session["touched"] >= IDLE_SECONDS:
            return await self._error(401, "Sign in to continue")(scope, receive, send)
        if method not in {"GET", "HEAD", "OPTIONS"} and not hmac.compare_digest(request.headers.get("x-csrf-token", ""), session["csrf"]):
            return await self._error(403, "Invalid CSRF token")(scope, receive, send)
        if path == "/api/auth/logout" and method == "POST":
            with self._db() as db:
                db.execute("DELETE FROM sessions WHERE token=?", (digest,))
            response = JSONResponse({"status": "signed_out"}, headers={"Cache-Control": "no-store"})
            response.delete_cookie(COOKIE, secure=True, httponly=True, samesite="strict", path="/")
            return await response(scope, receive, send)
        if path == "/api/auth/me" and method == "GET":
            return await JSONResponse({"user": public_user(user), "csrfToken": session["csrf"]}, headers={"Cache-Control": "no-store"})(scope, receive, send)
        if user["role"] != "super_admin":
            restricted = path.startswith(("/api/admin", "/api/licensing", "/api/auth/users")) or path in {"/api/ai/config", "/docs", "/redoc", "/openapi.json"}
            allowed_write = ((method == "POST" and (path in {"/api/analysis", "/api/employee-risk/analyze", "/api/ai/package", "/api/ai/analyze", "/api/ai/chat", "/api/support/tickets", "/api/platform/logs"} or re.fullmatch(r"/api/runs/[^/]+/(rerun|report)", path)))
                             or (method == "PATCH" and re.fullmatch(r"/api/runs/[^/]+/evidence(?:/[^/]+)?", path)))
            if restricted or (method not in {"GET", "HEAD"} and not allowed_write):
                return await self._error(403, "Your role does not permit this operation")(scope, receive, send)
        if path == "/api/auth/users" and method == "GET":
            return await JSONResponse({"users": [public_user(u) for u in users]}, headers={"Cache-Control": "no-store"})(scope, receive, send)
        with self._db() as db:
            db.execute("UPDATE sessions SET touched=? WHERE token=?", (now, digest))
        scope.setdefault("state", {})["auth_user"] = public_user(user)

        async def secured_send(message):
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() != b"cache-control"]
                headers.append((b"cache-control", b"no-store"))
                # Imported reports render in safe static mode: no scripts, external
                # images, forms or requests that could disclose confidential content.
                if path.startswith(("/reports/", "/api/reports/")):
                    headers.append((b"content-security-policy", b"sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data: 'self'; connect-src 'none'; form-action 'none'; base-uri 'none'"))
                message = {**message, "headers": headers}
            await send(message)
        await self.app(scope, receive, secured_send)
