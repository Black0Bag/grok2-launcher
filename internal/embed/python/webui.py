#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地可视化控制台：注册数量 / 账号列表 / 手动刷新 token / 同步到 grok2api。

启动:
  .venv\\Scripts\\python.exe webui.py
  浏览器打开 http://127.0.0.1:8765
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
import traceback
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT))

try:
    from dotenv import load_dotenv

    load_dotenv(_ROOT / ".env")
except Exception:
    pass

AUTH_DIR = Path(os.environ.get("CLIPROXYAPI_AUTH_DIR") or (_ROOT / "cliproxyapi_auth")).resolve()
# 同步目标：grok2api（数据库 API 模式）。
GROK2API_BASE_URL = (os.environ.get("GROK2API_BASE_URL") or "http://127.0.0.1:8000").rstrip("/")
GROK2API_ADMIN_USER = os.environ.get("GROK2API_ADMIN_USER") or ""
GROK2API_ADMIN_PASSWORD = os.environ.get("GROK2API_ADMIN_PASSWORD") or ""
CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
TOKEN_URL_DEFAULT = "https://auth.x.ai/oauth2/token"
HOST = os.environ.get("WEBUI_HOST", "127.0.0.1")
PORT = int(os.environ.get("WEBUI_PORT", "8765"))
VENV_PY = _ROOT / ".venv" / "Scripts" / "python.exe"
PYTHON = str(VENV_PY if VENV_PY.exists() else sys.executable)

# Job state (single register job at a time)
_job_lock = threading.Lock()
_job: dict[str, Any] = {
    "running": False,
    "kind": None,
    "started_at": None,
    "finished_at": None,
    "log": [],
    "returncode": None,
    "params": {},
}
_MAX_LOG = 800


def _proxy() -> Optional[dict]:
    p = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or ""
    return {"http": p, "https": p} if p else None


def _append_log(line: str) -> None:
    with _job_lock:
        _job["log"].append(line.rstrip("\n"))
        if len(_job["log"]) > _MAX_LOG:
            _job["log"] = _job["log"][-_MAX_LOG:]


def _parse_expired(raw: Any) -> Optional[datetime]:
    if not raw:
        return None
    s = str(raw).strip()
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        return None


def list_accounts() -> list[dict[str, Any]]:
    AUTH_DIR.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    rows: list[dict[str, Any]] = []
    for path in sorted(AUTH_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            rows.append(
                {
                    "file": path.name,
                    "email": path.stem,
                    "error": str(e),
                    "status": "broken",
                }
            )
            continue
        exp = _parse_expired(data.get("expired"))
        secs = None
        status = "unknown"
        if exp is not None:
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            secs = int((exp - now).total_seconds())
            if secs <= 0:
                status = "expired"
            elif secs < 1800:
                status = "expiring"
            else:
                status = "ok"
        else:
            status = "ok" if data.get("access_token") else "no_token"
        rows.append(
            {
                "file": path.name,
                "email": data.get("email") or path.stem,
                "expired": data.get("expired"),
                "last_refresh": data.get("last_refresh"),
                "has_access": bool(data.get("access_token")),
                "has_refresh": bool(data.get("refresh_token")),
                "seconds_left": secs,
                "status": status,
                "quota": _quota_cache.get(path.name),
                "mtime": datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat(),
            }
        )
    return rows


def refresh_one(path: Path) -> dict[str, Any]:
    import requests

    data = json.loads(path.read_text(encoding="utf-8"))
    email = data.get("email") or path.stem
    rt = data.get("refresh_token")
    if not rt:
        return {"ok": False, "email": email, "file": path.name, "error": "no refresh_token"}
    te = data.get("token_endpoint") or TOKEN_URL_DEFAULT
    r = requests.post(
        te,
        data={
            "grant_type": "refresh_token",
            "refresh_token": rt,
            "client_id": CLIENT_ID,
        },
        timeout=40,
        proxies=_proxy(),
    )
    if r.status_code != 200:
        return {
            "ok": False,
            "email": email,
            "file": path.name,
            "error": f"HTTP {r.status_code}: {r.text[:200]}",
        }
    tok = r.json()
    data["access_token"] = tok.get("access_token") or data.get("access_token")
    if tok.get("refresh_token"):
        data["refresh_token"] = tok["refresh_token"]
    if tok.get("id_token"):
        data["id_token"] = tok["id_token"]
    if tok.get("expires_in"):
        data["expires_in"] = tok["expires_in"]
        exp_ts = datetime.now(timezone.utc).timestamp() + int(tok["expires_in"])
        data["expired"] = datetime.fromtimestamp(exp_ts, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    data["last_refresh"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "ok": True,
        "email": email,
        "file": path.name,
        "expired": data.get("expired"),
    }


def refresh_all(files: Optional[list[str]] = None) -> dict[str, Any]:
    targets: list[Path]
    if files:
        targets = [AUTH_DIR / f for f in files]
    else:
        targets = sorted(AUTH_DIR.glob("*.json"))
    ok, fail = [], []
    for path in targets:
        if not path.exists():
            fail.append({"file": path.name, "error": "not found"})
            continue
        try:
            res = refresh_one(path)
            (ok if res.get("ok") else fail).append(res)
            time.sleep(0.25)
        except Exception as e:
            fail.append({"file": path.name, "error": str(e)})
    return {"ok_count": len(ok), "fail_count": len(fail), "ok": ok, "fail": fail}


# --- quota probing (manual, cached) --------------------------------------
# Probing spends 1 request of the account's free quota (a real chat call is the
# only way to read the x-ratelimit-* response headers), so it is never automatic:
# the UI calls it on a button press and results are cached for QUOTA_TTL seconds
# to keep repeated clicks from burning quota.
CHAT_URL = "https://cli-chat-proxy.grok.com/v1/chat/completions"
CHAT_HEADERS = {
    "x-xai-token-auth": "xai-grok-cli",
    "x-grok-client-identifier": "grok-shell",
    "x-grok-client-version": "0.2.93",
    "User-Agent": "grok-shell/0.2.93 (windows; x86_64)",
}
QUOTA_TTL = 1800  # seconds a cached probe result stays fresh
_quota_cache: dict[str, dict[str, Any]] = {}  # file name -> probe record
_quota_lock = threading.Lock()


def _jwt_exp(token: str) -> int:
    import base64

    try:
        seg = token.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        return int(json.loads(base64.urlsafe_b64decode(seg)).get("exp", 0))
    except Exception:
        return 0


def probe_quota_one(path: Path, force: bool = False) -> dict[str, Any]:
    """Probe one account's remaining free quota; cache the result.

    Returns a record with remaining_requests / remaining_tokens / limit_tokens
    and a status word. Reuses refresh_one() to mint a fresh access_token when the
    stored one is expiring. Uses curl_cffi (chrome impersonation) because the
    cli-chat-proxy endpoint sits behind Cloudflare.
    """
    from curl_cffi import requests as cffi

    name = path.name
    with _quota_lock:
        cached = _quota_cache.get(name)
        if cached and not force and (time.time() - cached.get("ts", 0)) < QUOTA_TTL:
            return {"file": name, "cached": True, **cached}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        rec = {"ts": time.time(), "status": "broken", "error": str(e)}
        with _quota_lock:
            _quota_cache[name] = rec
        return {"file": name, **rec}

    email = data.get("email") or path.stem
    access = data.get("access_token") or ""
    if not access or _jwt_exp(access) - time.time() < 120:
        res = refresh_one(path)  # writes new token back to the file
        if not res.get("ok"):
            rec = {"ts": time.time(), "status": "unauthorized", "error": res.get("error", "refresh failed")}
            with _quota_lock:
                _quota_cache[name] = rec
            return {"file": name, "email": email, **rec}
        access = json.loads(path.read_text(encoding="utf-8")).get("access_token") or ""

    headers = dict(CHAT_HEADERS)
    headers["Authorization"] = f"Bearer {access}"
    headers["Content-Type"] = "application/json"
    body = {"model": "grok-4.5", "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 1, "stream": False}
    try:
        r = cffi.post(CHAT_URL, headers=headers, json=body, impersonate="chrome",
                      proxies=_proxy(), timeout=40)
    except Exception as e:
        rec = {"ts": time.time(), "status": "error", "error": f"transport: {e}"}
        with _quota_lock:
            _quota_cache[name] = rec
        return {"file": name, "email": email, **rec}

    def _int(header_name: str) -> Optional[int]:
        try:
            return int(r.headers.get(header_name))
        except (TypeError, ValueError):
            return None

    if r.status_code == 200:
        status = "ok"
    elif r.status_code == 429:
        status = "exhausted"
    elif r.status_code in (401, 403):
        status = "unauthorized"
    else:
        status = f"http_{r.status_code}"

    rec = {
        "ts": time.time(),
        "status": status,
        "http": r.status_code,
        "remaining_requests": _int("x-ratelimit-remaining-requests"),
        "limit_requests": _int("x-ratelimit-limit-requests"),
        "remaining_tokens": _int("x-ratelimit-remaining-tokens"),
        "limit_tokens": _int("x-ratelimit-limit-tokens"),
    }
    with _quota_lock:
        _quota_cache[name] = rec
    return {"file": name, "email": email, **rec}


def probe_quota(files: Optional[list[str]] = None, force: bool = False) -> dict[str, Any]:
    """Probe several accounts serially (cache-respecting unless force)."""
    if files:
        targets = [AUTH_DIR / f for f in files]
    else:
        targets = sorted(AUTH_DIR.glob("*.json"))
    results = []
    for path in targets:
        if not path.exists():
            results.append({"file": path.name, "status": "error", "error": "not found"})
            continue
        try:
            results.append(probe_quota_one(path, force=force))
        except Exception as e:
            results.append({"file": path.name, "status": "error", "error": str(e)})
        time.sleep(0.3)
    return {"count": len(results), "results": results}


def _grok2api_build_document() -> tuple[dict[str, Any], int]:
    """把 cliproxyapi_auth/*.json 转成 grok2api 批量导入格式。

    grok2api 的 /accounts/import 接受 {"accounts":[{provider,email,access_token,
    refresh_token,id_token,client_id,token_type,expires_at}...]}。源文件的 `expired`
    字段已是 RFC3339（如 2026-07-16T08:04:13Z），可直接作为 expires_at。
    """
    accounts: list[dict[str, Any]] = []
    for path in sorted(AUTH_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        access = data.get("access_token") or ""
        refresh = data.get("refresh_token") or ""
        if not access and not refresh:
            continue
        entry: dict[str, Any] = {
            "provider": "grok_build",
            "email": data.get("email") or path.stem,
            "access_token": access,
            "refresh_token": refresh,
            "id_token": data.get("id_token") or "",
            "client_id": CLIENT_ID,
            "token_type": "Bearer",
        }
        expired = data.get("expired")
        if expired:
            entry["expires_at"] = str(expired)
        accounts.append(entry)
    return {"accounts": accounts}, len(accounts)


def _parse_sse_complete(text: str) -> dict[str, Any]:
    """从 grok2api 的 SSE 响应里取出 `complete`/`error` 事件的 data。"""
    event = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("event:"):
            event = line[len("event:"):].strip()
        elif line.startswith("data:") and event in ("complete", "error"):
            payload = line[len("data:"):].strip()
            try:
                obj = json.loads(payload)
            except Exception:
                obj = {"raw": payload}
            obj["_event"] = event
            return obj
    return {}


def sync_to_grok2api() -> dict[str, Any]:
    """通过管理端 API 把 Grok Build 账号批量导入 grok2api（数据库模式）。

    流程：管理员登录拿 Bearer token -> 组装批量导入 JSON -> multipart 上传到
    /api/admin/v1/accounts/import（返回 SSE，读取 complete 事件）。
    """
    import requests

    if not GROK2API_ADMIN_PASSWORD:
        return {"ok": False, "error": "GROK2API_ADMIN_PASSWORD 未设置（请在 .env 填写）"}

    document, count = _grok2api_build_document()
    if count == 0:
        return {"ok": False, "error": "cliproxyapi_auth 里没有可导入的账号（先注册/刷新）"}

    base = GROK2API_BASE_URL
    proxies = _proxy()
    # grok2api 通常是本机服务，不该走出网代理
    local_proxies = None if not proxies else {"http": None, "https": None}

    try:
        lr = requests.post(
            f"{base}/api/admin/v1/auth/login",
            json={"username": GROK2API_ADMIN_USER, "password": GROK2API_ADMIN_PASSWORD},
            timeout=30,
            proxies=local_proxies,
        )
    except Exception as e:
        return {"ok": False, "error": f"连接 grok2api 失败（{base}）：{e}"}
    if lr.status_code != 200:
        return {"ok": False, "error": f"登录失败 HTTP {lr.status_code}: {lr.text[:200]}"}
    try:
        token = (lr.json().get("data", {}) or {}).get("tokens", {}).get("accessToken")
    except Exception:
        token = None
    if not token:
        # 兼容不带 data 包裹的返回形态
        try:
            token = lr.json().get("tokens", {}).get("accessToken")
        except Exception:
            token = None
    if not token:
        return {"ok": False, "error": f"登录返回里找不到 accessToken: {lr.text[:200]}"}

    payload = json.dumps(document, ensure_ascii=False).encode("utf-8")
    files = {"files": ("grok_build_accounts.json", payload, "application/json")}
    try:
        ir = requests.post(
            f"{base}/api/admin/v1/accounts/import",
            headers={"Authorization": f"Bearer {token}"},
            files=files,
            timeout=300,
            proxies=local_proxies,
        )
    except Exception as e:
        return {"ok": False, "error": f"导入请求失败：{e}"}
    if ir.status_code not in (200, 201):
        return {"ok": False, "error": f"导入失败 HTTP {ir.status_code}: {ir.text[:300]}"}

    ctype = ir.headers.get("Content-Type", "")
    if "text/event-stream" in ctype:
        result = _parse_sse_complete(ir.text)
        if result.get("_event") == "error":
            return {"ok": False, "submitted": count, "error": result.get("message") or "导入报错"}
    else:
        # 兼容普通 JSON 返回
        try:
            body = ir.json()
            result = body.get("data", body) if isinstance(body, dict) else {}
        except Exception:
            result = {}

    return {
        "ok": True,
        "submitted": count,
        "created": result.get("created") or result.get("Created"),
        "updated": result.get("updated") or result.get("Updated"),
        "skipped": result.get("skipped") or result.get("Skipped"),
        "grok2api_base": base,
    }


def start_register(count: int, threads: int = 1, email_backend: str = "tempmail") -> dict[str, Any]:
    count = max(1, min(int(count), 30))
    threads = max(1, min(int(threads), count, 3))
    with _job_lock:
        if _job["running"]:
            return {"ok": False, "error": "已有任务在运行，请等待结束后再试"}
        _job.update(
            {
                "running": True,
                "kind": "register",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "finished_at": None,
                "log": [],
                "returncode": None,
                "params": {"count": count, "threads": threads, "email": email_backend},
            }
        )

    def worker() -> None:
        cmd = [
            PYTHON,
            str(_ROOT / "run.py"),
            "-n",
            str(count),
            "-t",
            str(threads),
            "-e",
            email_backend,
        ]
        _append_log(f"$ {' '.join(cmd)}")
        try:
            env = os.environ.copy()
            proc = subprocess.Popen(
                cmd,
                cwd=str(_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                _append_log(line)
            rc = proc.wait()
            with _job_lock:
                _job["returncode"] = rc
                _job["finished_at"] = datetime.now(timezone.utc).isoformat()
                _job["running"] = False
            _append_log(f"[done] exit={rc}")
            _append_log("[提示] 注册完成。请在页面上点「同步到 grok2api」把账号导入网关。")
        except Exception as e:
            _append_log(f"[error] {e}")
            _append_log(traceback.format_exc())
            with _job_lock:
                _job["returncode"] = -1
                _job["finished_at"] = datetime.now(timezone.utc).isoformat()
                _job["running"] = False

    threading.Thread(target=worker, daemon=True).start()
    return {"ok": True, "message": f"已开始注册 {count} 个账号", "params": _job["params"]}


def job_status() -> dict[str, Any]:
    with _job_lock:
        return {
            "running": _job["running"],
            "kind": _job["kind"],
            "started_at": _job["started_at"],
            "finished_at": _job["finished_at"],
            "returncode": _job["returncode"],
            "params": _job["params"],
            "log": list(_job["log"][-200:]),
            "log_total": len(_job["log"]),
        }


def captcha_balance() -> dict[str, Any]:
    import requests

    key = (os.environ.get("YESCAPTCHA_API_KEY") or "").strip()
    if not key:
        return {"ok": False, "error": "YESCAPTCHA_API_KEY 未设置"}
    try:
        r = requests.post(
            "https://api.yescaptcha.com/getBalance",
            json={"clientKey": key},
            timeout=20,
            proxies=_proxy(),
        )
        data = r.json()
        return {"ok": data.get("errorId", 1) == 0, "raw": data, "balance": data.get("balance")}
    except Exception as e:
        return {"ok": False, "error": str(e)}


HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Grok Build Auth 控制台</title>
<style>
  :root {
    --bg: #0b1020;
    --card: #121a2f;
    --line: #24304d;
    --text: #e8eefc;
    --muted: #93a0bf;
    --ok: #3dd68c;
    --warn: #f5c542;
    --bad: #ff6b7a;
    --accent: #6ea8fe;
    --accent2: #9b7bff;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: "Segoe UI", system-ui, sans-serif;
    background: radial-gradient(1200px 600px at 10% -10%, #1a2748 0%, transparent 50%),
                radial-gradient(900px 500px at 100% 0%, #2a1a48 0%, transparent 45%),
                var(--bg);
    color: var(--text);
    min-height: 100vh;
  }
  .wrap { max-width: 1100px; margin: 0 auto; padding: 28px 18px 60px; }
  h1 { font-size: 1.5rem; margin: 0 0 6px; letter-spacing: .2px; }
  .sub { color: var(--muted); margin-bottom: 22px; font-size: .95rem; }
  .grid { display: grid; grid-template-columns: 1.1fr 1fr; gap: 16px; }
  @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
  .card {
    background: linear-gradient(180deg, rgba(255,255,255,.03), transparent), var(--card);
    border: 1px solid var(--line);
    border-radius: 14px;
    padding: 16px 16px 14px;
    box-shadow: 0 10px 30px rgba(0,0,0,.25);
  }
  .card h2 { margin: 0 0 12px; font-size: 1.05rem; }
  label { display: block; color: var(--muted); font-size: .85rem; margin-bottom: 6px; }
  .row { display: flex; gap: 10px; flex-wrap: wrap; align-items: end; margin-bottom: 10px; }
  input, select {
    background: #0c1324;
    border: 1px solid var(--line);
    color: var(--text);
    border-radius: 10px;
    padding: 10px 12px;
    min-width: 100px;
  }
  button {
    border: 0;
    border-radius: 10px;
    padding: 10px 14px;
    font-weight: 600;
    cursor: pointer;
    color: #081018;
    background: linear-gradient(135deg, var(--accent), var(--accent2));
  }
  button.secondary {
    background: #1a243d;
    color: var(--text);
    border: 1px solid var(--line);
  }
  button:disabled { opacity: .5; cursor: not-allowed; }
  .stats { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 12px; }
  .pill {
    border: 1px solid var(--line);
    background: #0d1528;
    border-radius: 999px;
    padding: 6px 12px;
    font-size: .85rem;
    color: var(--muted);
  }
  .pill b { color: var(--text); }
  table { width: 100%; border-collapse: collapse; font-size: .9rem; }
  th, td { text-align: left; padding: 9px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { color: var(--muted); font-weight: 600; font-size: .8rem; }
  .tag {
    display: inline-block;
    border-radius: 999px;
    padding: 2px 8px;
    font-size: .75rem;
    font-weight: 700;
  }
  .tag.ok { background: rgba(61,214,140,.15); color: var(--ok); }
  .tag.expiring { background: rgba(245,197,66,.15); color: var(--warn); }
  .tag.expired { background: rgba(255,107,122,.15); color: var(--bad); }
  .tag.unknown, .tag.no_token, .tag.broken { background: #24304d; color: var(--muted); }
  .log {
    background: #070c18;
    border: 1px solid var(--line);
    border-radius: 10px;
    height: 280px;
    overflow: auto;
    padding: 10px 12px;
    font-family: ui-monospace, Consolas, monospace;
    font-size: .78rem;
    line-height: 1.45;
    white-space: pre-wrap;
    color: #c9d6f5;
  }
  .hint { color: var(--muted); font-size: .82rem; margin-top: 8px; line-height: 1.45; }
  .email { word-break: break-all; }
  .full { grid-column: 1 / -1; }
  .actions button { margin-right: 0; }
</style>
</head>
<body>
<div class="wrap">
  <h1>Grok Build Auth 控制台</h1>
  <div class="sub">手动选择注册数量 · 查看 6 小时有效期 · 到期一键刷新 · 同步到 grok2api</div>

  <div class="stats" id="stats"></div>

  <div class="grid">
    <div class="card">
      <h2>注册账号</h2>
      <div class="row">
        <div>
          <label>数量 (1–30)</label>
          <input id="count" type="number" min="1" max="30" value="1" />
        </div>
        <div>
          <label>并发线程</label>
          <input id="threads" type="number" min="1" max="3" value="1" />
        </div>
        <div>
          <label>邮箱后端</label>
          <select id="email">
            <option value="tempmail">tempmail</option>
            <option value="cloudflare">cloudflare</option>
          </select>
        </div>
        <button id="btnRegister">开始注册</button>
      </div>
      <div class="hint">串行（线程=1）更稳。每个账号约 1 分钟（打码+邮箱+OAuth）。注册结束后不会自动同步，请手动点「同步到 grok2api」。</div>
    </div>

    <div class="card">
      <h2>Token 刷新 / 同步</h2>
      <div class="row actions">
        <button id="btnRefreshAll">刷新全部 token</button>
        <button class="secondary" id="btnSyncG2A">同步到 grok2api</button>
        <button class="secondary" id="btnReload">刷新列表</button>
        <button class="secondary" id="btnQuotaAll">测额度(未探测的)</button>
      </div>
      <div class="hint">access_token 约 6 小时过期。到期或出现 401 时点「刷新全部」。刷新成功后再点「同步到 grok2api」，网关即可继续用 <code>grok-4.5</code>。</div>
      <div class="hint">「同步到 grok2api」：用管理员账号登录，把当前 token 批量导入到 grok2api 数据库（需先在 <code>.env</code> 填 <code>GROK2API_*</code>）。</div>
      <div class="hint">⚠️ 「测额度」会给每个号发一次真实请求，<b>消耗该号 1 次额度</b>；结果缓存 30 分钟，不会重复烧。「测额度(未探测的)」只测还没缓存的号；单行「测」按钮可强制重测某个号。</div>
      <div class="hint" id="balanceLine">YesCaptcha 余额：加载中…</div>
    </div>

    <div class="card full">
      <h2>账号列表 <span id="accCount" style="color:var(--muted);font-weight:500"></span></h2>
      <div style="overflow:auto">
        <table>
          <thead>
            <tr>
              <th>状态</th>
              <th>邮箱</th>
              <th>剩余</th>
              <th>额度(请求/token)</th>
              <th>过期时间 (UTC)</th>
              <th>文件</th>
              <th></th>
            </tr>
          </thead>
          <tbody id="tbody"></tbody>
        </table>
      </div>
    </div>

    <div class="card full">
      <h2>任务日志</h2>
      <div class="log" id="log"></div>
    </div>
  </div>
</div>
<script>
function fmtLeft(sec) {
  if (sec === null || sec === undefined) return "-";
  if (sec <= 0) return "已过期";
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}
function tag(status) {
  const map = {ok:"可用", expiring:"即将过期", expired:"已过期", no_token:"无token", broken:"损坏", unknown:"未知"};
  return `<span class="tag ${status}">${map[status] || status}</span>`;
}
function fmtQuota(q) {
  if (!q) return `<span style="color:var(--muted)">未探测</span>`;
  const age = Math.max(0, Math.floor(Date.now()/1000 - (q.ts||0)));
  const ageStr = age<60 ? `${age}s前` : age<3600 ? `${Math.floor(age/60)}m前` : `${Math.floor(age/3600)}h前`;
  if (q.status === "ok") {
    const rr = q.remaining_requests ?? "?", lr = q.limit_requests ?? "?";
    const rt = q.remaining_tokens != null ? Math.round(q.remaining_tokens/1000)+"k" : "?";
    return `<span style="color:#3fb950">${rr}/${lr} 请求 · ${rt} tok</span> <span style="color:var(--muted);font-size:11px">${ageStr}</span>`;
  }
  const label = {exhausted:"已耗尽", unauthorized:"失效", broken:"损坏", error:"错误"}[q.status] || q.status;
  return `<span style="color:#f85149">${label}</span> <span style="color:var(--muted);font-size:11px">${ageStr}</span>`;
}
async function api(path, opts) {
  let r;
  try {
    r = await fetch(path, opts);
  } catch (e) {
    throw new Error(
      "无法连接控制台服务 (127.0.0.1:8765)。请先运行 start-webui.bat 并保持窗口不关闭。原始错误: " +
      (e && e.message ? e.message : e)
    );
  }
  let j;
  try {
    j = await r.json();
  } catch (e) {
    throw new Error("服务返回了非 JSON 响应，HTTP " + r.status);
  }
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}
function setStats(accounts, job) {
  const total = accounts.length;
  const ok = accounts.filter(a => a.status === "ok").length;
  const exp = accounts.filter(a => a.status === "expired" || a.status === "expiring").length;
  const run = job.running ? "运行中" : "空闲";
  document.getElementById("stats").innerHTML = `
    <div class="pill">账号 <b>${total}</b></div>
    <div class="pill">可用 <b>${ok}</b></div>
    <div class="pill">过期/将过期 <b>${exp}</b></div>
    <div class="pill">任务 <b>${run}</b></div>
    <div class="pill">auth 目录 <b>cliproxyapi_auth</b></div>
  `;
  document.getElementById("accCount").textContent = `(${total})`;
}
function renderAccounts(accounts) {
  const tb = document.getElementById("tbody");
  tb.innerHTML = accounts.map(a => `
    <tr>
      <td>${tag(a.status)}</td>
      <td class="email">${a.email || ""}</td>
      <td>${fmtLeft(a.seconds_left)}</td>
      <td>${fmtQuota(a.quota)}</td>
      <td>${a.expired || "-"}</td>
      <td class="email">${a.file}</td>
      <td>
        <button class="secondary" data-file="${a.file}" onclick="probeOne(this.dataset.file)">测</button>
        <button class="secondary" data-file="${a.file}" onclick="refreshOne(this.dataset.file)">刷新</button>
      </td>
    </tr>
  `).join("") || `<tr><td colspan="7" style="color:var(--muted)">暂无账号，先注册一个</td></tr>`;
}
function renderLog(job) {
  const el = document.getElementById("log");
  const text = (job.log || []).join("\n");
  const stick = el.scrollTop + el.clientHeight >= el.scrollHeight - 30;
  el.textContent = text || "暂无日志";
  if (stick) el.scrollTop = el.scrollHeight;
}
async function refreshList() {
  const [accounts, job] = await Promise.all([
    api("/api/accounts"),
    api("/api/job"),
  ]);
  setStats(accounts.accounts, job);
  renderAccounts(accounts.accounts);
  renderLog(job);
  document.getElementById("btnRegister").disabled = !!job.running;
}
async function loadBalance() {
  try {
    const b = await api("/api/balance");
    document.getElementById("balanceLine").textContent =
      b.ok ? `YesCaptcha 余额：${b.balance}` : `YesCaptcha：${b.error || "查询失败"}`;
  } catch (e) {
    document.getElementById("balanceLine").textContent = "YesCaptcha：查询失败";
  }
}
document.getElementById("btnRegister").onclick = async () => {
  const count = Number(document.getElementById("count").value || 1);
  const threads = Number(document.getElementById("threads").value || 1);
  const email = document.getElementById("email").value;
  try {
    const res = await api("/api/register", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({count, threads, email}),
    });
    alert(res.message || "已开始");
    refreshList();
  } catch (e) { alert(e.message); }
};
document.getElementById("btnRefreshAll").onclick = async () => {
  if (!confirm("确认刷新全部账号 token？")) return;
  try {
    const res = await api("/api/refresh", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({}),
    });
    alert(`刷新完成：成功 ${res.ok_count}，失败 ${res.fail_count}`);
    refreshList();
  } catch (e) { alert(e.message); }
};
async function refreshOne(file) {
  try {
    const res = await api("/api/refresh", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({files:[file]}),
    });
    alert(res.ok_count ? "刷新成功" : (res.fail[0]?.error || "失败"));
    refreshList();
  } catch (e) { alert(e.message); }
}
async function probeOne(file) {
  try {
    const res = await api("/api/quota", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({files:[file], force:true}),
    });
    const q = (res.results && res.results[0]) || {};
    if (q.status === "ok") {
      alert(`额度：剩余 ${q.remaining_requests}/${q.limit_requests} 请求，${Math.round((q.remaining_tokens||0)/1000)}k token`);
    } else {
      alert(`状态：${q.status}${q.error ? " — " + q.error : ""}`);
    }
    refreshList();
  } catch (e) { alert(e.message); }
}
document.getElementById("btnQuotaAll").onclick = async () => {
  if (!confirm("给所有『未探测』的号各发一次请求测额度？每号消耗 1 次额度，结果缓存 30 分钟。")) return;
  const btn = document.getElementById("btnQuotaAll");
  btn.disabled = true; btn.textContent = "探测中…";
  try {
    const res = await api("/api/quota", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({}),  // no files = all, cache-respecting (force=false)
    });
    const ok = (res.results||[]).filter(r => r.status === "ok").length;
    alert(`探测完成：${res.count} 个号，其中 ${ok} 个可用`);
    refreshList();
  } catch (e) { alert(e.message); }
  finally { btn.disabled = false; btn.textContent = "测额度(未探测的)"; }
};
document.getElementById("btnSyncG2A").onclick = async () => {
  if (!confirm("用管理员账号登录 grok2api 并批量导入当前 token？(需先在 .env 填 GROK2API_BASE_URL / 账号密码)")) return;
  const btn = document.getElementById("btnSyncG2A");
  btn.disabled = true; btn.textContent = "同步中…";
  try {
    const res = await api("/api/sync_grok2api", {method:"POST", headers:{"Content-Type":"application/json"}, body:"{}"});
    if (res.ok) {
      alert(`已导入 grok2api：提交 ${res.submitted} 个；新增 ${res.created ?? "?"}，更新 ${res.updated ?? "?"}，跳过 ${res.skipped ?? "?"}`);
    } else {
      alert("同步失败：" + (res.error || "未知错误"));
    }
  } catch (e) { alert(e.message); }
  finally { btn.disabled = false; btn.textContent = "同步到 grok2api"; }
};
document.getElementById("btnReload").onclick = () => refreshList();
refreshList();
loadBalance();
setInterval(refreshList, 3000);
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        # quieter console
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, code: int, body: Any, content_type: str = "application/json; charset=utf-8") -> None:
        if isinstance(body, (dict, list)):
            raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            raw = body.encode("utf-8")
        else:
            raw = body
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _read_json(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return {}
        raw = self.rfile.read(n)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def do_GET(self) -> None:  # noqa: N802
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            self._send(200, HTML, "text/html; charset=utf-8")
            return
        if u.path == "/api/accounts":
            self._send(200, {"accounts": list_accounts(), "auth_dir": str(AUTH_DIR)})
            return
        if u.path == "/api/job":
            self._send(200, job_status())
            return
        if u.path == "/api/balance":
            self._send(200, captcha_balance())
            return
        if u.path == "/api/health":
            self._send(200, {"ok": True, "auth_dir": str(AUTH_DIR)})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        u = urlparse(self.path)
        data = self._read_json()
        try:
            if u.path == "/api/register":
                self._send(
                    200,
                    start_register(
                        count=int(data.get("count") or 1),
                        threads=int(data.get("threads") or 1),
                        email_backend=str(data.get("email") or "tempmail"),
                    ),
                )
                return
            if u.path == "/api/refresh":
                files = data.get("files")
                self._send(200, refresh_all(files if isinstance(files, list) else None))
                return
            if u.path == "/api/quota":
                files = data.get("files")
                self._send(200, probe_quota(
                    files if isinstance(files, list) else None,
                    force=bool(data.get("force")),
                ))
                return
            if u.path == "/api/sync_grok2api":
                self._send(200, sync_to_grok2api())
                return
            self._send(404, {"error": "not found"})
        except Exception as e:
            self._send(500, {"error": str(e), "trace": traceback.format_exc()[-800:]})


def main() -> None:
    AUTH_DIR.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Grok Build Auth WebUI")
    print(f"  open:     http://{HOST}:{PORT}/")
    print(f"  auth_dir: {AUTH_DIR}")
    print("  Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
        server.server_close()


if __name__ == "__main__":
    main()
