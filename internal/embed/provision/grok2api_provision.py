#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Provision a running grok2api instance through its Admin API.

Steps performed (all idempotent):
  1. Log in with the bootstrap admin account to obtain a Bearer token.
  2. Ensure a client API key (g2a_...) exists; create it or reveal the
     existing one, then print it.
  3. Optionally import Grok Build account credentials from an auth dir
     (the *.json files produced by grok-build-auth).

This script only talks to the local grok2api service. It is meant to be
called by start-all.ps1, but can also be run directly.

Usage:
  python grok2api_provision.py \
      --base-url http://127.0.0.1:8000 \
      --user admin --password <pwd> \
      --key-name default \
      --auth-dir ./grok-build-auth-main/grok-build-auth-main/cliproxyapi_auth
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from typing import Any

# grok-build OAuth client id (same value grok2api's importer defaults to).
CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"

# grok2api is a local service; never route these calls through an outbound proxy.
NO_PROXY = {"http": None, "https": None}


def _login(session, base: str, user: str, password: str) -> str:
    resp = session.post(
        f"{base}/api/admin/v1/auth/login",
        json={"username": user, "password": password},
        timeout=30,
        proxies=NO_PROXY,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"login failed HTTP {resp.status_code}: {resp.text[:200]}")
    body = resp.json()
    data = body.get("data", body) if isinstance(body, dict) else {}
    token = (data.get("tokens", {}) or {}).get("accessToken")
    if not token:
        raise RuntimeError(f"no accessToken in login response: {resp.text[:200]}")
    return token


def _find_key_id(session, base: str, headers: dict, name: str):
    resp = session.get(
        f"{base}/api/admin/v1/client-keys",
        headers=headers,
        params={"search": name, "pageSize": 100},
        timeout=30,
        proxies=NO_PROXY,
    )
    if resp.status_code != 200:
        return None
    body = resp.json()
    data = body.get("data", body) if isinstance(body, dict) else {}
    for item in data.get("items", []) or []:
        if str(item.get("name")) == name:
            return str(item.get("id"))
    return None


def _reveal_secret(session, base: str, headers: dict, key_id: str):
    resp = session.get(
        f"{base}/api/admin/v1/client-keys/{key_id}/secret",
        headers=headers,
        timeout=30,
        proxies=NO_PROXY,
    )
    if resp.status_code != 200:
        return None
    body = resp.json()
    data = body.get("data", body) if isinstance(body, dict) else {}
    return data.get("secret")


def _create_key(session, base: str, headers: dict, name: str):
    resp = session.post(
        f"{base}/api/admin/v1/client-keys",
        headers=headers,
        json={"name": name, "enabled": True},
        timeout=30,
        proxies=NO_PROXY,
    )
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"create client key failed HTTP {resp.status_code}: {resp.text[:200]}")
    body = resp.json()
    data = body.get("data", body) if isinstance(body, dict) else {}
    return data.get("secret")


def _build_import_document(auth_dir: str) -> tuple[dict[str, Any], int]:
    accounts: list[dict[str, Any]] = []
    for path in sorted(glob.glob(os.path.join(auth_dir, "*.json"))):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception:
            continue
        access = data.get("access_token") or ""
        refresh = data.get("refresh_token") or ""
        if not access and not refresh:
            continue
        entry: dict[str, Any] = {
            "provider": "grok_build",
            "email": data.get("email") or os.path.splitext(os.path.basename(path))[0],
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


def _import_accounts(session, base: str, headers: dict, auth_dir: str) -> None:
    document, count = _build_import_document(auth_dir)
    if count == 0:
        print("[provision] no accounts to import (register some in the WebUI first).")
        return
    payload = json.dumps(document, ensure_ascii=False).encode("utf-8")
    files = {"files": ("grok_build_accounts.json", payload, "application/json")}
    resp = session.post(
        f"{base}/api/admin/v1/accounts/import",
        headers=headers,
        files=files,
        timeout=600,
        proxies=NO_PROXY,
    )
    if resp.status_code not in (200, 201):
        print(f"[provision] account import failed HTTP {resp.status_code}: {resp.text[:200]}")
        return
    ctype = resp.headers.get("Content-Type", "")
    if "text/event-stream" in ctype:
        result = _parse_sse_complete(resp.text)
    else:
        try:
            body = resp.json()
            result = body.get("data", body) if isinstance(body, dict) else {}
        except Exception:
            result = {}
    if result.get("_event") == "error":
        print(f"[provision] account import error: {result.get('message') or result}")
        return
    created = result.get("created")
    updated = result.get("updated")
    skipped = result.get("skipped")
    print(f"[provision] imported {count} account file(s): "
          f"created={created} updated={updated} skipped={skipped}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Provision grok2api via its Admin API.")
    parser.add_argument("--base-url", default=os.environ.get("GROK2API_BASE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--user", default=os.environ.get("GROK2API_ADMIN_USER", "admin"))
    parser.add_argument("--password", default=os.environ.get("GROK2API_ADMIN_PASSWORD", ""))
    parser.add_argument("--key-name", default="default")
    parser.add_argument("--auth-dir", default="")
    args = parser.parse_args()

    try:
        import requests
    except ImportError:
        print("[provision] python package 'requests' is not installed.", file=sys.stderr)
        return 2

    base = args.base_url.rstrip("/")
    if not args.password:
        print("[provision] admin password is empty; cannot log in.", file=sys.stderr)
        return 2

    session = requests.Session()
    # grok2api is a local service; ignore any HTTP(S)_PROXY env so calls to
    # 127.0.0.1 are never routed through an outbound proxy.
    session.trust_env = False
    try:
        token = _login(session, base, args.user, args.password)
    except Exception as exc:
        print(f"[provision] {exc}", file=sys.stderr)
        return 1
    headers = {"Authorization": f"Bearer {token}"}

    # Ensure the client API key exists, then print it.
    try:
        key_id = _find_key_id(session, base, headers, args.key_name)
        if key_id:
            secret = _reveal_secret(session, base, headers, key_id)
            if secret:
                print(f"[provision] existing client key '{args.key_name}' reused.")
            else:
                print(f"[provision] client key '{args.key_name}' exists but secret is hidden.")
        else:
            secret = _create_key(session, base, headers, args.key_name)
            print(f"[provision] created client key '{args.key_name}'.")
        if secret:
            # Marker line consumed by start-all.ps1.
            print(f"APIKEY={secret}")
    except Exception as exc:
        print(f"[provision] client key step failed: {exc}", file=sys.stderr)

    # Optionally import already-generated Grok Build accounts.
    if args.auth_dir and os.path.isdir(args.auth_dir):
        try:
            _import_accounts(session, base, headers, args.auth_dir)
        except Exception as exc:
            print(f"[provision] account import step failed: {exc}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
