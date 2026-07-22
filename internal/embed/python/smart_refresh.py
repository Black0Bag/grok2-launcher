#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Smart refresh: try free token refresh first, recover only revoked accounts.

Usage:
    .venv\\Scripts\\python.exe smart_refresh.py
    .venv\\Scripts\\python.exe smart_refresh.py --delay 4
    .venv\\Scripts\\python.exe smart_refresh.py --recover-limit 20
    .venv\\Scripts\\python.exe smart_refresh.py --no-recover   # only refresh, list revoked

Flow:
  1) refresh_one every cliproxyapi_auth/*.json  (fast, no captcha)
  2) for revoked/invalid_grant only -> recover via password OAuth (slow, costs Turnstile)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT))

try:
    from dotenv import load_dotenv

    load_dotenv(_ROOT / ".env")
except Exception:
    pass

from webui import AUTH_DIR, refresh_one  # noqa: E402
from recover_tokens import load_accounts  # noqa: E402
from xconsole_client.xai_oauth import (  # noqa: E402
    CLIPROXYAPI_GROK_BASE_URL,
    complete_build_oauth,
)


def _is_revoked(err: str) -> bool:
    e = (err or "").lower()
    return "invalid_grant" in e or "revoked" in e


def main() -> int:
    ap = argparse.ArgumentParser(description="Refresh all; recover only revoked")
    ap.add_argument("--auth-dir", default=str(AUTH_DIR))
    ap.add_argument("--accounts-dir", default=str(_ROOT / "accounts_output"))
    ap.add_argument("--delay", type=float, default=4.0, help="delay between recover calls")
    ap.add_argument("--refresh-delay", type=float, default=0.15, help="delay between refresh calls")
    ap.add_argument("--recover-limit", type=int, default=0, help="max recover attempts (0=all revoked)")
    ap.add_argument("--no-recover", action="store_true", help="only refresh, do not recover")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    auth_dir = Path(args.auth_dir)
    files = sorted(auth_dir.glob("*.json"))
    if not files:
        print(f"no auth json in {auth_dir}")
        return 1

    print(f"Phase 1: refresh {len(files)} auth file(s) in {auth_dir}")
    print(f"proxy={(os.environ.get('HTTPS_PROXY') or os.environ.get('HTTP_PROXY') or '(none)')}\n")

    ok_files: list[str] = []
    revoked_emails: list[str] = []
    other_fail: list[tuple[str, str]] = []

    for i, path in enumerate(files, 1):
        try:
            res = refresh_one(path)
        except Exception as e:
            res = {"ok": False, "email": path.stem, "file": path.name, "error": str(e)}
        email = str(res.get("email") or path.stem)
        if res.get("ok"):
            ok_files.append(path.name)
            print(f"[{i}/{len(files)}] REFRESH OK   {email}")
        else:
            err = str(res.get("error") or "")
            if _is_revoked(err):
                revoked_emails.append(email)
                print(f"[{i}/{len(files)}] REVOKED      {email}")
            else:
                other_fail.append((email, err[:120]))
                print(f"[{i}/{len(files)}] FAIL         {email}  {err[:100]}")
        time.sleep(args.refresh_delay)

    print("\n" + "=" * 56)
    print(f"  refresh OK : {len(ok_files)}")
    print(f"  revoked    : {len(revoked_emails)}  (need recover / captcha)")
    print(f"  other fail : {len(other_fail)}")
    print("=" * 56)

    if other_fail:
        print("\nOther failures (not auto-recovered):")
        for em, er in other_fail[:15]:
            print(f"  - {em}: {er}")

    if args.no_recover or not revoked_emails:
        if not revoked_emails:
            print("\nNo revoked tokens. Done. Sync + pack + push when ready.")
        else:
            print(f"\nSkipped recover (--no-recover). Revoked count={len(revoked_emails)}")
            rev_path = auth_dir / "_revoked_list.txt"
            rev_path.write_text("\n".join(revoked_emails), encoding="utf-8")
            print(f"List written: {rev_path}")
        return 0

    # Map email -> account record for recover
    accounts = load_accounts(Path(args.accounts_dir))
    by_email = {a["email"]: a for a in accounts}
    # also allow partial match on local-part
    targets = []
    missing = []
    for em in revoked_emails:
        if em in by_email:
            targets.append(by_email[em])
            continue
        hit = next((a for a in accounts if a["email"] == em or em in a["email"] or a["email"] in em), None)
        if hit:
            targets.append(hit)
        else:
            missing.append(em)

    if missing:
        print(f"\nNo password/SSO in accounts_output for {len(missing)} revoked (cannot recover):")
        for em in missing[:20]:
            print(f"  - {em}")

    if args.recover_limit and args.recover_limit > 0:
        targets = targets[: args.recover_limit]

    if not targets:
        print("\nNothing to recover.")
        return 0 if ok_files else 1

    yes_key = os.environ.get("YESCAPTCHA_API_KEY", "")
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or ""
    print(f"\nPhase 2: recover {len(targets)} revoked account(s) (captcha cost applies)")
    if not yes_key:
        print("WARN: YESCAPTCHA_API_KEY empty — recover will fail without captcha")

    rok = rfail = 0
    for i, a in enumerate(targets, 1):
        email = a["email"]
        cookies = {"sso": a["sso"]} if a.get("sso") else None
        t0 = time.time()
        try:
            res = complete_build_oauth(
                email,
                a.get("password") or "",
                cliproxyapi_auth_dir=str(auth_dir),
                cliproxyapi_base_url=CLIPROXYAPI_GROK_BASE_URL,
                timeout=180.0,
                proxy=proxy,
                yescaptcha_key=yes_key,
                protocol=True,
                debug=args.debug,
                session_cookies=cookies,
                auth_client=None,
            )
            dt = time.time() - t0
            if res.cliproxyapi_path:
                rok += 1
                print(f"[{i}/{len(targets)}] RECOVER OK   {email}  ({dt:.0f}s)")
            else:
                rfail += 1
                print(f"[{i}/{len(targets)}] RECOVER FAIL {email}  (no path)  ({dt:.0f}s)")
        except Exception as e:
            rfail += 1
            dt = time.time() - t0
            print(f"[{i}/{len(targets)}] RECOVER FAIL {email}  {type(e).__name__}: {str(e)[:140]}  ({dt:.0f}s)")
        if i < len(targets):
            time.sleep(args.delay)

    print(f"\ndone: refresh_ok={len(ok_files)} recover_ok={rok} recover_fail={rfail}")
    print("Next: 打开 WebUI（start-webui.bat），点「同步到 grok2api」。")
    return 0 if (ok_files or rok) else 1


if __name__ == "__main__":
    sys.exit(main())
