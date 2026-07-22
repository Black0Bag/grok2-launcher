# -*- coding: utf-8 -*-
"""Protocolized xAI OAuth login (no browser) for Grok Build / CLIProxyAPI.

After account signup (or with email/password), this module:

  1. Starts OAuth PKCE against auth.x.ai
  2. Lands on accounts.x.ai/sign-in?redirect=oauth2-provider&return_to=/oauth2/consent?...
  3. Solves Cloudflare Turnstile via YesCaptcha
  4. Calls auth_mgmt.AuthManagement/CreateSession (gRPC-web)
  5. Follows cookieSetterUrl + OAuth redirects to capture authorization code
  6. Exchanges code for tokens and exports CLIProxyAPI Grok Build auth JSON

CreateSessionRequest wire layout (reverse-engineered 2026-07):

  field 1  Credentials {
      field 1  EmailAndPassword { email=1, clearTextPassword=2 }
  }
  field 4  AntiAbuseToken {
      field 1  turnstileToken
      field 2  castleRequestToken (optional, may be empty)
  }
"""
from __future__ import annotations

import re
import secrets
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlencode, urljoin, urlparse

from . import grpcweb
from .solver import YesCaptchaSolver
from .xai_oauth import (
    AUTHORIZATION_ENDPOINT,
    CLIPROXYAPI_GROK_BASE_URL,
    DEFAULT_CLIENT_ID,
    DEFAULT_SCOPES,
    OAuthLoginResult,
    TOKEN_ENDPOINT,
    _finalize_oauth_code,
    build_authorization_url,
    code_challenge_s256,
    generate_code_verifier,
)

TURNSTILE_SITEKEY = "0x4AAAAAAAhr9JGVDZbrZOo0"
CREATE_SESSION_RPC = "https://accounts.x.ai/auth_mgmt.AuthManagement/CreateSession"
CREATE_COOKIE_SETTER_RPC = "https://accounts.x.ai/auth_mgmt.AuthManagement/CreateCookieSetterLink"
ACCOUNTS_ORIGIN = "https://accounts.x.ai"
# Observed Next.js server action for the consent Allow button (may change on deploy).
SUBMIT_OAUTH2_CONSENT_ACTION = "4005315a1d7e426de592990bb54bb37471f39dd6d2"


def _enc_msg(field_no: int, raw: bytes) -> bytes:
    return grpcweb.encode_bytes(field_no, raw)


def encode_create_session_request(
    email: str,
    password: str,
    *,
    turnstile_token: str,
    castle_request_token: str = "",
) -> bytes:
    """Encode CreateSessionRequest protobuf body."""
    email_pw = grpcweb.encode_string(1, email) + grpcweb.encode_string(2, password)
    # Credentials.credentials oneof emailAndPassword = field 1
    credentials = _enc_msg(1, email_pw)
    # CreateSessionRequest.credentials = field 1
    req = _enc_msg(1, credentials)
    # CreateSessionRequest.anti_abuse_token = field 4
    anti = grpcweb.encode_string(1, turnstile_token)
    if castle_request_token:
        anti += grpcweb.encode_string(2, castle_request_token)
    else:
        anti += grpcweb.encode_string(2, "")
    req += _enc_msg(4, anti)
    return req


def _grpc_headers(referer: str) -> Dict[str, str]:
    return {
        "content-type": "application/grpc-web+proto",
        "x-grpc-web": "1",
        "x-user-agent": "connect-es/2.1.1",
        "accept": "*/*",
        "origin": ACCOUNTS_ORIGIN,
        "referer": referer,
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
    }


def _extract_urls_from_fields(fields: List[Dict[str, Any]]) -> List[str]:
    urls: List[str] = []
    for f in fields:
        if f.get("type") == "string":
            val = str(f.get("value") or "")
            if val.startswith("http://") or val.startswith("https://"):
                urls.append(val)
        elif f.get("type") == "bytes" and f.get("hex"):
            try:
                raw = bytes.fromhex(f["hex"])
                nested = grpcweb.decode_message(raw)
                urls.extend(_extract_urls_from_fields(nested))
            except Exception:
                pass
    return urls


def _parse_grpc_error(headers: Dict[str, str], body: bytes) -> Tuple[Optional[int], str]:
    # Trailers may be in body frames or HTTP headers (connect/grpc-web).
    status = headers.get("grpc-status")
    message = unquote(headers.get("grpc-message") or "")
    if status is not None:
        try:
            return int(status), message
        except ValueError:
            return None, message
    try:
        parsed = grpcweb.parse_response(body)
    except Exception:
        return None, message
    if parsed.get("grpc_status") is not None:
        return int(parsed["grpc_status"]), message or str(parsed.get("trailers") or "")
    return None, message


def extract_cookies_from_auth_client(client: Any) -> Dict[str, str]:
    """Best-effort dump of name->value cookies from XConsoleAuthClient."""
    out: Dict[str, str] = {}
    try:
        jar = client._t.cookies  # type: ignore[attr-defined]
    except Exception:
        return out
    # dict-like
    try:
        if hasattr(jar, "items"):
            for k, v in jar.items():
                if k and v is not None:
                    out[str(k)] = str(v)
            if out:
                return out
    except Exception:
        pass
    # curl_cffi jar iteration
    try:
        iterable = jar.jar if hasattr(jar, "jar") else jar
        for ck in iterable:
            name = getattr(ck, "name", None)
            value = getattr(ck, "value", None)
            if name and value is not None:
                out[str(name)] = str(value)
    except Exception:
        pass
    return out


class ProtocolOAuthClient:
    """HTTP-only OAuth client using curl_cffi fingerprint + YesCaptcha."""

    def __init__(
        self,
        *,
        yescaptcha_key: str = "",
        proxy: str = "",
        impersonate: str = "chrome131",
        debug: bool = False,
        turnstile_premium: bool = True,
    ):
        self.debug = debug
        self.turnstile_premium = turnstile_premium
        self._yescaptcha_key = (yescaptcha_key or "").strip()
        self.solver: Optional[YesCaptchaSolver] = None
        if self._yescaptcha_key:
            self.solver = YesCaptchaSolver(self._yescaptcha_key, debug=debug)
        try:
            from curl_cffi import requests as creq
        except ImportError as exc:
            raise RuntimeError("curl_cffi is required for protocol OAuth") from exc
        kwargs: Dict[str, Any] = {"impersonate": impersonate}
        if proxy:
            kwargs["proxies"] = {"http": proxy, "https": proxy}
        self._s = creq.Session(**kwargs)

    def load_cookies(self, cookies: Dict[str, str]) -> None:
        """Inject pre-existing accounts.x.ai session cookies (e.g. post-signup)."""
        if not cookies:
            return
        for name, value in cookies.items():
            try:
                # Prefer domain-scoped cookies for accounts.x.ai
                self._s.cookies.set(name, value, domain="accounts.x.ai")
            except Exception:
                try:
                    self._s.cookies.set(name, value)
                except Exception:
                    pass
        self._log(f"loaded {len(cookies)} cookies into OAuth session")

    def _log(self, msg: str) -> None:
        if self.debug:
            print(f"  [oauth-protocol] {msg}")

    def _get(self, url: str, *, allow_redirects: bool = True, headers: Optional[Dict[str, str]] = None):
        h = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "upgrade-insecure-requests": "1",
        }
        if headers:
            h.update(headers)
        return self._s.get(url, headers=h, allow_redirects=allow_redirects, timeout=45)

    def _set_sso_cookie(self, jwt_token: str, domains: Optional[Tuple[str, ...]] = None) -> None:
        """Attach session JWT as ``sso`` cookie on selected domains.

        Important: CreateSession's session_jwt is the real accounts.x.ai session.
        The multi-domain set-cookie hop's ``config.token`` is for .grok.com family
        only — applying it onto accounts.x.ai **clobbers** the real session and
        makes consent redirect back to sign-in (observed 2026-07).
        """
        if not jwt_token:
            return
        if domains is None:
            domains = (
                "accounts.x.ai",
                ".x.ai",
                "auth.x.ai",
                ".grok.com",
                "auth.grok.com",
                ".grokusercontent.com",
                "auth.grokusercontent.com",
                ".grokipedia.com",
                "auth.grokipedia.com",
            )
        set_ok = False
        for domain in domains:
            try:
                self._s.cookies.set("sso", jwt_token, domain=domain)
                set_ok = True
            except Exception:
                continue
        if not set_ok:
            try:
                self._s.cookies.set("sso", jwt_token)
            except Exception:
                pass

    # Domains that receive the set-cookie hop token (NOT accounts.x.ai).
    _GROK_SSO_DOMAINS: Tuple[str, ...] = (
        ".grok.com",
        "auth.grok.com",
        ".grokusercontent.com",
        "auth.grokusercontent.com",
        ".grokipedia.com",
        "auth.grokipedia.com",
    )
    _ACCOUNTS_SSO_DOMAINS: Tuple[str, ...] = (
        "accounts.x.ai",
        ".x.ai",
        "auth.x.ai",
    )

    def create_cookie_setter_link(
        self,
        success_url: str,
        *,
        error_url: str = f"{ACCOUNTS_ORIGIN}/sign-in",
        referer: str = f"{ACCOUNTS_ORIGIN}/sign-in",
    ) -> Dict[str, Any]:
        """Call CreateCookieSetterLink; returns cookie_setter_url for the multi-domain hop."""
        msg = grpcweb.encode_string(1, success_url) + grpcweb.encode_string(2, error_url)
        resp = self._s.post(
            CREATE_COOKIE_SETTER_RPC,
            headers=_grpc_headers(referer),
            data=grpcweb.frame_request(msg),
            timeout=45,
        )
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        header_status, header_msg = _parse_grpc_error(hdrs, resp.content)
        try:
            parsed = grpcweb.parse_response(resp.content)
        except Exception:
            parsed = {"messages": [], "trailers": {}, "grpc_status": None}
        grpc_status = parsed.get("grpc_status")
        if grpc_status is None:
            grpc_status = header_status
        grpc_msg = header_msg or unquote(str((parsed.get("trailers") or {}).get("grpc-message") or ""))
        fields = parsed["messages"][0] if parsed.get("messages") else []
        urls = _extract_urls_from_fields(fields)
        cookie_setter = next((u for u in urls if "set-cookie" in u), None) or (urls[0] if urls else None)
        ok = grpc_status in (None, 0) and bool(cookie_setter)
        return {
            "ok": ok,
            "error": None if ok else (grpc_msg or "CreateCookieSetterLink failed"),
            "grpc_status": grpc_status,
            "cookie_setter_url": cookie_setter,
            "raw_fields": fields,
        }

    def create_session(self, email: str, password: str, *, referer: str) -> Dict[str, Any]:
        """Call CreateSession; on success stores sso JWT on the session.

        CreateSession field 2 is a session JWT (not the cookie-setter URL).
        Call :meth:`create_cookie_setter_link` next with the OAuth consent URL.
        """
        if not self.solver:
            return {
                "ok": False,
                "error": "YESCAPTCHA_API_KEY required for CreateSession Turnstile",
                "grpc_status": None,
                "session_jwt": None,
                "raw_fields": [],
            }
        self._log("solving Turnstile for sign-in...")
        turnstile = self.solver.solve_turnstile(
            website_url=referer.split("#")[0],
            website_key=TURNSTILE_SITEKEY,
            premium=self.turnstile_premium,
        )
        self._log(f"Turnstile {len(turnstile)} chars")

        body = encode_create_session_request(
            email, password, turnstile_token=turnstile, castle_request_token=""
        )
        framed = grpcweb.frame_request(body)
        resp = self._s.post(
            CREATE_SESSION_RPC,
            headers=_grpc_headers(referer),
            data=framed,
            timeout=45,
        )
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        header_status, header_msg = _parse_grpc_error(hdrs, resp.content)
        try:
            parsed = grpcweb.parse_response(resp.content)
        except Exception:
            parsed = {"messages": [], "trailers": {}, "grpc_status": None}

        grpc_status = parsed.get("grpc_status")
        if grpc_status is None:
            grpc_status = header_status
        grpc_msg = header_msg
        if not grpc_msg and parsed.get("trailers"):
            grpc_msg = unquote(str(parsed["trailers"].get("grpc-message") or ""))

        fields = parsed["messages"][0] if parsed.get("messages") else []
        session_jwt = None
        for f in fields:
            if f.get("type") == "string":
                val = str(f.get("value") or "")
                if val.startswith("eyJ") and val.count(".") >= 2:
                    session_jwt = val
                    break

        if grpc_status not in (None, 0) or not session_jwt:
            return {
                "ok": False,
                "error": grpc_msg or (
                    f"CreateSession failed (status={grpc_status}, fields={len(fields)})"
                ),
                "grpc_status": grpc_status,
                "session_jwt": session_jwt,
                "raw_fields": fields,
            }

        self._set_sso_cookie(session_jwt)
        self._log(f"CreateSession OK session_jwt={session_jwt[:24]}...")
        return {
            "ok": True,
            "error": None,
            "grpc_status": 0 if grpc_status is None else grpc_status,
            "session_jwt": session_jwt,
            "raw_fields": fields,
        }

    @staticmethod
    def _absolute_return_to(url: str) -> Optional[str]:
        """Extract absolute return_to target from a sign-in URL."""
        qs = parse_qs(urlparse(url).query)
        rt = (qs.get("return_to") or [""])[0]
        if not rt:
            return None
        rt = unquote(rt)
        if rt.startswith("/"):
            return ACCOUNTS_ORIGIN + rt
        if rt.startswith("http://") or rt.startswith("https://"):
            return rt
        return urljoin(ACCOUNTS_ORIGIN + "/", rt)

    def _consume_set_cookie_url(self, setter_url: str) -> str:
        """Process a multi-domain set-cookie hop.

        Recent xAI deploys often return HTTP 403 on auth.grok.com/set-cookie for
        pure HTTP clients. The JWT in ``?q=`` still carries ``config.token`` and
        ``config.success_url``.

        Critical: ``config.token`` must ONLY be applied to .grok.com family domains.
        Never overwrite accounts.x.ai ``sso`` (that is CreateSession's session_jwt).
        """
        from .sso import parse_jwt_payload, _extract_jwt_from_url

        jwt = _extract_jwt_from_url(setter_url) or ""
        payload = parse_jwt_payload(jwt) if jwt else None
        cfg = (payload or {}).get("config") if isinstance(payload, dict) else None
        token = ""
        success = ""
        if isinstance(cfg, dict):
            token = str(cfg.get("token") or "")
            success = str(cfg.get("success_url") or "")
        if token:
            # Grok-family only — do NOT touch accounts.x.ai sso.
            self._set_sso_cookie(token, domains=self._GROK_SSO_DOMAINS)
            self._log(f"offline-applied set-cookie token on grok domains ({token[:16]}...)")

        try:
            resp = self._get(setter_url, allow_redirects=False)
            status = resp.status_code
            loc = resp.headers.get("location") or resp.headers.get("Location") or ""
            self._log(f"set-cookie HTTP {status} loc={(loc or '')[:120]}")
            try:
                raw_scs = []
                if hasattr(resp.headers, "get_list"):
                    raw_scs = resp.headers.get_list("set-cookie") or []
                elif "set-cookie" in resp.headers:
                    raw_scs = [resp.headers.get("set-cookie") or ""]
                for sc in raw_scs:
                    m = re.search(
                        r"(?:^|,\s*)sso=(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)",
                        sc or "",
                        flags=re.I,
                    )
                    if m:
                        # Response Set-Cookie from auth.grok.com → grok domains only
                        self._set_sso_cookie(m.group(1), domains=self._GROK_SSO_DOMAINS)
                        self._log("harvested sso from set-cookie response (grok domains)")
            except Exception:
                pass
            if loc:
                return urljoin(setter_url, loc)
            if status >= 400 and success:
                self._log(f"set-cookie {status} → fallback success_url")
                return success
            if success:
                return success
            return str(getattr(resp, "url", setter_url) or setter_url)
        except Exception as exc:
            self._log(f"set-cookie GET failed ({exc}); using success_url/offline only")
            if success:
                return success
            raise

    def _follow_for_code(
        self,
        start_url: str,
        *,
        redirect_uri: str,
        state: str,
        max_hops: int = 25,
    ) -> str:
        """Follow redirects / cookie-setter until redirect_uri?code=... is reached."""
        current = start_url
        pending_return_to: Optional[str] = None
        visited: set[str] = set()

        for hop in range(max_hops):
            self._log(f"hop {hop}: {current[:160]}")
            # Never let the HTTP client connect to localhost callback.
            if current.startswith(redirect_uri) or (
                "code=" in current and "state=" in current and "127.0.0.1" in current
            ):
                return self._code_from_url(current, state)

            # Remember OAuth return_to while we bounce through sign-in.
            rt = self._absolute_return_to(current)
            if rt:
                pending_return_to = rt

            # If a hop dumps us on /account while OAuth return_to is known, recover.
            # Do NOT auto-jump from /sign-in (that can trigger sign-out loops).
            path = urlparse(current).path or ""
            if pending_return_to and path.rstrip("/") in ("/account", "/home"):
                key = "rt:" + pending_return_to
                if key not in visited:
                    visited.add(key)
                    self._log(f"account page → return_to {pending_return_to[:140]}")
                    current = pending_return_to
                    continue

            # Never follow logout / delete-cookie chains — that is what turns a
            # weak session into a permanent sign-in loop (observed 2026-07).
            low = current.lower()
            if "sign-out" in low or "delete-cookie" in low or "signout" in low:
                self._log(f"refusing logout hop: {current[:140]}")
                if pending_return_to and pending_return_to not in visited:
                    current = pending_return_to
                    continue
                raise RuntimeError(
                    f"OAuth hit logout hop without a usable session: {current[:180]}"
                )

            if current in visited and hop > 2:
                raise RuntimeError(f"OAuth redirect loop at {current[:180]}")
            visited.add(current)

            # set-cookie hops: consume JWT offline on 403 (endpoint often 403s now)
            if "set-cookie" in low:
                current = self._consume_set_cookie_url(current)
                continue

            resp = self._get(current, allow_redirects=False)
            status = resp.status_code
            loc = resp.headers.get("location") or resp.headers.get("Location")

            if status in (301, 302, 303, 307, 308) and loc:
                nxt = urljoin(current, loc)
                if nxt.startswith(redirect_uri) or (
                    "code=" in nxt and ("127.0.0.1" in nxt or "localhost" in nxt)
                ):
                    return self._code_from_url(nxt, state)
                nxt_low = nxt.lower()
                if "sign-out" in nxt_low or "delete-cookie" in nxt_low:
                    self._log(f"blocked redirect to logout: {nxt[:140]}")
                    if pending_return_to and pending_return_to not in visited:
                        current = pending_return_to
                        continue
                    raise RuntimeError(
                        f"consent/session redirected to logout: {nxt[:180]}"
                    )
                # sign-in → /account while we still have return_to: go to consent
                nxt_path = urlparse(nxt).path or ""
                if pending_return_to and nxt_path.rstrip("/") in ("/account", "/home"):
                    self._log("redirect to account intercepted; using return_to")
                    current = pending_return_to
                    continue
                current = nxt
                continue

            # HTML page: try meta-refresh / JS location / form action
            html = resp.text or ""
            m2 = re.search(
                r'https?://127\.0\.0\.1[^\"\'\s<>]*code=[^\"\'\s<>]+',
                html,
            )
            if m2:
                return self._code_from_url(m2.group(0).replace("&amp;", "&"), state)

            m = re.search(
                r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+url=([^\"\'>\s]+)',
                html,
                re.I,
            )
            if m:
                current = urljoin(current, unquote(m.group(1)))
                continue

            # Consent page: look for authorize/continue links or form actions
            for pat in (
                r'href=["\']([^"\']*oauth2[^"\']*)["\']',
                r'action=["\']([^"\']*oauth2[^"\']*)["\']',
                r'href=["\']([^"\']*callback[^"\']*)["\']',
            ):
                m = re.search(pat, html, re.I)
                if m:
                    candidate = urljoin(current, m.group(1).replace("&amp;", "&"))
                    if candidate != current and candidate not in visited:
                        current = candidate
                        break
            else:
                # If consent URL itself is the current page and already logged in,
                # try POST approve is unknown; last resort: re-hit return_to once.
                if pending_return_to and current != pending_return_to and pending_return_to not in visited:
                    current = pending_return_to
                    continue
                raise RuntimeError(
                    f"OAuth redirect chain stalled at HTTP {status} {current[:180]} "
                    f"(no authorization code)."
                )
            continue

        raise TimeoutError("OAuth redirect chain exceeded max hops without code")

    @staticmethod
    def _code_from_url(url: str, expected_state: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if qs.get("error"):
            detail = (qs.get("error_description") or qs.get("error") or [""])[0]
            raise RuntimeError(f"authorization failed: {detail}")
        got_state = (qs.get("state") or [""])[0]
        if got_state and got_state != expected_state:
            raise RuntimeError("authorization failed: state mismatch")
        code = (qs.get("code") or [""])[0]
        if not code:
            raise RuntimeError(f"authorization failed: missing code in {url[:200]}")
        return code

    def login(
        self,
        email: str,
        password: str,
        *,
        client_id: str = DEFAULT_CLIENT_ID,
        scopes: Optional[List[str]] = None,
        redirect_host: str = "127.0.0.1",
        redirect_port: int = 56121,
        output_dir: Optional[str] = None,
        cliproxyapi_auth_dir: Optional[str] = None,
        cliproxyapi_base_url: str = CLIPROXYAPI_GROK_BASE_URL,
        cliproxyapi_disabled: bool = False,
        proxy: str = "",
        session_cookies: Optional[Dict[str, str]] = None,
    ) -> OAuthLoginResult:
        scopes = scopes or list(DEFAULT_SCOPES)
        if session_cookies:
            self.load_cookies(session_cookies)

        state = secrets.token_hex(16)
        nonce = secrets.token_hex(16)
        verifier = generate_code_verifier()
        challenge = code_challenge_s256(verifier)
        redirect_uri = f"http://{redirect_host}:{int(redirect_port)}/callback"

        auth_url = build_authorization_url(
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
            nonce=nonce,
            code_challenge=challenge,
            scopes=scopes,
        )
        # Consent URL is on the CreateCookieSetterLink allowlist (authorize URL is not).
        consent_url = (
            f"{ACCOUNTS_ORIGIN}/oauth2/consent?"
            + urlencode(
                {
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "scope": " ".join(scopes),
                    "state": state,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "nonce": nonce,
                }
            )
        )

        def _submit_oauth2_consent(page_url: str, page_html: str = "") -> str:
            """POST Next.js submitOAuth2Consent server action; return authorization code."""
            import json as _json

            # --- discover live server action id(s) from page + linked chunks ---
            candidates: List[str] = []

            def _add_id(hid: str) -> None:
                hid = (hid or "").strip()
                if hid and re.fullmatch(r"[a-f0-9]{40,44}", hid) and hid not in candidates:
                    candidates.append(hid)

            # 1) Explicit submitOAuth2Consent binding (best)
            for pat in (
                r'createServerReference\)\("([a-f0-9]{40,44})"[^)]*submitOAuth2Consent',
                r'submitOAuth2Consent[^"]{0,40}"([a-f0-9]{40,44})"',
                r'"([a-f0-9]{40,44})"[^"]{0,80}submitOAuth2Consent',
                r'submitOAuth2Consent.*?([a-f0-9]{40,44})',
            ):
                for m in re.finditer(pat, page_html or "", re.I | re.S):
                    _add_id(m.group(1))

            # 2) Any createServerReference on the consent page
            for m in re.finditer(
                r'createServerReference\)\("([a-f0-9]{40,44})"', page_html or ""
            ):
                _add_id(m.group(1))

            # 3) Fetch linked Next.js chunks — action ids usually live there, not in HTML
            script_srcs = re.findall(
                r'<script[^>]+src=["\']([^"\']+)["\']', page_html or "", re.I
            )
            # Also bare /_next/static paths in flight data
            script_srcs += re.findall(
                r'(/_next/static/[^"\'\s<>]+\.js)', page_html or ""
            )
            seen_src: set[str] = set()
            for src in script_srcs:
                if not src or src in seen_src:
                    continue
                seen_src.add(src)
                full = urljoin(page_url, src)
                # Only pull same-origin app chunks (skip analytics etc.)
                if "accounts.x.ai" not in full and not src.startswith("/"):
                    continue
                if "/_next/" not in full and "accounts.x.ai" not in full:
                    continue
                try:
                    js = self._get(full, allow_redirects=True)
                    text = js.text or ""
                    if "submitOAuth2Consent" in text or "OAuth2Consent" in text or "oauth2" in text.lower():
                        self._log(f"scanning chunk for action id: {full[-80:]}")
                        for pat in (
                            r'createServerReference\)\("([a-f0-9]{40,44})"[^)]*submitOAuth2Consent',
                            r'submitOAuth2Consent[^"]{0,60}"([a-f0-9]{40,44})"',
                            r'"([a-f0-9]{40,44})"[^"]{0,100}submitOAuth2Consent',
                            r'submitOAuth2Consent["\']?\s*[,:]\s*["\']([a-f0-9]{40,44})',
                            r'createServerReference\)\("([a-f0-9]{40,44})"',
                        ):
                            for m in re.finditer(pat, text, re.I | re.S):
                                _add_id(m.group(1))
                                if len(candidates) >= 8:
                                    break
                    if len(candidates) >= 8:
                        break
                except Exception as exc:
                    self._log(f"chunk fetch failed {full[-60:]}: {exc}")

            # 4) Hardcoded fallback last (often stale → 404)
            _add_id(SUBMIT_OAUTH2_CONSENT_ACTION)

            if not candidates:
                raise RuntimeError(
                    "no server action id found on consent page/chunks "
                    f"(html_len={len(page_html or '')})"
                )
            self._log(f"consent action candidates={candidates[:6]}")

            # principalId from session if present in page
            principal_id = ""
            m_pid = re.search(
                r'"principalId"\s*:\s*"([^"]+)"|"userId"\s*:\s*"([^"]+)"|"sub"\s*:\s*"([^"]+)"',
                page_html or "",
            )
            if m_pid:
                principal_id = m_pid.group(1) or m_pid.group(2) or m_pid.group(3) or ""

            from urllib.parse import quote as _quote

            router_tree = (
                '["",{"children":["(app)",{"children":["(auth)",{"children":["oauth2",'
                '{"children":["consent",{"children":["__PAGE__",{}]}]}]}]}]},'
                '"$undefined","$undefined",16]'
            )
            payload = [{
                "action": "allow",
                "clientId": client_id,
                "redirectUri": redirect_uri,
                "scope": " ".join(scopes),
                "state": state,
                "codeChallenge": challenge,
                "codeChallengeMethod": "S256",
                "nonce": nonce,
                "principalType": "User",
                "principalId": principal_id,
                "referrer": "",
            }]
            body = _json.dumps(payload, separators=(",", ":")).encode("utf-8")

            last_err = ""
            for action_id in candidates:
                headers = {
                    "accept": "text/x-component",
                    "content-type": "text/plain;charset=UTF-8",
                    "next-action": action_id,
                    "next-router-state-tree": _quote(router_tree, safe=""),
                    "origin": ACCOUNTS_ORIGIN,
                    "referer": page_url,
                    "sec-fetch-site": "same-origin",
                    "sec-fetch-mode": "cors",
                    "sec-fetch-dest": "empty",
                }
                self._log(f"submitOAuth2Consent action={action_id[:16]}...")
                # Try path without query first, then full URL
                endpoints = [
                    page_url.split("?")[0] if "?" in page_url else page_url,
                    page_url,
                ]
                for ep in endpoints:
                    resp = self._s.post(ep, headers=headers, data=body, timeout=45)
                    text = resp.text or ""
                    self._log(
                        f"consent action HTTP {resp.status_code} "
                        f"body={text[:180]!r}"
                    )
                    if resp.status_code == 404 or "Server action not found" in text:
                        last_err = f"404 action={action_id[:16]}"
                        continue
                    m = re.search(r'"code"\s*:\s*"([^"]+)"', text)
                    if m:
                        return m.group(1)
                    m = re.search(r'code=([A-Za-z0-9._~\-]+)', text)
                    if m and "error" not in m.group(0):
                        return m.group(1)
                    loc = resp.headers.get("location") or resp.headers.get("Location") or ""
                    if "code=" in loc:
                        return self._code_from_url(urljoin(page_url, loc), state)
                    # Some RSC responses embed redirect as flight data
                    m = re.search(
                        r'https?://127\.0\.0\.1[^"\'\s]*code=([A-Za-z0-9._~\-]+)',
                        text,
                    )
                    if m:
                        return m.group(1)
                    last_err = f"HTTP {resp.status_code}: {text[:200]}"
            raise RuntimeError(
                f"submitOAuth2Consent failed after {len(candidates)} action ids; "
                f"last={last_err}"
            )

        def _complete_via_cookie_setter(label: str) -> str:
            """Mint set-cookie chain with consent as success_url, then Allow consent."""
            # Prime authorize so the AS has a pending OAuth request.
            self._get(auth_url, allow_redirects=False)
            csl = self.create_cookie_setter_link(
                consent_url,
                error_url=f"{ACCOUNTS_ORIGIN}/sign-in",
                referer=f"{ACCOUNTS_ORIGIN}/sign-in?redirect=oauth2-provider",
            )
            if not csl.get("ok"):
                raise RuntimeError(f"{label}: CreateCookieSetterLink failed: {csl.get('error')}")
            setter = str(csl.get("cookie_setter_url") or "")
            self._log(f"{label}: cookie_setter={setter[:100]}...")

            # Walk set-cookie chain (handles 403 via offline JWT apply).
            current = setter
            for _ in range(8):
                if "code=" in current and (
                    current.startswith(redirect_uri) or "127.0.0.1" in current
                ):
                    return self._code_from_url(current, state)
                if "set-cookie" in current:
                    current = self._consume_set_cookie_url(current)
                    continue
                break

            # Consent page (HTML) → server action Allow → code
            # Always re-GET consent with allow_redirects=False so we see real status.
            # If session is valid we get 200 + Authorize form; if not, 302→sign-in.
            page = self._get(consent_url, allow_redirects=False)
            loc = page.headers.get("location") or page.headers.get("Location") or ""
            self._log(
                f"consent GET HTTP {page.status_code} "
                f"loc={(loc or '')[:120]} body_has_Authorize={'Authorize' in (page.text or '')}"
            )
            if loc and "code=" in loc:
                return self._code_from_url(urljoin(consent_url, loc), state)
            if page.status_code in (301, 302, 303, 307, 308) and loc and "sign-in" in loc.lower():
                raise RuntimeError(
                    "consent redirected to sign-in — accounts.x.ai session missing/invalid "
                    f"(loc={loc[:160]})"
                )
            html = page.text or ""
            if page.status_code == 200:
                # Session is valid (200 + Authorize). Do NOT fall through to
                # _follow_for_code — that just bounces consent→sign-out and
                # obscures the real failure (usually stale server action id).
                return _submit_oauth2_consent(consent_url, html)
            # If cookie-setter landed elsewhere, try that URL too.
            if "consent" in current and current != consent_url:
                return self._follow_for_code(current, redirect_uri=redirect_uri, state=state)
            raise RuntimeError(
                f"consent not reachable after cookie-setter "
                f"(status={page.status_code}, current={current[:160]})"
            )

        self._log("OAuth PKCE start...")
        try:
            if session_cookies and session_cookies.get("sso"):
                self._set_sso_cookie(session_cookies["sso"])
            code = _complete_via_cookie_setter("session-reuse")
            self._log("authorization code obtained via session cookie-setter")
        except Exception as session_err:
            self._log(f"session-reuse failed ({session_err}); password CreateSession")
            if not email or not password:
                raise RuntimeError(
                    f"OAuth needs password login; prior error: {session_err}"
                ) from session_err
            signin = f"{ACCOUNTS_ORIGIN}/sign-in?redirect=oauth2-provider"
            self._get(signin, allow_redirects=True)
            sess = self.create_session(email, password, referer=signin)
            if not sess.get("ok"):
                raise RuntimeError(
                    f"CreateSession failed: {sess.get('error')}; prior: {session_err}"
                ) from session_err
            # Prefer CreateSession jwt as accounts.x.ai sso ONLY.
            # Do not fall back to the stale signup sso from accounts_output —
            # that is what causes CreateCookieSetterLink "invalid-credentials".
            jwt = sess.get("session_jwt")
            if not jwt:
                raise RuntimeError("CreateSession returned no session_jwt")
            self._set_sso_cookie(str(jwt), domains=self._ACCOUNTS_SSO_DOMAINS)
            self._log("bound CreateSession session_jwt to accounts.x.ai sso")
            try:
                code = _complete_via_cookie_setter("password-login")
            except Exception as csl_err:
                self._log(f"cookie-setter path failed ({csl_err}); raw authorize follow")
                code = self._follow_for_code(auth_url, redirect_uri=redirect_uri, state=state)

        self._log("exchanging authorization code...")
        return _finalize_oauth_code(
            code=code,
            code_verifier=verifier,
            redirect_uri=redirect_uri,
            client_id=client_id,
            proxy=proxy,
            output_dir=output_dir,
            cliproxyapi_auth_dir=cliproxyapi_auth_dir,
            cliproxyapi_base_url=cliproxyapi_base_url,
            cliproxyapi_disabled=cliproxyapi_disabled,
        )


def login_with_protocol(
    email: str,
    password: str,
    *,
    yescaptcha_key: str = "",
    proxy: str = "",
    debug: bool = False,
    turnstile_premium: bool = True,
    cliproxyapi_auth_dir: Optional[str] = None,
    cliproxyapi_base_url: str = CLIPROXYAPI_GROK_BASE_URL,
    cliproxyapi_disabled: bool = False,
    output_dir: Optional[str] = None,
    redirect_port: int = 56121,
    session_cookies: Optional[Dict[str, str]] = None,
    auth_client: Any = None,
) -> OAuthLoginResult:
    """Convenience wrapper: protocol OAuth + optional CLIProxyAPI Build export.

    If *auth_client* (XConsoleAuthClient) is provided after signup, its live
    curl_cffi session is reused so accounts.x.ai cookies stay attached.
    """
    client = ProtocolOAuthClient(
        yescaptcha_key=yescaptcha_key,
        proxy=proxy,
        debug=debug,
        turnstile_premium=turnstile_premium,
    )
    if auth_client is not None:
        try:
            transport = auth_client._t
            session = getattr(transport, "_session", None)
            if session is not None:
                client._s = session
                client._log("reusing XConsoleAuthClient curl_cffi session for OAuth")
        except Exception as exc:
            client._log(f"could not reuse auth client session: {exc}")
            if not session_cookies:
                session_cookies = extract_cookies_from_auth_client(auth_client)
    return client.login(
        email,
        password,
        cliproxyapi_auth_dir=cliproxyapi_auth_dir,
        cliproxyapi_base_url=cliproxyapi_base_url,
        cliproxyapi_disabled=cliproxyapi_disabled,
        output_dir=output_dir,
        redirect_port=redirect_port,
        proxy=proxy,
        session_cookies=session_cookies,
    )
