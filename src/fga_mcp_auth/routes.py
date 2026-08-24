"""The three custom HTTP routes: /login, /okta/callback, /oauth/error.

Handlers are free functions over a provider so both wiring helpers can mount the
same code; `FGAAuthProvider` also exposes them as methods for direct testing.
"""

from __future__ import annotations

import logging
from html import escape
from typing import TYPE_CHECKING

from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from .constants import ERROR_REASON_FALLBACK, ERROR_REASONS
from .okta import AuthzDenied
from .urls import append_params

if TYPE_CHECKING:  # pragma: no cover
    from .provider import FGAAuthProvider

logger = logging.getLogger(__name__)


async def handle_login_get(provider: FGAAuthProvider, request: Request) -> Response:
    """Where the shared-password form used to render: now a 302 straight to Okta."""
    state_key = request.query_params.get("state", "")
    pending = provider.take_pending(state_key)
    if isinstance(pending, Response):
        return pending
    if provider._okta is None:
        # No fallback login path exists. In production this is unreachable —
        # require_http_complete() refuses to boot without Okta — so it only
        # shows up in local development.
        return HTMLResponse(
            error_html("Okta SSO is not configured on this server."), status_code=503
        )

    challenge = provider.pkce_challenge(pending["okta_verifier"])
    url = await provider._okta.authorize_url(state_key, pending["okta_nonce"], challenge)
    return RedirectResponse(url=url, status_code=302)


async def handle_okta_callback(provider: FGAAuthProvider, request: Request) -> Response:
    params = request.query_params
    state_key = params.get("state", "")
    pending = provider.take_pending(state_key)
    if isinstance(pending, Response):
        return pending

    if error := params.get("error"):
        provider._pending.pop(state_key, None)
        logger.warning("Okta returned error: %s", error)
        # Don't reflect Okta's (attacker-influenceable) prose onto our own
        # origin, even escaped — escaping stops XSS but not phishing, and
        # attacker-chosen text on our domain mid-login is the whole primitive
        # ("Session expired, call 1-800-..."). The log has the detail.
        return HTMLResponse(error_html("Okta rejected the sign-in. Try again."), 400)

    # RFC 9207: when the AS echoes `iss`, it must match the one we trust.
    # Mix-up defence, and it fires BEFORE the code is spent.
    assert provider._okta is not None
    meta = await provider._okta.metadata()
    if (returned := params.get("iss")) and returned.rstrip("/") != meta["issuer"].rstrip("/"):
        provider._pending.pop(state_key, None)
        logger.error("Issuer mismatch: got %s want %s", returned, meta["issuer"])
        return HTMLResponse(error_html("Issuer mismatch — login rejected."), 400)

    code = params.get("code", "")
    if not code:
        return HTMLResponse(error_html("Okta did not return an authorization code."), 400)

    try:
        claims = await provider._okta.exchange_and_verify(
            code, pending["okta_verifier"], pending["okta_nonce"]
        )
        provider._okta.check_authorized(claims)
    except AuthzDenied as exc:
        provider._pending.pop(state_key, None)
        logger.warning("Login denied: %s", exc, extra={"event_category": "auth.failure"})
        return HTMLResponse(error_html(str(exc)), 403)
    except Exception:
        provider._pending.pop(state_key, None)
        logger.exception("Okta callback failed")
        return HTMLResponse(error_html("Sign-in failed. Please try again."), 500)

    # Consume pending state, then issue our auth code — exactly where the
    # password check used to sit.
    provider._pending.pop(state_key, None)
    our_code = provider.issue_auth_code(pending, claims)

    logger.info(
        "Okta login succeeded",
        extra={
            "user": claims.get("email"),
            "server": provider.settings.audience,
            "event_category": "auth.success",
        },
    )
    out = {"code": our_code}
    if pending["original_state"]:
        out["state"] = pending["original_state"]
    return RedirectResponse(url=append_params(pending["redirect_uri"], out), status_code=302)


def handle_oauth_error(request: Request) -> Response:
    # Reason is looked up in a fixed table, never echoed, so an attacker cannot
    # use this page to render text of their choosing on our domain.
    reason = request.query_params.get("reason", "")
    return HTMLResponse(
        error_html(ERROR_REASONS.get(reason, ERROR_REASON_FALLBACK)),
        status_code=400,
    )


def error_html(message: str) -> str:
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sign-in error</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
background:#f4f4f5;color:#18181b;display:flex;align-items:center;justify-content:center;
min-height:100vh;margin:0}}.card{{background:#fff;padding:32px;border-radius:12px;max-width:420px;
box-shadow:0 4px 16px rgba(0,0,0,.06)}}h1{{font-size:18px;margin:0 0 8px}}
p{{color:#52525b;font-size:14px;margin:0}}</style></head>
<body><div class="card"><h1>Could not sign you in</h1><p>{escape(message)}</p>
<p style="margin-top:12px">Close this window and try connecting again.</p></div></body></html>"""
