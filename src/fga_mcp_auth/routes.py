"""The three custom HTTP routes: /login, /okta/callback, /oauth/error.

Handlers are free functions over a provider so both wiring helpers can mount the
same code; `FGAAuthProvider` also exposes them as methods for direct testing.

Two different ways to fail, and which one applies is decided by whether we hold
a VALIDATED redirect_uri for the request:

  * No trusted redirect_uri (unknown/expired state, or a redirect_uri that never
    passed the allowlist) -> render an error page on OUR origin. Bouncing to an
    unvalidated URI is exactly the open redirect the allowlist exists to remove.
  * A trusted redirect_uri (the pending login carries one that passed the
    allowlist at DCR registration AND again at /authorize) -> 302 back to it
    with `error`, `error_description` and the client's `state`, per RFC 6749
    §4.1.2.1. This is the only way the OAuth client ever learns the flow failed:
    an HTML page on our origin leaves claude.ai's connector waiting on a
    callback that never arrives, with nothing to show the user but a spinner.

The `error` code is drawn from a fixed set and the description is our own prose.
Okta's error text never travels — not into the page (phishing on our origin) and
not into the redirect either.

FLAGGED BEHAVIOR CHANGE (needs Jacob's sign-off, like D4): both live servers
answer EVERY callback rejection on their own origin — quorum's oauth.py renders
HTML 400/403/500, ob3's does the same — and quorum's suite pins "a callback
rejection never 302s" as a security property. Redirecting instead is not a
superset of that, so it is called out here, in the README's deliberate-changes
section, and in both retrofit PR bodies rather than being defended only in a
docstring. What it buys: claude.ai used to spin forever on a denial. What it
costs: the reason now reaches the user only as one of our fixed descriptions
(constants.REDIRECT_ERRORS, chosen by AuthzDenied.code) and otherwise only the
log, and any runbook watching for 403/500 on this route sees 302s. It is not
exploitable — the target passed the allowlist at DCR and again at /authorize,
and every code and description is from our own table.
"""

from __future__ import annotations

import logging
from html import escape
from typing import TYPE_CHECKING

from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from .constants import (
    ERROR_REASON_FALLBACK,
    ERROR_REASONS,
    REDIRECT_ERROR_CODES,
    REDIRECT_ERRORS,
)
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

    def fail(error: str) -> Response:
        provider._pending.pop(state_key, None)
        return error_redirect(pending, error)

    if error := params.get("error"):
        logger.warning("Okta returned error: %s", error, extra={"event_category": "auth.failure"})
        # Okta's prose is attacker-influenceable, so only a code from our own
        # fixed set travels — never Okta's string, in the page or the redirect.
        # The log keeps the detail.
        return fail("access_denied" if error == "access_denied" else "server_error")

    # RFC 9207: when the AS echoes `iss`, it must match the one we trust.
    # Mix-up defence, and it fires BEFORE the code is spent.
    assert provider._okta is not None
    meta = await provider._okta.metadata()
    if (returned := params.get("iss")) and returned.rstrip("/") != meta["issuer"].rstrip("/"):
        logger.error("Issuer mismatch: got %s want %s", returned, meta["issuer"])
        return fail("server_error")

    code = params.get("code", "")
    if not code:
        logger.warning("Okta callback carried neither a code nor an error")
        return fail("server_error")

    try:
        claims = await provider._okta.exchange_and_verify(
            code, pending["okta_verifier"], pending["okta_nonce"]
        )
        provider._okta.check_authorized(claims)
    except AuthzDenied as exc:
        logger.warning("Login denied: %s", exc, extra={"event_category": "auth.failure"})
        # The group/domain gate. The wire code is `access_denied` either way —
        # that is what tells claude.ai the human was refused rather than the
        # server broken — but the description is picked from our table by which
        # gate refused, so the user gets the next step (join the group / use
        # your FGA email) that quorum's on-origin 403 page used to give them.
        # The gate's own message stays in the log; it is not the client's to
        # render.
        return fail(getattr(exc, "code", "account_not_permitted"))
    except Exception:
        logger.exception("Okta callback failed")
        return fail("server_error")

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


def error_redirect(pending: dict, error: str) -> Response:
    """RFC 6749 §4.1.2.1 error response, on the validated redirect_uri.

    `error` must be a key of REDIRECT_ERRORS: the code and the description both
    come from our own table, so nothing an attacker (or Okta) chose is echoed to
    the client. Keys that name a specific denial map to the RFC code they are a
    flavour of (REDIRECT_ERROR_CODES), so the vocabulary on the wire stays the
    one claude.ai parses while the description can still be actionable. `state`
    is the client's own value and is returned unchanged, as the RFC requires — a
    client that cannot match the response to its request has to treat it as
    unsolicited.
    """
    out = {
        "error": REDIRECT_ERROR_CODES.get(error, error),
        "error_description": REDIRECT_ERRORS[error],
    }
    if pending.get("original_state"):
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
