"""The three custom HTTP routes: /login, /okta/callback, /oauth/error.

/login is a consent step, not a bare hop. DCR is open, so the client asking for
a staff member's auth code may be anyone's; with a live Okta session the rest of
the chain is silent. GET /login shows the human which redirect target will
receive the code and sets a per-login, HttpOnly browser-binding cookie; only a
POST carrying that cookie goes on to Okta, and /okta/callback refuses (on our
own origin, minting nothing) unless that same browser consented.

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

import hashlib
import logging
import secrets
from html import escape
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from .constants import (
    ERROR_REASON_FALLBACK,
    ERROR_REASONS,
    PENDING_TTL,
    REDIRECT_ERROR_CODES,
    REDIRECT_ERRORS,
)
from .okta import AuthzDenied
from .urls import append_params

if TYPE_CHECKING:  # pragma: no cover
    from .provider import FGAAuthProvider

logger = logging.getLogger(__name__)


LOGIN_COOKIE_PREFIX = "fga_login_"
CONSENT_COOKIE_PREFIX = "fga_consent_"
CLIENT_NAME_MAX = 80

# The consent page must not be cached, framed, or run script. No `form-action`:
# Chrome applies it to the redirect after submit, which would block the hop to
# Okta.
CONSENT_HEADERS = {
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
    ),
}


def login_cookie_name(state_key: str) -> str:
    """Per-login name, so two connectors set up at once do not clobber each other."""
    return LOGIN_COOKIE_PREFIX + hashlib.sha256(state_key.encode()).hexdigest()[:16]


def consent_cookie_name(state_key: str) -> str:
    """Set only on the consent POST's response: proof that this browser clicked."""
    return CONSENT_COOKIE_PREFIX + hashlib.sha256(state_key.encode()).hexdigest()[:16]


def _cookie_matches(request: Request, name: str, expected: str) -> bool:
    got = request.cookies.get(name) or ""
    if not expected or not got:
        return False
    return secrets.compare_digest(got.encode(), expected.encode())


def _set_login_cookie(provider: FGAAuthProvider, resp: Response, name: str, value: str) -> None:
    resp.set_cookie(
        name,
        value,
        max_age=PENDING_TTL,
        path="/",
        secure=provider.settings.public_base_url.startswith("https://"),
        httponly=True,
        samesite="lax",
    )


def _browser_matches(request: Request, state_key: str, pending: dict) -> bool:
    expected = pending.get("browser") or ""
    got = request.cookies.get(login_cookie_name(state_key)) or ""
    if not expected or not got:
        return False
    return secrets.compare_digest(got.encode(), expected.encode())


def _same_origin(provider: FGAAuthProvider, request: Request) -> bool:
    """Refuse a consent POST another site submitted. SameSite=Lax still sends
    our cookie on a top-level POST from a sibling subdomain, so check what the
    browser says about the request's origin. Absent headers pass: old browsers
    and non-browser clients send neither, and those cannot ride a victim's
    cookie anyway."""
    base = urlparse(provider.settings.public_base_url)
    ours = f"{base.scheme}://{base.netloc}"
    origin = request.headers.get("origin")
    if origin is not None and origin != ours:
        return False
    site = request.headers.get("sec-fetch-site")
    return site is None or site == "same-origin"


def _okta_unconfigured() -> Response:
    # No fallback login path exists. In production this is unreachable —
    # require_http_complete() refuses to boot without Okta — so it only shows
    # up in local development.
    return HTMLResponse(error_html("Okta SSO is not configured on this server."), status_code=503)


def _redirect_target(redirect_uri: str) -> str:
    """scheme://host[:port] of the validated redirect_uri — the line the human
    can trust, unlike the client's self-reported name."""
    parsed = urlparse(redirect_uri)
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{parsed.hostname or ''}{port}"


async def handle_login_get(provider: FGAAuthProvider, request: Request) -> Response:
    """Consent page. Replayable: a refresh reuses the same browser token."""
    state_key = request.query_params.get("state", "")
    pending = provider.take_pending(state_key)
    if isinstance(pending, Response):
        return pending
    if provider._okta is None:
        return _okta_unconfigured()
    if pending.get("consented"):
        # The page token is handed to any browser that loads this URL; once
        # someone has clicked Continue, stop handing it out.
        return HTMLResponse(
            error_html(
                "This sign-in has already been approved. Start again from your application."
            ),
            status_code=400,
        )

    if not pending.get("browser"):
        pending["browser"] = secrets.token_urlsafe(32)
    client = provider._clients.get(pending["client_id"])
    name = (getattr(client, "client_name", None) or "").strip() or "(no name given)"
    if len(name) > CLIENT_NAME_MAX:
        name = name[:CLIENT_NAME_MAX] + "…"
    resp = HTMLResponse(
        consent_html(
            state_key=state_key,
            client_name=name,
            server=provider.settings.audience,
            target=_redirect_target(pending["redirect_uri"]),
        ),
        headers=CONSENT_HEADERS,
    )
    _set_login_cookie(provider, resp, login_cookie_name(state_key), pending["browser"])
    return resp


async def handle_login_post(provider: FGAAuthProvider, request: Request) -> Response:
    """The consent click. Only the browser that saw the page can make it."""
    form = parse_qs((await request.body()).decode("utf-8", "replace"))
    state_key = (form.get("state") or [""])[0]
    pending = provider.take_pending(state_key)
    if isinstance(pending, Response):
        return pending
    if provider._okta is None:
        return _okta_unconfigured()
    if not _same_origin(provider, request):
        logger.warning(
            "Consent POST from another origin",
            extra={"event_category": "auth.failure"},
        )
        return HTMLResponse(
            error_html("This sign-in must be continued from this server's own page."),
            status_code=400,
        )
    if not _browser_matches(request, state_key, pending):
        logger.warning(
            "Consent POST without this login's browser cookie",
            extra={"event_category": "auth.failure"},
        )
        return HTMLResponse(
            error_html("This sign-in was started in a different browser."), status_code=400
        )

    # A fresh secret only the clicking browser receives. The page token above
    # reaches every browser that loaded the page, so it cannot prove the click.
    pending["consented"] = True
    pending["consent"] = secrets.token_urlsafe(32)
    challenge = provider.pkce_challenge(pending["okta_verifier"])
    url = await provider._okta.authorize_url(state_key, pending["okta_nonce"], challenge)
    resp = RedirectResponse(url=url, status_code=303)
    _set_login_cookie(provider, resp, consent_cookie_name(state_key), pending["consent"])
    return resp


async def handle_okta_callback(provider: FGAAuthProvider, request: Request) -> Response:
    params = request.query_params
    state_key = params.get("state", "")
    pending = provider.take_pending(state_key)
    if isinstance(pending, Response):
        return pending

    # Before anything is spent: the browser arriving here must be the one that
    # clicked Continue on our consent page. Otherwise answer on our origin,
    # mint nothing, and leave the pending login alone — a stranger holding only
    # the state must not be able to burn it.
    if not pending.get("consented") or not _cookie_matches(
        request, consent_cookie_name(state_key), pending.get("consent") or ""
    ):
        logger.warning(
            "Okta callback without consent from this browser",
            extra={"event_category": "auth.failure"},
        )
        return HTMLResponse(
            error_html("This sign-in was not approved in this browser."), status_code=400
        )
    cookies = (login_cookie_name(state_key), consent_cookie_name(state_key))

    def fail(error: str) -> Response:
        provider._pending.pop(state_key, None)
        resp = error_redirect(pending, error)
        for name in cookies:
            resp.delete_cookie(name, path="/")
        return resp

    if error := params.get("error"):
        logger.warning(
            "Okta returned error: %.200r", error, extra={"event_category": "auth.failure"}
        )
        # Okta's prose is attacker-influenceable, so only a code from our own
        # fixed set travels — never Okta's string, in the page or the redirect.
        # The log keeps the detail.
        return fail("access_denied" if error == "access_denied" else "server_error")

    # RFC 9207: when the AS echoes `iss`, it must match the one we trust.
    # Mix-up defence, and it fires BEFORE the code is spent.
    assert provider._okta is not None
    meta = await provider._okta.metadata()
    if (returned := params.get("iss")) and returned.rstrip("/") != meta["issuer"].rstrip("/"):
        logger.error("Issuer mismatch: got %.200r want %s", returned, meta["issuer"])
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
    resp = RedirectResponse(url=append_params(pending["redirect_uri"], out), status_code=302)
    for name in cookies:
        resp.delete_cookie(name, path="/")
    return resp


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


_PAGE_STYLE = """body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
background:#f4f4f5;color:#18181b;display:flex;align-items:center;justify-content:center;
min-height:100vh;margin:0}.card{background:#fff;padding:32px;border-radius:12px;max-width:420px;
box-shadow:0 4px 16px rgba(0,0,0,.06)}h1{font-size:18px;margin:0 0 8px}
p{color:#52525b;font-size:14px;margin:0 0 12px}strong{color:#18181b;word-break:break-all}
button{font-size:15px;padding:10px 18px;border:0;border-radius:8px;background:#18181b;
color:#fff;cursor:pointer}"""


def consent_html(*, state_key: str, client_name: str, server: str, target: str) -> str:
    """Every value is escaped. The client name is attacker-chosen (open DCR), so it
    is labelled as self-reported; the redirect target is what we validated."""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Approve sign-in</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>{_PAGE_STYLE}</style></head>
<body><div class="card"><h1>Sign in to {escape(server)}?</h1>
<p>Your FGA sign-in will be sent to <strong>{escape(target)}</strong>.</p>
<p>The application calls itself &ldquo;{escape(client_name)}&rdquo;. That name is
self-reported and not verified.</p>
<p>Continue only if you just started connecting this application yourself.</p>
<form method="post" action="/login">
<input type="hidden" name="state" value="{escape(state_key)}">
<button type="submit">Continue</button></form></div></body></html>"""


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
