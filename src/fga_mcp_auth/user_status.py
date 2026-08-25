"""Refresh-time Okta user-status check: the offboarding tail, shortened.

Our refresh tokens are stateless HS256 JWTs that re-mint from their own claims
(see grants.refresh_token_grant), so nothing that happens in Okta afterwards
reaches them. Deactivate a staff member and their sessions on every FGA MCP
server keep working until each refresh token crosses its `exp` — up to 7 days,
which is what README v1.0.0 called "`REFRESH_TTL` *is* the offboarding tail".

This module closes that gap at the one place a session can be extended. Once per
refresh, behind a 5-minute per-email cache, we ask Okta's Users API whether the
human still has an account they could log in with. A deactivated user's next
refresh is `invalid_grant`, so the tail becomes one access-token lifetime (<=1h)
plus at most the cache window, instead of a week.

## Why this needs opting into

The Users API needs an SSWS admin token, which is a credential the OIDC login
leg does not have and which has to be added to seven DO app environments. So it
is OPT-IN: no OKTA_ADMIN_TOKEN, no checker, v1.0.0 behavior exactly, with the
state announced at boot rather than inferred from an env var nobody remembers
setting.

Mint that token from a **read-only** Okta admin account. An SSWS token inherits
the permissions of whoever created it, so a Super Admin token sitting in seven
app environments is a fleet-wide write credential solving a read problem. The
only request this package ever makes is `GET /api/v1/users/{login}`.

## Why it fails OPEN

Every failure mode that is OURS rather than the user's — a timeout, a transport
error, a 429, a 5xx, a revoked SSWS token — allows the refresh and logs loudly.
This check runs on the refresh of every session on every server, so a policy of
denying on error turns a few minutes of Okta admin-API trouble into a fleet-wide
lockout of all staff, caused entirely by the safety feature. The <=7d REFRESH_TTL
horizon still sits underneath as the backstop, and that is precisely what makes
failing open affordable: the worst case of a failing check is the behavior we
already shipped in v1.0.0.

Note what is NOT a failure mode of ours: HTTP 404. A user Okta has never heard of
(or has deleted, which is where DEPROVISIONED accounts eventually go) cannot log
in, so their session cannot be renewed either.

## Why not Okta's own refresh token

The clean version of this would exchange Okta's refresh token on each of ours and
let Okta decide. Our tokens are signed but NOT encrypted, so anything embedded in
one is handed to the client — an Okta credential included. Hence an admin-API
question about the email claim instead.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

import httpx

from .constants import OKTA_LOGIN_STATUSES, USER_STATUS_CACHE_TTL, USER_STATUS_TIMEOUT

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class StatusVerdict:
    """`allow` is the decision; `status` is only ever for the log line.

    Two fields rather than a bare bool because the caller has to record WHY it
    refused a refresh — "SUSPENDED" and "NOT_FOUND" are different offboarding
    stories — and because "allowed because Okta was unreachable" must be
    distinguishable from "allowed because the account is ACTIVE" after the fact.
    """

    allow: bool
    status: str


def admin_base(issuer: str) -> str:
    """The Okta ORG host, which is not always OKTA_ISSUER.

    The issuer may point at a custom authorization server
    (`https://example.okta.com/oauth2/default`) — FGA is on the org AS today, but
    licensing API Access Management later is supposed to be a change to
    OKTA_ISSUER and nothing else (see settings.OktaConfig.discovery_url). The
    Users API lives at the org root either way, so keep scheme + host and drop
    the path.
    """
    parts = urlsplit(issuer)
    return f"{parts.scheme}://{parts.netloc}"


class OktaUserStatus:
    """Asks Okta whether an email still belongs to an account that can log in."""

    def __init__(
        self,
        *,
        issuer: str,
        admin_token: str,
        ttl: int = USER_STATUS_CACHE_TTL,
        timeout: float = USER_STATUS_TIMEOUT,
    ) -> None:
        self._base = admin_base(issuer)
        self._headers = {"Authorization": f"SSWS {admin_token}", "Accept": "application/json"}
        self._ttl = ttl
        # email -> monotonic deadline. ALLOW decisions only, and monotonic so a
        # clock adjustment cannot extend one. shortcut: a plain dict with
        # opportunistic pruning, no lock — two concurrent refreshes for the same
        # user can both miss and both call Okta, which costs one duplicate GET
        # and gets the same answer. An asyncio.Lock per email (or one shared
        # single-flight map) is the upgrade if admin-API quota ever bites.
        self._allowed_until: dict[str, float] = {}
        # Same lifetime trade as OktaOIDC's client: one keep-alive client for the
        # life of the process, no close() hook, because the provider is built by
        # the wiring helper and the app lifespan never sees it.
        self._http = httpx.AsyncClient(timeout=timeout)

    async def check(self, email: str) -> StatusVerdict:
        """Allow-or-deny for one email. Never raises."""
        if not email:
            # No email claim, nothing to ask about. Fail open for the same reason
            # a 5xx does: this is our gap, not the user's, and denying here would
            # break every session whose token predates an email claim.
            self._unavailable(email, "the token carries no email claim")
            return StatusVerdict(True, "unchecked")

        now = time.monotonic()
        deadline = self._allowed_until.get(email)
        if deadline is not None and deadline > now:
            return StatusVerdict(True, "cached")
        self._prune(now)

        # quote() with no safe characters: an email is a path SEGMENT here, and
        # "+" tags or a stray "/" would otherwise re-target the request.
        url = f"{self._base}/api/v1/users/{quote(email, safe='')}"
        try:
            resp = await self._http.get(url, headers=self._headers)
        except httpx.HTTPError as exc:
            # Covers timeouts, DNS and connection failures — httpx.TimeoutException
            # is a subclass — and never lets an admin-API problem become a 500 on
            # the token endpoint.
            self._unavailable(email, f"{type(exc).__name__}: {exc}")
            return StatusVerdict(True, "unavailable")

        if resp.status_code == 404:
            return StatusVerdict(False, "NOT_FOUND")
        if resp.status_code != 200:
            # 401/403 (SSWS token revoked, rotated, or under-scoped), 429, 5xx.
            # All of them are misconfiguration or capacity on our side, so they
            # get the fail-open path rather than every staff member's session.
            self._unavailable(email, f"HTTP {resp.status_code}")
            return StatusVerdict(True, "unavailable")

        try:
            status = str(resp.json().get("status") or "")
        except ValueError as exc:  # includes json.JSONDecodeError
            self._unavailable(email, f"unreadable response body: {exc}")
            return StatusVerdict(True, "unavailable")

        if status in OKTA_LOGIN_STATUSES:
            self._allowed_until[email] = time.monotonic() + self._ttl
            return StatusVerdict(True, status)
        # Deny decisions are NEVER cached: a deactivation has to bite on the next
        # refresh, and there is no volume to save — a denied session stops
        # refreshing. It also means re-activating someone in Okta works
        # immediately instead of after a cache window.
        return StatusVerdict(False, status or "UNKNOWN")

    def _prune(self, now: float) -> None:
        """Drop expired entries. Keyed by email, so the live set is bounded by
        headcount — this exists so a long-running process does not accumulate
        every person who ever refreshed."""
        for email, deadline in list(self._allowed_until.items()):
            if deadline <= now:
                self._allowed_until.pop(email, None)

    def _unavailable(self, email: str, reason: str) -> None:
        """Fail open, loudly. See the module docstring for why open."""
        logger.warning(
            "Okta user-status check unavailable; allowing the refresh (%s)",
            reason,
            extra={
                "user": email or "(no email claim)",
                "reason": reason,
                "event_category": "auth.refresh.status_check_unavailable",
            },
        )
