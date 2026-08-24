"""Shared constants. Values are the reconciled ones from fga-quorum-mcp and
fga-ob3-mcp (identical in both, except where a verdict in the reconciliation map
picked a side). Changing any of these changes fleet-wide behavior."""

from __future__ import annotations

# --- redirect allowlist -----------------------------------------------------
# Split by scheme policy: loopback hosts may be plain http (a local connector
# has no cert), the public Claude hosts must be https. Loopback is matched
# EXACTLY — `anything.localhost` and `anything.127.0.0.1` used to pass the old
# suffix rule, which was over-broad for no benefit.
LOOPBACK_REDIRECT_HOSTS = frozenset({"localhost", "127.0.0.1"})
HTTPS_REDIRECT_DOMAINS = frozenset({"claude.ai", "claude.com"})
ALLOWED_REDIRECT_DOMAINS = LOOPBACK_REDIRECT_HOSTS | HTTPS_REDIRECT_DOMAINS

# --- lifetimes --------------------------------------------------------------
ACCESS_TTL = 3600  # 1h — short because stateless tokens can't be revoked
# Bounds the offboarding tail. Refresh re-mints from the token's own claims and
# never re-contacts Okta, so a deactivated account keeps working until its refresh
# token expires; this window IS that exposure. 7d rather than 24h because staff
# Okta sessions are 12h with a persistent cookie, so re-login is normally a silent
# redirect — but a daily one would still be felt. Do not raise this back to 30d.
# Immediate cut-off would need Okta's own refresh token exchanged on each refresh,
# which we can't do: our tokens are signed but NOT encrypted, so embedding an Okta
# credential in them would hand it to the client.
REFRESH_TTL = 7 * 24 * 3600
AUTH_CODE_TTL = 300
PENDING_TTL = 600  # how long the Okta round-trip can take before state expires

# --- registry ---------------------------------------------------------------
# DCR is unauthenticated by design (claude.ai has to be able to register), so the
# client registry is an unbounded write primitive for anyone who can reach
# /register. Cap it and evict oldest-first. shortcut: a flat FIFO cap — an LRU
# keyed on last use would be kinder to long-idle connectors if we ever outgrow
# this. Eviction is survivable: a dropped client re-registers on its next connect.
MAX_CLIENTS = 500

# --- identity ---------------------------------------------------------------
SERVICE_CLIENT_ID = "fga-service-token"  # synthetic client_id for the static bearer
OKTA_SCOPES = "openid email profile groups"

# The static bearer is opaque, not a JWT, so it cannot carry an `aud` claim —
# and it grants MORE than a user token does (SERVICE_CLIENT_ID is unrestricted
# at the group gate, and never expires). Its audience binding is therefore
# structural: it must begin with "<MCP_SERVER_SLUG>." or the server refuses to
# boot. That makes reusing one bearer across the seven DO apps impossible rather
# than merely discouraged — the exact convenience move `aud` defends against for
# MCP_TOKEN_SECRET.
SERVICE_TOKEN_SEPARATOR = "."

# --- token format -----------------------------------------------------------
# Carried as the `v` claim. Bump ONLY when the claim set changes incompatibly:
# an unrecognized version is answered with RFC-compliant `invalid_grant`, which
# claude.ai renders as an inline Connect card and retries, so a format change
# degrades to a one-click re-auth instead of a 500.
TOKEN_VERSION = 1

# --- error page copy --------------------------------------------------------
# Fixed lookup table. `/oauth/error` never echoes its input, so the page cannot
# be used to render attacker-chosen prose on our own origin.
ERROR_REASONS = {
    "redirect_not_allowed": (
        "This application's redirect address isn't permitted by this server. "
        "If you're setting up a connector, use the URL from the FGA runbook."
    ),
}
ERROR_REASON_FALLBACK = "This sign-in request was rejected."
