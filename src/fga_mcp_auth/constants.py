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
# Third-party hosted clients get an EXACT URI, never a domain: a domain grant
# would let any page on that host receive our auth codes. Cursor's cloud agent
# (2026-10-16, Nick) is the first; local clients already pass via loopback.
EXACT_REDIRECT_URIS = frozenset({"https://www.cursor.com/agents/mcp/oauth/callback"})

# --- lifetimes --------------------------------------------------------------
ACCESS_TTL = 3600  # 1h — short because stateless tokens can't be revoked
# Bounds the offboarding tail. Refresh re-mints from the token's own claims, so
# without OKTA_ADMIN_TOKEN set (see below) nothing re-contacts Okta and a
# deactivated account keeps working until its refresh token expires: this window
# IS that exposure, and it stays the backstop even with the check on.
# 7d rather than 24h because staff
# Okta sessions are 12h with a persistent cookie, so re-login is normally a silent
# redirect — but a daily one would still be felt. Do not raise this back to 30d.
# Immediate cut-off would need Okta's own refresh token exchanged on each refresh,
# which we can't do: our tokens are signed but NOT encrypted, so embedding an Okta
# credential in them would hand it to the client.
REFRESH_TTL = 7 * 24 * 3600
AUTH_CODE_TTL = 300
PENDING_TTL = 600  # how long the Okta round-trip can take before state expires

# --- refresh-time Okta user-status check (opt-in, OKTA_ADMIN_TOKEN) ---------
# With the check on, the paragraph above still holds as the BACKSTOP but stops
# being the whole story: a deactivated account loses access on its next refresh,
# so the tail is one ACCESS_TTL plus at most this cache window rather than 7d.
#
# 300s is the trade between how fresh a deactivation is and how many admin-API
# calls a fleet of seven servers makes on every session refresh. Raising it
# lengthens the tail one-for-one; lowering it buys minutes and costs quota.
USER_STATUS_CACHE_TTL = 300
# Short on purpose: this sits inside a token exchange claude.ai is waiting on,
# and the failure policy is fail-open, so a slow Okta should hit the timeout and
# allow rather than hang the refresh.
USER_STATUS_TIMEOUT = 5.0
# The one-time canary that proves OKTA_ADMIN_TOKEN is actually accepted by Okta
# (GET /api/v1/users/me) rides on the first refresh, so it gets the same budget
# as the check itself: a slow Okta must not turn the first refresh of the process
# into a ten-second wait.
USER_STATUS_BOOT_TIMEOUT = 5.0
# The two Okta statuses a human can still sign in from. PASSWORD_EXPIRED is one
# of them: the account is live, Okta will make them change their password at the
# next interactive login, and killing their session for it would be a password
# policy enforced as an outage. Everything else — SUSPENDED, DEPROVISIONED,
# LOCKED_OUT, PROVISIONED, RECOVERY, STAGED, and anything Okta adds later —
# denies, because this gate is the offboarding bound and an unrecognized status
# must not silently widen it.
OKTA_LOGIN_STATUSES = frozenset({"ACTIVE", "PASSWORD_EXPIRED"})

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
# structural: beginning with "<MCP_SERVER_SLUG>." is what stops one value being
# reused across the seven DO apps — the exact convenience move `aud` defends
# against for MCP_TOKEN_SECRET. Warned about by default, enforced at boot by
# MCP_REQUIRE_BOUND_BEARER, because the two live servers hold unprefixed values
# that socialbot also holds (see provider._require_bound_service_token).
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

# --- OAuth error responses --------------------------------------------------
# The only outcomes /okta/callback will send back to a client, with our own
# descriptions. Fixed table for the same reason as ERROR_REASONS: neither Okta's
# error string nor a denial message from the group gate is ever echoed onward.
#
# BEHAVIOR CHANGE, FLAGGED: quorum and ob3 render these on-origin as HTML
# 400/403/500. This package delivers them to the validated redirect_uri instead
# (see routes.py) — claude.ai's connector is waiting on that callback, and an
# HTML page it never fetches is a spinner. The cost is that the denial reason no
# longer reaches a page we control, so the descriptions below have to carry the
# next step themselves.
REDIRECT_ERRORS = {
    "access_denied": "Sign-in was refused. Contact FGA IT if you expect access to this server.",
    "server_error": "Sign-in could not be completed. Try connecting again.",
    # Denial-specific prose. Still ours, still fixed — the actionable half of
    # what quorum's 403 page used to show, minus anything Okta wrote.
    "account_not_permitted": (
        "Your Okta account is not permitted to use this FGA server. Ask #it-help to be "
        "added to its Okta group."
    ),
    "wrong_email_domain": (
        "This server only accepts FGA accounts. Sign in with your FGA email address."
    ),
}

# Table key -> the code that goes on the wire. Keys that are not listed send
# themselves. RFC 6749 §4.1.2.1 defines the vocabulary claude.ai parses, so the
# extra keys above are descriptions of an `access_denied`, not new codes.
REDIRECT_ERROR_CODES = {
    "account_not_permitted": "access_denied",
    "wrong_email_domain": "access_denied",
}
# What may ever appear as `error=` on the wire.
RFC6749_ERROR_CODES = frozenset({"access_denied", "server_error"})
