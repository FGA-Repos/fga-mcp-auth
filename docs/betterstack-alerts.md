# BetterStack alerts — staged, not created

Four alert definitions for the MCP fleet, ready to paste into BetterStack on deploy
day. **Nothing here has been created.** No API call was made; no source token appears
in this file (they live in 1Password / the `betterstack-logging` memory note).

## Before you paste

* **Fields come from `extra=` on stdlib `logging` calls.** They only become
  queryable JSON keys if the host server installs a JSON formatter
  (`python-json-logger`, per the FGA logging standard). On a server still using the
  default formatter the extras are dropped entirely and only `message` survives —
  check Live Tail before saving an alert, and fall back to the message-substring
  query given for each alert.
* **Field prefix.** DO's Logtail drain usually nests the payload, so
  `event_category` may need to be `json.event_category`. Confirm once in Live Tail
  and apply the same prefix to all four queries.
* **`server`** is `MCP_SERVER_SLUG` (`fga-quorum`, `fga-ob3`, …) and is present on
  most — not all — records. Where it is missing, scope by BetterStack source
  instead. Each server needs its own source + DO log forwarding; only some of the
  seven have one today.
* **Retention.** Free tier is 3-day retention / 1 GB per month. Any alert or
  investigation window longer than 3 days does not work until the plan changes —
  this bites alert 3 directly (`REFRESH_TTL` is 7 days).
* `logger` is the module path (`fga_mcp_auth.user_status`, `fga_mcp_auth.grants`,
  `fga_mcp_auth.audit`, `fga_mcp_auth.routes`, `fga_mcp_auth.gating`).

Notify target placeholder used below: **`<NOTIFY>`** = BetterStack notification
policy "FGA MCP oncall" → jacob@thefga.org (+ SMS on P1). Create the policy first,
then swap it into all four.

---

## 1. User-status check EFFECTIVELY OFF — bad SSWS token

The one-shot canary in `OktaUserStatus.verify_admin_token()`. Okta answered 401/403
to `GET /api/v1/users/me`, so every lookup this process makes will fail open: the
offboarding tail is silently back to 7 days while the config claims otherwise.

```
event_category:"auth.config.error" AND level:"ERROR"
```
Fallback (no JSON formatter): `"user-status check is EFFECTIVELY OFF"`

* **Threshold:** ≥ 1 occurrence in 5 min. **Group by `server`** — one incident per
  server, not one for the fleet.
* **Severity:** P1 / critical. This is a security control that reports itself as on
  while being off.
* **Notify:** `<NOTIFY>` immediately, no delay window.
* **When it fires:** re-mint `OKTA_ADMIN_TOKEN` from a **read-only** Okta admin
  account, update that server's DO env, redeploy. Confirm recovery by the matching
  `auth.config` INFO line: `"user-status check ENABLED"`.

## 2. `status_check_unavailable` rate — Okta admin API failing

The fail-open path in `OktaUserStatus._unavailable()`. Every one of these is a
refresh that was **allowed without checking Okta**. One is noise (a timeout); a
sustained rate means the check is effectively not running.

```
event_category:"auth.refresh.status_check_unavailable"
```
Fallback: `"Okta user-status check unavailable"`

Fields on the record: `user` (email, or `(no email claim)`), `reason` (e.g.
`HTTP 429`, `ConnectTimeout: …`, `response body is JSON list, not an object`).

* **Threshold:** > 10 events in 15 min, evaluated every 5 min, grouped by `server`.
  (Tune after a week of baseline — the floor is one event per user per 5-min cache
  window, so headcount sets the noise level.)
* **Severity:** P2 / warning. Escalate to P1 if it persists past 60 min.
* **Notify:** `<NOTIFY>`, 15-minute delay so a blip self-resolves.
* **When it fires:** read `reason` on a sample record. `HTTP 401`/`403` → treat as
  alert 1 (token died mid-life, no canary re-runs in that process — restart the app
  to re-fire it). `HTTP 429` → admin-API quota, consider raising
  `USER_STATUS_CACHE_TTL`. Timeouts / 5xx → check Okta status, no action if Okta is
  degraded; refreshes are still being allowed, which is the intended behavior.

## 3. Auth activity for a deactivated identity

**This is a query, not a self-firing alert.** BetterStack cannot join against Okta,
so nothing knows an identity was deactivated. Read the limits before relying on it.

The automatic half already exists: when someone is deactivated, their next refresh
produces

```
event_category:"auth.refresh.user_inactive"
```
with `user` (email), `okta_status` (`SUSPENDED`, `NOT_FOUND`, `DEPROVISIONED`,
`LOCKED_OUT`…), `client_id`, `server`. Worth a **low-threshold informational alert**
(≥ 1 in 15 min → `<NOTIFY>` daily digest, P3): it confirms the control fired, and an
unexpected name in it is worth a look.

The manual half — *did they do anything in the tail before the refresh was refused?*
Run this after any offboarding, substituting the email:

```
event_category:"mcp.call" AND user:"leaver@thefga.org"
```
and the failure companion `event_category:"mcp.call.error" AND user:"leaver@thefga.org"`.
Fields: `user`, `okta_sub`, `client_id`, `server`, `tool`, `mcp_method`,
`duration_ms`. Widen with `event_category:"auth.token.issued"` (token endpoint) and
`event_category:"auth.success"` (Okta login) for the same `user`.

**Limits, honestly:**

* **SDK 2.0 only.** `AuditMiddleware` is the only source of per-call `user` records
  and it has no SDK 1.x equivalent. On a 1.x server a deactivated user's tool calls
  are simply not logged — the most you see is `auth.token.issued` / `auth.success`
  at the token and login endpoints.
* Only `tools/call` produces an INFO `mcp.call` line; `tools/list` and other methods
  are deliberately not logged. A failed call logs `mcp.call.error` regardless.
* Calls made with the static service bearer log as `user: "service-token"` — no
  human identity, by design.
* The window that matters is up to one access-token lifetime (≤1h) after
  deactivation, plus the 5-min status cache. With the check disabled it is up to
  `REFRESH_TTL` (7 days) — **longer than free-tier retention**, so the evidence may
  no longer exist.
* **When it fires / when you run it:** any hit after the deactivation timestamp →
  treat as an active session on a revoked identity. Revoke the Okta session, rotate
  `MCP_TOKEN_SECRET` on the affected server (invalidates every live token there,
  everyone re-auths), and check `tool` for what was actually reached.

## 4. Authentication-failure spikes — compromise indicator

Stolen-credential pattern, DonorsTrust-style. Three separate failure categories,
one alert each is overkill — one alert on the union, then triage by
`event_category`.

```
event_category:("auth.refresh.rejected" OR "auth.failure" OR "auth.registration.rejected" OR "auth.redirect.rejected" OR "auth.tool.denied")
```
Fallback: match on `"refusing to re-mint"` OR `"Login denied"` OR
`"Okta returned error"`.

* `auth.refresh.rejected` (`fga_mcp_auth.grants`, INFO) — a refresh token that
  failed verification at exchange. **The strongest signal:** normal clients do not
  present unverifiable refresh tokens. Fields: `client_id`, `server`.
* `auth.failure` (`fga_mcp_auth.routes`, WARNING) — Okta returned an error, or the
  group/domain gate refused the login. ⚠️ this record carries **no `server` field**;
  scope by source.
* `auth.registration.rejected` / `auth.redirect.rejected` (`fga_mcp_auth.provider`)
  — someone registering a client or redirect URI we refuse. Rare enough that any
  volume is interesting.
* `auth.tool.denied` (`fga_mcp_auth.gating`) — authenticated but out-of-group;
  usually a permissions gap, occasionally lateral movement. Fields: `tool`,
  `required_groups`, `reason`, `server`.

* **Threshold:** > 20 events in 10 min fleet-wide, **or** > 5
  `auth.refresh.rejected` in 10 min from a single `client_id` (the second is the one
  that matters — set it as a separate rule if BetterStack's grouping allows).
* **Severity:** P2 by default; P1 if `auth.refresh.rejected` alone crosses its
  threshold.
* **Notify:** `<NOTIFY>`, no delay on the refresh-rejected rule.
* **When it fires:** identify the `client_id` and `user`; if it looks like probing,
  rotate `MCP_TOKEN_SECRET` on the affected server and check the DO HTTP access log
  for the source IPs (401s on the MCP endpoint are **not** in these logs — the
  package logs nothing on a plain `load_access_token` miss).

**The honest gap in alert 4:** a *working* stolen token produces no failures at all.
It looks like normal success. The companion query for that scenario is volume /
pattern anomaly on the success path, which has no good threshold and has to be
eyeballed:

```
event_category:"auth.token.issued"      # new sessions — watch for odd hours, unfamiliar client_id
event_category:"mcp.call" | group by user, tool   # one user's call volume against their own baseline
```

Run that weekly rather than alerting on it. A real detection for a valid stolen
token needs an Okta-side signal (impossible travel, new device), not a log
threshold here.

---

## Deploy-day order

1. Create/verify a BetterStack source per MCP server + DO log forwarding
   (Logtail type, source token — not the API token).
2. Confirm the host servers install the JSON formatter; verify one `mcp.call`
   record in Live Tail and note whether fields are prefixed.
3. Create the `<NOTIFY>` policy.
4. Paste alerts 1, 2 and 4. Alert 3 is a saved search plus the low-threshold
   `auth.refresh.user_inactive` rule.
5. Baseline for a week, then tune the thresholds in 2 and 4 — the numbers above are
   starting points, not measurements.
