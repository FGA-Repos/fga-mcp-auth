# fga-mcp-auth

FGA's shared Okta OIDC auth layer for MCP servers. One package, both MCP SDK
lines (1.26+ and 2.x).

Seven FGA MCP servers need per-user Okta authentication. Two of them grew their
own ~600-line `oauth.py` and immediately diverged; the rest still share one
static admin password. This package is the extraction of those two modules,
reconciled behavior-by-behavior with the safer side winning, so a change (the
Enterprise Managed Auth grant, say) lands once instead of seven times.

## What it does

* Runs the OAuth 2.1 authorization-server dance that Claude's connector UI
  requires, with **Okta as the login, not the token issuer**. FGA does not have
  Okta's API Access Management SKU (verified 2026-07-29), so Okta cannot mint
  tokens audienced to an MCP server. We redirect the human to Okta for OIDC,
  consume the `id_token` to learn who they are, and issue our own tokens. This
  needs only Okta's org authorization server, which every tenant has.
* Issues **stateless HS256 tokens** that carry the user's identity in their
  claims. Nothing is stored server-side, so a DO App Platform redeploy — which
  happens on every push — no longer logs every staff member out.
* Enforces a **redirect allowlist at DCR registration**, keeps `/authorize`
  answering on our own origin, and never reflects attacker-supplied text.
* Keeps the static **`MCP_BEARER_TOKEN` service path** working for socialbot,
  curl and CI.
* Ships **per-user audit logging** (SDK 2.0) and an opt-in **per-tool group
  gate**.
* Optionally **re-checks the user's Okta status at every refresh**
  (`OKTA_ADMIN_TOKEN`), which cuts the offboarding tail from ≤7 days to ≤1 hour.
  Fails open by design — see **Offboarding semantics**.

## What it deliberately is not

* **Not a framework.** One IdP (Okta), one flow shape, no plugin points. If a
  second IdP ever matters, that is a fork of this package, not a feature of it.
* **No revocation.** Tokens are stateless, so `revoke_token` cannot invalidate
  anything. The wiring advertises `RevocationOptions(enabled=False)` rather than
  returning HTTP 200 to a revocation request while the token keeps working. The
  blunt instrument is rotating `MCP_TOKEN_SECRET`, which invalidates everything.
* **No *continuous* Okta re-check.** Since v1.1 the status check runs at the
  refresh grant only (opt-in, `OKTA_ADMIN_TOKEN`), not per MCP request — that
  would be an Okta admin-API call on every tool call. So a deactivated account
  keeps its current access token until it expires: the tail is ≤1h with the check
  on, ≤7 days without. See **Offboarding semantics**.
* **No EMA / jwt-bearer grant.** Waitlist-gated. `grants.py` keeps the door open
  (isolated grant handlers, RFC 8707 `resource` carried through) and nothing
  more. Its docstring also records how the grant will have to be *mounted* —
  ASGI middleware or route-list surgery, because FastMCP appends custom routes
  after the SDK's, so `custom_route("/token")` is dead code.
* **Not an authorization model.** The group gate denies a tool call. What a tool
  then returns, and what it redacts, stays the consumer's problem.

## Install

Consumers install a **SHA-pinned GitHub tarball**, not `git+https` — the DO
Dockerfiles are `python:3.12-slim` with no git binary, and a tarball at a full
commit SHA is immutable where a tag is not:

```
# fga-mcp-auth v1.1.0
fga-mcp-auth @ https://github.com/FGA-Repos/fga-mcp-auth/archive/<full-40-char-sha>.tar.gz
```

## Wiring — MCP SDK 1.x (`FastMCP`)

```python
from mcp.server.fastmcp import FastMCP
from fga_mcp_auth import Settings, wire_sdk1

mcp = FastMCP(name="fga-quorum", instructions=..., json_response=True)
register_all(mcp)  # your tools

if cfg.transport == "http":
    wire_sdk1(mcp, Settings())  # provider, AuthSettings, transport
    # security, /login, /okta/callback,
    # /oauth/error — all of it
    app = mcp.streamable_http_app()
    app.routes.insert(0, Route("/health", health))
    uvicorn.run(app, host=cfg.host, port=cfg.port)
else:
    mcp.run(transport="stdio")  # local dev, authless by design
```

`wire_sdk1` sets both `_auth_server_provider` and `_token_verifier` (1.x needs
both) and returns the provider if you want it.

## Wiring — MCP SDK 2.0 (`MCPServer`)

```python
from mcp.server import MCPServer
from fga_mcp_auth import (
    Settings,
    audit_middleware,
    auth_kwargs,
    build_http_app,
    register_auth_routes,
)

settings = Settings()
kwargs = {"name": "fga-ob3", "instructions": ..., "lifespan": lifespan}

if cfg.transport == "http":
    provider, auth = auth_kwargs(settings)
    mcp = MCPServer(**kwargs, middleware=[audit_middleware(settings)], **auth)
    register_auth_routes(mcp, provider)  # /login, /okta/callback, /oauth/error
else:
    mcp = MCPServer(**kwargs)

app = build_http_app(mcp, settings, json_response=True, stateless_http=True, host=cfg.host)
```

`auth_kwargs` never returns a `token_verifier`: SDK 2.0 rejects being handed
both that and an `auth_server_provider`.

**Use `build_http_app`, not `mcp.streamable_http_app()`.** On this SDK line
DNS-rebinding / Host-header protection is an argument to the app builder, not to
the constructor, so it is the one part of the 1.x helper's job that `auth_kwargs`
structurally cannot do — and a consumer that calls the SDK method directly drops
that protection with every test still passing. Everything else passes straight
through, and an explicit `transport_security=` still wins if a server fronts the
DO app with extra hostnames.

Calling the wrong helper for the installed SDK raises `SdkMismatch` naming the
right one.

## Per-tool group gating (optional, ships OFF)

```python
from fga_mcp_auth import GroupGate

gate = GroupGate(settings)

@mcp.tool()
@gate.require("MCP Teamtailor Users")
async def get_candidate(...): ...

@mcp.tool()
@gate.require("MCP Teamtailor Users")
def list_candidates(...): ...   # sync tools are gated the same way
```

With `MCP_TOOL_GATING` unset the decorator returns the function **unwrapped** —
no runtime cost and no behavior change. With it on, `async def` and `def` tools
are both wrapped in their own shape, so the SDK still sees the kind of callable
it was given.

Turning it on takes two coordinated steps, in this order:

1. Add a `groups` claim to the shared Okta OIDC app. **It has none today.**
2. Set `MCP_TOOL_GATING=true` on the server.

Doing (2) first denies every gated call, because the gate fails closed on a
missing claim. That is correct — treating an absent claim as "no restriction"
would turn a misconfigured Okta app into an open door — but it is an outage.

The static service token is admitted through gated tools, matching today's
behavior where socialbot has unrestricted access. Narrowing that is a deliberate
future change.

## Environment variables

| Variable | Required (HTTP) | Purpose |
|---|---|---|
| `MCP_ALLOWED_HOST` | **yes** | Public host, e.g. `fga-example-mcp.ondigitalocean.app`. Becomes the JWT `iss` claim and the DNS-rebinding allowlist. |
| `MCP_SERVER_SLUG` | **yes** | Canonical server identity, e.g. `fga-quorum`. Becomes the token `aud` claim and the audit-log `server` field. |
| `MCP_TOKEN_SECRET` | **yes** | HS256 signing key, ≥32 bytes. **Use a distinct value per server.** |
| `OKTA_ISSUER` | **yes** | Org authorization server URL, e.g. `https://example.okta.com`. Endpoints come from its discovery document, never hardcoded. |
| `OKTA_CLIENT_ID` | **yes** | The shared FGA OIDC app. |
| `OKTA_CLIENT_SECRET` | **yes** | Used with `client_secret_basic` at the token exchange. |
| `MCP_BEARER_TOKEN` | no | Static service token for socialbot / curl / CI. Unset = no service path. **Must be `<MCP_SERVER_SLUG>.<random>`** — anything else refuses to boot (see `MCP_REQUIRE_BOUND_BEARER`). A value of exactly `<slug>.` is always fatal. |
| `MCP_REQUIRE_BOUND_BEARER` | no | **Default on.** `false` downgrades the refusal above to a boot warning — the retrofit-only escape hatch for quorum and ob3, whose live unprefixed bearers socialbot also holds. Set it for that deploy, re-issue the bearer, then delete the variable. Nothing else should ever set it. |
| `MCP_ACCEPT_LEGACY_TOKENS` | no | `true` accepts pre-package tokens (no `aud`, no `v`) as format v1, for a silent retrofit cutover. Default off. Turn it back off inside the 7-day refresh window. |
| `OKTA_ADMIN_TOKEN` | no | SSWS token for Okta's Users API. Set = the refresh-time user-status check is on (a deactivated account loses access within ≤1h instead of ≤7d). Unset = no check, v1.0.0 behavior. **Mint it from a READ-ONLY Okta admin account** — an SSWS token inherits its creator's permissions, so a Super Admin token in seven DO app environments is a fleet-wide *write* credential solving a read problem. |
| `OKTA_ALLOWED_GROUPS` | no | CSV. Server-wide login gate. Empty = any authenticated Okta user. **Non-empty with no groups claim on the app = everyone denied.** |
| `OKTA_ALLOWED_EMAIL_DOMAINS` | no | CSV. Second login gate, checked beside groups. Empty = inert. |
| `MCP_TOOL_GATING` | no | `true` enables `GroupGate`. Default off. |
| `MCP_PORT` | no | Read, not owned — only to build a coherent issuer in local dev. |

Missing any of the six required vars raises one `RuntimeError` naming **all** of
them, at wiring time, before anything is attached. A server that boots with SSO
silently disabled is worse than one that refuses to start.

Consumer-owned and untouched by this package: `MCP_TRANSPORT`, `MCP_HOST`,
`LOG_LEVEL`, and every upstream API key.

### Rename table for the five password-era servers

| Old | New |
|---|---|
| `MCP_ADMIN_PASSWORD` | *(removed — the password path is gone entirely)* |
| `MCP_BEARER_TOKEN` | same name, **new value required**: `<slug>.<random>` |
| — | `MCP_TOKEN_SECRET` **(new)** |
| — | `MCP_SERVER_SLUG` **(new)** |
| — | `OKTA_ISSUER` **(new)** |
| — | `OKTA_CLIENT_ID` **(new)** |
| — | `OKTA_CLIENT_SECRET` **(new)** |
| — | `OKTA_ALLOWED_GROUPS`, `OKTA_ALLOWED_EMAIL_DOMAINS`, `MCP_TOOL_GATING` (optional) |

For `fga-quorum-mcp` and `fga-ob3-mcp`, every name already matches and two vars
are new: `MCP_SERVER_SLUG`, plus `MCP_REQUIRE_BOUND_BEARER=false` for the deploy
window. With that flag set the retrofit needs **no credential rotation**:
today's unprefixed `MCP_BEARER_TOKEN` keeps working (with a boot warning) and
socialbot is untouched. Without it the server refuses to start.

Re-issuing the bearer is a **separate, later step**, and it is a three-place
change — do all three inside one window:

1. `MCP_BEARER_TOKEN` on the DO app → `<slug>.<random>`
2. socialbot's config → the same value
3. any script / CI job / saved curl that holds the old one
4. then **delete** `MCP_REQUIRE_BOUND_BEARER` so the old value can never come back

Skipping (2) is a socialbot outage: every tool call 401s until its config
catches up. The five password-era servers have no such history, so they are
issued a prefixed bearer from the start and never set the flag at all.

Each server also needs its Okta redirect URI registered on the shared app:
`https://<app>.ondigitalocean.app/okta/callback`.

## Security notes

* **Give every server its own `MCP_TOKEN_SECRET`.** The `aud` claim is the
  structural backstop against replaying one server's token at another, not a
  licence to share one key across seven DO apps.
* **Slug-bind the service bearer.** `MCP_BEARER_TOKEN` is an opaque string, not
  a JWT, so it cannot carry `aud` — and it grants *more* than a user token
  (never expires, unrestricted at the group gate). A `<MCP_SERVER_SLUG>.<random>`
  value is what stops one shared bearer from opening every server: the value
  teamtailor accepts cannot be a value congress also accepts. **Required by
  default** — "cross-server replay is impossible even with identical secrets"
  has to cover the path that grants *more* than a user token, not only the JWT
  one, and a binding that shipped default-off is one an admin never meets.
  `MCP_REQUIRE_BOUND_BEARER=false` exists only so the two live servers can be
  retrofitted without a synchronized rotation. Distinct random half per server
  as well.
* **Mint `OKTA_ADMIN_TOKEN` from a read-only admin account.** An Okta SSWS token
  inherits the permissions of whoever created it and has no scopes of its own, so
  a Super Admin token copied into seven DO app environments is a fleet-wide write
  credential — user creation, group membership, app assignment — bought to answer
  one read question. This package only ever issues `GET /api/v1/users/{login}`,
  plus one `GET /api/v1/users/me` per process (the token canary below).
  Rotating it is safe in the sense that matters operationally: a revoked token
  fails open — the check stops working, loudly — rather than denying every
  refresh on the fleet.
* **`MCP_ALLOWED_HOST` is load-bearing.** Unset, `public_base_url` falls back to
  `http://localhost:8080` — the same string on every FGA MCP server. That is why
  it is boot-required, and why `aud` exists on top of it.
* **Stdio is authless by design.** Never run a gated server over stdio with
  `MCP_TOOL_GATING` on: there is no auth context, so the gate denies everything.
* **DCR is unauthenticated** (claude.ai needs it), so `/register` is an open
  write primitive. The client registry is capped at 500 with FIFO eviction, and
  rejected redirect URIs are logged by hostname only.
* **Nothing user-supplied is reflected.** `/oauth/error` looks its reason up in
  a fixed table, and Okta's `error` parameter goes to the log rather than onto a
  page on our own origin — escaping stops XSS but not phishing. The error
  *codes* sent back to the client come from a fixed table too, so nothing Okta
  chose ever travels onward.
* **Login errors are delivered to the client, not just rendered.** A failed
  callback 302s to the validated `redirect_uri` with `error` +
  `error_description` + `state` (RFC 6749 §4.1.2.1) — `access_denied` when the
  human was refused, `server_error` otherwise. Without that, claude.ai's
  connector waits on a callback that never arrives and the user sees a spinner.
  The exception is a request with **no** validated `redirect_uri` (unknown or
  expired state, or a URI that never passed the allowlist): those still answer
  on our own origin, because 302ing to an unchecked URI is the open redirect the
  allowlist exists to remove.

## Token format

```json
{
  "iss": "https://<MCP_ALLOWED_HOST>",
  "aud": "<MCP_SERVER_SLUG>",
  "v": 1,
  "typ": "access" | "refresh",
  "sub": "<okta sub>", "email": "...", "name": "...", "groups": [...],
  "client_id": "<dcr client id>", "scope": "",
  "iat": ..., "exp": ..., "jti": "..."
}
```

Verification pins `HS256` and requires `exp`, `iat`, `iss`, `aud`, `typ`,
`client_id` and `v`. An unrecognized `v` is answered with `invalid_grant`, which
claude.ai renders as an inline Connect card and retries — so a future format
change costs one click, never a 500.

Access tokens live 1 hour, refresh tokens 7 days, and refresh does **not** slide
the horizon — no floor, no exceptions. A refresh with 5 seconds left returns a
5-second pair; at 0 it returns `invalid_grant`. `REFRESH_TTL` is the outer bound
on the offboarding tail, so anything that lets a loop walk the expiry forward (a
`max(60, …)` floor did exactly that) is the end of the guarantee, not a rounding
detail. `OKTA_ADMIN_TOKEN` tightens the bound; it does not replace it.

### Deploying the retrofit: one forced reconnect, or the transition switch

`fga-quorum-mcp` and `fga-ob3-mcp` are live today and mint neither `aud` nor
`v`. Both are normally required, so **the first deploy that takes this package
invalidates every token those servers have already issued.** Every connected
staff member is prompted to reconnect, at the moment the deploy lands.

It degrades cleanly rather than breaking: a legacy access token gets 401 +
`WWW-Authenticate`, a legacy refresh gets `invalid_grant`, and claude.ai turns
both into an inline Connect card and retries the tool call. The static
`MCP_BEARER_TOKEN` path — socialbot included — does not go through this at all.

Two ways to land it. **Pick one per server and put it in the PR body:**

* **Accept the reconnect.** Deploy off-peak, announce it, expect the prompts.
  One click each, no config to remove afterwards.
* **Silent cutover.** Deploy with `MCP_ACCEPT_LEGACY_TOKENS=true`: existing
  tokens verify as format v1, and each session re-mints itself with both claims
  on its next refresh. Remove the var within the 7-day refresh window — by then
  nothing legacy is left. While it is on, legacy tokens (which have no `aud`)
  are not audience-checked; modern tokens still are, and a token bearing the
  *wrong* `aud` is rejected either way.

Neither option is behavior-identical, and no test can catch the cutover itself
(the statelessness suite only proves same-version round-trips), so it is a
deploy-timing decision for Jacob rather than an implementation detail.
`TestLegacyTokenRejection` pins the default failure shape and
`TestLegacyTransitionWindow` pins what the switch does and does not loosen.

## Offboarding semantics

What actually happens when IT deactivates someone in Okta. This is the question
the whole token design answers, so it is written down rather than inferred.

| Path | Cut-off |
|---|---|
| **Interactive login** (a new connector, or any re-auth) | **Immediate.** Okta refuses the OIDC hop; we never see them. |
| **Refresh, with `OKTA_ADMIN_TOKEN` set** | **≤1 hour** — their next refresh is `invalid_grant`, so they keep only the access token they already hold (`ACCESS_TTL`, 1h), plus at most the 300s status cache. |
| **Refresh, without it** | **≤7 days** (`REFRESH_TTL`). Refresh re-mints from the token's own claims, so nothing about the deactivation reaches it. |
| **`MCP_BEARER_TOKEN`** | **Never.** It is a service credential, not a person, and it does not refresh. Rotate it. |
| **Emergency kill switch** | **Rotate `MCP_TOKEN_SECRET`.** Every token that server ever signed stops verifying at the next request. Fleet-wide means rotating it on each server, which is the point — distinct secrets per server. |

The refresh check **fails open**: a timeout, transport error, 429, 5xx, or a
revoked SSWS token allows the refresh and logs
`auth.refresh.status_check_unavailable` at WARNING. An Okta admin-API hiccup
would otherwise lock every staff member out of every MCP server at once, and the
`REFRESH_TTL` horizon is still underneath as the backstop — the worst case of a
failing check is exactly the v1.0.0 behavior. A denial logs
`auth.refresh.user_inactive` with the email and the Okta status, and answers
`invalid_grant` with the same description an expired refresh token gets, so
claude.ai shows the reconnect card and Okta does the actual refusing.

`ACTIVE` and `PASSWORD_EXPIRED` pass. Everything else denies — `SUSPENDED`,
`DEPROVISIONED`, `LOCKED_OUT`, a 404 (deprovisioned accounts are eventually
deleted), and any status Okta invents later, because this gate *is* the
offboarding bound and an unrecognized string must not silently widen it.

⚠️ **The lookup resolves by Okta *login*, using the token's `email` claim — it
assumes login == email, which is true at FGA today.** Rename someone's Okta login
away from their email and that person 404s: an *active* account denied at every
refresh, reconnecting roughly hourly, with `auth.refresh.user_inactive` logging
`okta_status=NOT_FOUND`. If a login ever gets renamed, that log line is the tell.

**`OKTA_ADMIN_TOKEN` being set is not proof the check runs.** Because it fails
open, a revoked, rotated, mistyped or under-scoped SSWS token 401s on every
lookup and every one of those *allows* the refresh — the tail is quietly back to
7 days. So the first lookup of each process first asks Okta about the token
itself (`GET /api/v1/users/me`, once, 5s, never fatal) and logs the verdict:

| Boot / first-refresh log | Means |
|---|---|
| `...check DISABLED (OKTA_ADMIN_TOKEN not set)` | v1.0.0 behavior, on purpose. |
| `...check CONFIGURED` | The env var is set. Nothing verified yet — Okta has not been asked. |
| `...check ENABLED (…admin token accepted by Okta)` | Running. This is the line to alert on the absence of. |
| `...check is EFFECTIVELY OFF` (ERROR) | Okta rejected the token (401/403). Re-mint it; until then the tail is `REFRESH_TTL`. |
| `Could not verify OKTA_ADMIN_TOKEN…` (WARNING) | Indeterminate — Okta was unreachable. The token may be fine. |

## Deliberate behavior changes vs. live quorum and ob3 — FLAGGED

Everything else in this package is the safer of the two live implementations.
These five are **not supersets** of what is running today, so they are listed
here to be copied into each retrofit PR body and signed off, rather than
discovered at deploy time.

| # | Change | Who it affects | What it costs |
|---|---|---|---|
| 1 | **Callback failures 302 to the client** instead of rendering HTML 400/403/500 on our origin. Every rejection path: Okta `error`, RFC 9207 `iss` mismatch, missing `code`, group/domain denial, unexpected exception. | Both live servers. Quorum's suite pinned "a callback rejection never 302s" as a security property; that test is replaced. | claude.ai stops spinning forever on a denial (the reason it changed). The user now sees one of *our* fixed descriptions instead of the on-origin page, and a runbook watching for 403/500 on `/okta/callback` sees 302s. The denial reason itself stays in the log. A missing `code` also consumes the pending state where quorum left it retryable. |
| 2 | **`aud` and `v` are required claims**, so pre-package tokens are rejected. | Both live servers, at the first deploy. | A synchronized reconnect card for every connected staff member, unless the deploy sets `MCP_ACCEPT_LEGACY_TOKENS=true` — see the section above. |
| 3 | **The service bearer must be slug-bound.** | Both live servers, which run unprefixed bearers. | Their retrofit deploy must set `MCP_REQUIRE_BOUND_BEARER=false`, or the server will not boot. |
| 4 | **Fail-loud startup**: missing Okta config refuses to boot. | ob3, which could boot with SSO silently disabled. | Nothing, if the env is complete. That is the point. |
| 5 | **Revocation is advertised as disabled** (`RevocationOptions(enabled=False)`). | Both. | `/revoke` disappears. It never revoked anything — stateless tokens — so it returned 200 while the token kept working. |

Denial messages are the mitigation for (1): the fixed `error_description` for a
group denial says to ask for the Okta group, and for a domain denial says to use
an FGA account, so the actionable half of quorum's 403 page survives the bounce.
The wire `error` stays RFC 6749 vocabulary (`access_denied` / `server_error`),
which is all claude.ai parses.

## Release and pinning policy

* Consumers **pin the full commit SHA**, in a tarball URL, with a comment naming
  the version. Tags are for humans; the SHA is the pin.
* Tags are immutable by convention only. Never point a consumer at a branch.
* Bump one consumer at a time and deliberately. There is no fleet-wide upgrade
  button, on purpose: a regression in this package logs staff out of whichever
  servers took it.
* CI runs `--locked`: every job installs exactly the resolution in `uv.lock` and
  fails if `pyproject.toml` and the lockfile have drifted.
* Dependency updates are therefore deliberate — run `uv lock` and commit the
  lockfile alongside the `pyproject.toml` change, never as a silent CI-time float.

## Test matrix

The suite must pass under both SDK lines:

```bash
uv run --isolated --group dev --group sdk1 pytest    # mcp>=1.26,<2
uv run --isolated --group dev --group sdk2 pytest    # mcp>=2
```

`tests/test_wiring_sdk1.py` and `tests/test_wiring_sdk2.py` self-skip on the
wrong leg; everything else runs on both.

## Changelog

### 1.1.0

* **New — refresh-time Okta user-status check (`OKTA_ADMIN_TOKEN`, opt-in).**
  Stateless refresh tokens re-mint from their own claims, so v1.0.0's offboarding
  tail was the full 7-day `REFRESH_TTL`. With an SSWS token set, every
  `refresh_token` grant asks Okta whether the account can still log in (300s
  per-email cache, allow-results only) and answers `invalid_grant` if it cannot —
  taking the tail down to one access-token lifetime. Fails **open** on any
  unavailability, because a check that denies during an Okta blip is a
  fleet-wide outage of its own making. See **Offboarding semantics**.
* The admin token is **verified against Okta once per process** before its first
  answer is trusted, and the check only calls itself `ENABLED` after Okta agrees.
  A rejected token is an `ERROR` saying the check is *effectively off* rather
  than a boot line claiming it is on — a fail-open check with a dead credential
  is otherwise indistinguishable from a working one.
* Unset `OKTA_ADMIN_TOKEN` is v1.0.0 behavior exactly, and which one you are
  running is stated in the startup log rather than left to be inferred.
* No change to the service-bearer path, the login leg, the token format (`v` is
  still 1), or any wiring signature. Nothing in a consumer has to change to take
  this version.

### 1.0.0

Initial extraction from `fga-quorum-mcp` and `fga-ob3-mcp`. Behavior is the
safer of the two everywhere they differed, plus:

* **New — audience-bound tokens.** Every token carries `aud` (the server slug)
  and verification requires it. Previously the only cross-server boundary was
  `iss`.
* **New — token format version (`v`).** Unrecognized versions degrade to
  `invalid_grant` instead of an exception.
* **New — the service bearer is slug-bound.** `<MCP_SERVER_SLUG>.<random>` stops
  one bearer being shared across the fleet, which `aud` cannot do for an opaque
  string. Required at boot; `MCP_REQUIRE_BOUND_BEARER=false` is the escape hatch
  that lets quorum and ob3 retrofit before re-issuing their bearers (a
  three-place change that includes socialbot's config).
* **New — `MCP_ACCEPT_LEGACY_TOKENS`**, the transition switch that turns the
  forced reconnect above into a silent cutover. Default off.
* **Fixed — a refresh token that fails verification** (an expiry crossed between
  the SDK's check and ours) used to mint an anonymous, indefinitely renewable
  session. It is now `invalid_grant`.
* **Fixed — the refresh expiry could slide outward.** A `max(60, exp - now)`
  floor meant a refresh inside the last minute of a token's life came back with
  a *later* expiry than it went in with, so a loop could hold a session open
  past `REFRESH_TTL` forever — the offboarding bound this package is built
  around. The horizon is now hard, and it caps the access token minted with it.
* **Fixed — login errors never reached the OAuth client.** A group-gate denial
  or a failed Okta exchange rendered an HTML page on our origin, so claude.ai
  sat waiting on a callback that never came. Failures now redirect to the
  validated `redirect_uri` with `error` + `state` per RFC 6749 §4.1.2.1, and the
  fixed `error_description` carries the user's next step (join the Okta group /
  use your FGA account) that the on-origin page used to give them.
  *Behavior change vs. live quorum/ob3 — item 1 in the flagged table above.*
* **Fixed — `GroupGate` on a sync tool.** The wrapper was unconditionally
  `async`, so with gating on a permitted caller of a plain `def` tool got a
  `TypeError` while denials worked: turning gating on would have broken the
  gated tools for exactly the people allowed to use them.
* **Fixed — the SDK 2.0 wiring dropped transport security.** `build_http_app`
  now supplies the DNS-rebinding / Host-header protection that `wire_sdk1` sets
  and that ob3 passes live; nothing prompted a 2.0 consumer to keep it.
* **New — hardened redirect allowlist.** Exact-host matching for loopback, https
  required for `claude.ai`/`claude.com`, backslashes rejected outright.
* **Fixed — a signed token with no `client_id`** used to raise `KeyError` and
  return 500. It is now a clean 401.
* **New — `OKTA_ALLOWED_EMAIL_DOMAINS`** and the per-tool `GroupGate`, both
  inert by default.

Two deliberate behavior changes for `fga-ob3-mcp`, both flagged:

1. **Fail-loud startup.** It could previously boot with Okta silently disabled;
   now it refuses.
2. **The `/login` hop.** The package uses `fga-quorum-mcp`'s shape for both SDK
   lines — `authorize()` returns a relative `/login?state=...` and a dedicated
   route does the Okta redirect — rather than ob3's direct-to-Okta authorize.
   One extra 302, one new route, no user-visible difference. Two flow shapes
   behind a flag would re-seed the drift this package exists to remove.
