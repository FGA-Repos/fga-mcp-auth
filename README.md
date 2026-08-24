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

## What it deliberately is not

* **Not a framework.** One IdP (Okta), one flow shape, no plugin points. If a
  second IdP ever matters, that is a fork of this package, not a feature of it.
* **No revocation.** Tokens are stateless, so `revoke_token` cannot invalidate
  anything. The wiring advertises `RevocationOptions(enabled=False)` rather than
  returning HTTP 200 to a revocation request while the token keeps working. The
  blunt instrument is rotating `MCP_TOKEN_SECRET`, which invalidates everything.
* **No Okta re-check at refresh.** Refresh re-mints from the token's own claims,
  so a deactivated Okta account keeps working until its refresh token expires.
  `REFRESH_TTL` (7 days) *is* the offboarding tail. Adding a status check needs
  an SSWS token in seven deploys plus a failure policy — deferred to v1.1.
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
# fga-mcp-auth v1.0.0
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
from mcp.server.transport_security import TransportSecuritySettings
from fga_mcp_auth import Settings, audit_middleware, auth_kwargs, register_auth_routes

settings = Settings()
kwargs = {"name": "fga-ob3", "instructions": ..., "lifespan": lifespan}

if cfg.transport == "http":
    provider, auth = auth_kwargs(settings)
    mcp = MCPServer(**kwargs, middleware=[audit_middleware(settings)], **auth)
    register_auth_routes(mcp, provider)  # /login, /okta/callback, /oauth/error
else:
    mcp = MCPServer(**kwargs)

app = mcp.streamable_http_app(
    json_response=True,
    stateless_http=True,
    host=cfg.host,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=bool(cfg.allowed_host),
        allowed_hosts=[cfg.allowed_host] if cfg.allowed_host else [],
    ),
)
```

`auth_kwargs` never returns a `token_verifier`: SDK 2.0 rejects being handed
both that and an `auth_server_provider`.

Calling the wrong helper for the installed SDK raises `SdkMismatch` naming the
right one.

## Per-tool group gating (optional, ships OFF)

```python
from fga_mcp_auth import GroupGate

gate = GroupGate(settings)

@mcp.tool()
@gate.require("MCP Teamtailor Users")
async def get_candidate(...): ...
```

With `MCP_TOOL_GATING` unset the decorator returns the function **unwrapped** —
no runtime cost and no behavior change. Turning it on takes two coordinated
steps, in this order:

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
| `MCP_BEARER_TOKEN` | no | Static service token for socialbot / curl / CI. Unset = no service path. **Must be `<MCP_SERVER_SLUG>.<random>`** — the server refuses to boot otherwise. |
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

For `fga-quorum-mcp` and `fga-ob3-mcp`, every name already matches; only
`MCP_SERVER_SLUG` is new — but `MCP_BEARER_TOKEN` still has to be **re-issued**
with the slug prefix on both, and every caller that holds it (socialbot,
scripts, CI) updated in the same window. The server will not start with an
unprefixed bearer.

Each server also needs its Okta redirect URI registered on the shared app:
`https://<app>.ondigitalocean.app/okta/callback`.

## Security notes

* **Give every server its own `MCP_TOKEN_SECRET`.** The `aud` claim is the
  structural backstop against replaying one server's token at another, not a
  licence to share one key across seven DO apps.
* **The service bearer is slug-bound at boot.** `MCP_BEARER_TOKEN` is an opaque
  string, not a JWT, so it cannot carry `aud` — and it grants *more* than a user
  token (never expires, unrestricted at the group gate). Requiring
  `<MCP_SERVER_SLUG>.<random>` is what stops one shared bearer from opening
  every server: the value teamtailor accepts cannot be a value congress also
  accepts. Use a distinct random half per server as well.
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
  page on our own origin — escaping stops XSS but not phishing.

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
the horizon.

### Deploying the retrofit costs one forced reconnect

`fga-quorum-mcp` and `fga-ob3-mcp` are live today and mint neither `aud` nor
`v`. Both are required, so **the first deploy that takes this package invalidates
every token those servers have already issued.** Every connected staff member is
prompted to reconnect the connector, at the moment the deploy lands.

It degrades cleanly rather than breaking: a legacy access token gets 401 +
`WWW-Authenticate`, a legacy refresh gets `invalid_grant`, and claude.ai turns
both into an inline Connect card and retries the tool call. The static
`MCP_BEARER_TOKEN` path — socialbot included — does not go through this and is
unaffected *provided its new slug-prefixed value is set in the same deploy*.

This is not behavior-identical, and no test can catch it (the statelessness
suite only proves same-version round-trips). Announce it, deploy it off-peak,
and expect the reconnect prompts.

## Release and pinning policy

* Consumers **pin the full commit SHA**, in a tarball URL, with a comment naming
  the version. Tags are for humans; the SHA is the pin.
* Tags are immutable by convention only. Never point a consumer at a branch.
* Bump one consumer at a time and deliberately. There is no fleet-wide upgrade
  button, on purpose: a regression in this package logs staff out of whichever
  servers took it.

## Test matrix

The suite must pass under both SDK lines:

```bash
uv run --isolated --group dev --group sdk1 pytest    # mcp>=1.26,<2
uv run --isolated --group dev --group sdk2 pytest    # mcp>=2
```

`tests/test_wiring_sdk1.py` and `tests/test_wiring_sdk2.py` self-skip on the
wrong leg; everything else runs on both.

## Changelog

### 1.0.0

Initial extraction from `fga-quorum-mcp` and `fga-ob3-mcp`. Behavior is the
safer of the two everywhere they differed, plus:

* **New — audience-bound tokens.** Every token carries `aud` (the server slug)
  and verification requires it. Previously the only cross-server boundary was
  `iss`.
* **New — token format version (`v`).** Unrecognized versions degrade to
  `invalid_grant` instead of an exception.
* **New — the service bearer is slug-bound.** `MCP_BEARER_TOKEN` must be
  `<MCP_SERVER_SLUG>.<random>` or the server refuses to boot, so one bearer
  cannot be shared across the fleet. **Both live servers need a re-issued value
  and their callers updated.**
* **Fixed — a refresh token that fails verification** (an expiry crossed between
  the SDK's check and ours) used to mint an anonymous, indefinitely renewable
  session. It is now `invalid_grant`.
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
