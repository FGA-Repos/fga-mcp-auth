"""Canonical configuration for every FGA MCP server's auth layer.

These env var names are defined HERE, not per repo. Divergent config names are
the same drift disease this package exists to kill, so consumers adopt these
rather than keeping their own. fga-quorum-mcp and fga-ob3-mcp already use all of
them except MCP_SERVER_SLUG; the five password-era servers get a rename table in
their migration PR.

Every field is Optional at load time so stdio / local development never needs
any of them. The HTTP wiring helpers call `require_http_complete()` before
building anything, which raises ONE error naming every missing variable: a
server that boots with SSO silently disabled is worse than one that refuses to
start.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# Required before an HTTP (public) deployment may boot. Order is the order they
# are reported in, which is the order they appear in the README's env table.
REQUIRED_FOR_HTTP = (
    "MCP_ALLOWED_HOST",
    "MCP_SERVER_SLUG",
    "MCP_TOKEN_SECRET",
    "OKTA_ISSUER",
    "OKTA_CLIENT_ID",
    "OKTA_CLIENT_SECRET",
)


def _csv_set(raw: object) -> object:
    """CSV -> frozenset. Env vars are strings; a set passed in code stays as-is."""
    if raw is None:
        return frozenset()
    if isinstance(raw, str):
        return frozenset(x.strip() for x in raw.split(",") if x.strip())
    return frozenset(raw)


class OktaConfig:
    """Read-only view of the Okta half of Settings.

    Kept as a distinct object because `check_authorized` and the OIDC client
    need exactly these four values and nothing else — and because `.enabled`
    (all three of issuer/id/secret present) is the local-dev gate that decides
    whether interactive login exists at all. In production
    `require_http_complete()` makes a half-set Okta fatal long before this
    matters.
    """

    __slots__ = ("issuer", "client_id", "client_secret", "allowed_groups", "allowed_email_domains")

    def __init__(
        self,
        *,
        issuer: str | None,
        client_id: str | None,
        client_secret: str | None,
        allowed_groups: frozenset[str] = frozenset(),
        allowed_email_domains: frozenset[str] = frozenset(),
    ) -> None:
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret
        self.allowed_groups = allowed_groups
        self.allowed_email_domains = allowed_email_domains

    @property
    def enabled(self) -> bool:
        return bool(self.issuer and self.client_id and self.client_secret)

    @property
    def discovery_url(self) -> str:
        """Endpoints are NOT constructed from the issuer — they are read from the
        issuer's OIDC discovery document, because Okta's org and custom
        authorization servers put them in different places:

            org AS      https://example.okta.com
                        -> https://example.okta.com/oauth2/v1/authorize
            custom AS   https://example.okta.com/oauth2/default
                        -> https://example.okta.com/oauth2/default/v1/authorize

        FGA is on the org AS (API Access Management is not licensed, verified
        2026-07-29). Discovery means licensing it later is a change to
        OKTA_ISSUER and nothing else.
        """
        return f"{str(self.issuer).rstrip('/')}/.well-known/openid-configuration"


class Settings(BaseSettings):
    """Auth configuration, read from the environment."""

    model_config = SettingsConfigDict(
        populate_by_name=True,
        case_sensitive=False,
        extra="ignore",
    )

    # Public host this server answers on. Basis of `public_base_url`, which
    # becomes the JWT `iss` claim AND the DNS-rebinding allowlist.
    allowed_host: str | None = Field(default=None, validation_alias="MCP_ALLOWED_HOST")

    # Canonical server identity, e.g. "fga-quorum". Becomes the `aud` claim on
    # every minted token and the `server` field on every audit record — one var,
    # both jobs. Required, because it is the only structural barrier to replaying
    # one server's token at another if an admin reuses a signing secret.
    server_slug: str | None = Field(default=None, validation_alias="MCP_SERVER_SLUG")

    # HS256 signing key. >=32 bytes is enforced at provider construction
    # (RFC 7518 §3.2). Use a DISTINCT value per server; `aud` is the backstop,
    # not the excuse.
    token_secret: SecretStr | None = Field(default=None, validation_alias="MCP_TOKEN_SECRET")

    # Static service token for socialbot, curl and CI. Optional: unset means the
    # service path simply does not exist. It is never a bypass of anything.
    #
    # SHOULD be `<MCP_SERVER_SLUG>.<random>`. The bearer is an opaque string with
    # no claims to check, so a slug prefix is the service path's only audience
    # binding — without it, one value pasted across all seven DO apps replays at
    # every one of them (a leaked congress bearer opening teamtailor's PII
    # tools). An unprefixed value logs a loud warning at boot and keeps working;
    # MCP_REQUIRE_BOUND_BEARER=true turns that warning into a refusal to boot.
    bearer_token: SecretStr | None = Field(default=None, validation_alias="MCP_BEARER_TOKEN")

    # Enforce the slug prefix above. Default OFF in v1.0.0 on purpose: quorum and
    # ob3 are LIVE with unprefixed bearers, and socialbot holds those values, so
    # a hard requirement would make the retrofit deploy a three-place credential
    # rotation (DO env, socialbot config, scripts) with a socialbot outage in the
    # gap. Flip it on per server once the bearer has been re-issued — that is a
    # deliberate operational step, not something this package decides for the
    # fleet. FLAGGED FOR JACOB: fleet-wide default-on is the end state.
    require_bound_bearer: bool = Field(default=False, validation_alias="MCP_REQUIRE_BOUND_BEARER")

    # Transition switch for the retrofit of the two LIVE servers. Tokens minted
    # before this package carry neither `aud` nor `v`, both of which are normally
    # required, so the first deploy invalidates every session at once and every
    # connected staff member gets a reconnect card. With this set, a token
    # missing those claims is accepted as format v1 for as long as it is on —
    # a silent cutover instead of a synchronized reconnect.
    #
    # The cost, stated plainly: a legacy token has no `aud`, so while this is on
    # the cross-server replay barrier is off FOR LEGACY TOKENS ONLY (modern
    # tokens are still audience-checked, and a wrong `aud` is still rejected).
    # Turn it on for the deploy, turn it off within the 7-day refresh window —
    # by then every live session has been re-minted with both claims.
    accept_legacy_tokens: bool = Field(default=False, validation_alias="MCP_ACCEPT_LEGACY_TOKENS")

    okta_issuer: str | None = Field(default=None, validation_alias="OKTA_ISSUER")
    okta_client_id: str | None = Field(default=None, validation_alias="OKTA_CLIENT_ID")
    okta_client_secret: SecretStr | None = Field(
        default=None, validation_alias="OKTA_CLIENT_SECRET"
    )

    # Server-wide login gate, enforced once at /okta/callback. Empty = any
    # authenticated Okta user. Non-empty + a token with no `groups` claim = DENY
    # (fail-closed): treating an absent claim as "no restriction" would turn a
    # misconfigured Okta app into an open door. The shared FGA Okta app emits no
    # groups claim today, so setting this before adding the claim is a total
    # outage — add the claim first.
    allowed_groups: Annotated[frozenset[str], NoDecode] = Field(
        default=frozenset(), validation_alias="OKTA_ALLOWED_GROUPS"
    )
    # Second server-wide login gate, checked beside groups. Empty = inert.
    allowed_email_domains: Annotated[frozenset[str], NoDecode] = Field(
        default=frozenset(), validation_alias="OKTA_ALLOWED_EMAIL_DOMAINS"
    )

    # Master switch for per-tool GroupGate. Ships OFF, and must stay off until
    # the Okta app emits a groups claim.
    tool_gating_enabled: bool = Field(default=False, validation_alias="MCP_TOOL_GATING")

    # Read, not owned: the consumer's own config still decides what uvicorn binds.
    # Used only to build a coherent issuer in local dev when MCP_ALLOWED_HOST is
    # unset — which never happens in production, because it is boot-required.
    local_port: int = Field(default=8080, validation_alias="MCP_PORT")

    @field_validator("allowed_groups", "allowed_email_domains", mode="before")
    @classmethod
    def _parse_csv(cls, raw: object) -> object:
        return _csv_set(raw)

    @field_validator("allowed_email_domains", mode="after")
    @classmethod
    def _lower_domains(cls, value: frozenset[str]) -> frozenset[str]:
        return frozenset(d.lower().lstrip("@") for d in value)

    # --- derived ------------------------------------------------------------

    @property
    def public_base_url(self) -> str:
        if self.allowed_host:
            return f"https://{self.allowed_host}"
        return f"http://localhost:{self.local_port}"

    @property
    def issuer(self) -> str:
        return self.public_base_url.rstrip("/")

    @property
    def audience(self) -> str:
        """The `aud` claim. Boot-required in HTTP mode; the empty string here is
        only reachable in stdio/dev, where no tokens are minted anyway."""
        return self.server_slug or ""

    @property
    def okta(self) -> OktaConfig:
        return OktaConfig(
            issuer=self.okta_issuer,
            client_id=self.okta_client_id,
            client_secret=(
                self.okta_client_secret.get_secret_value() if self.okta_client_secret else None
            ),
            allowed_groups=self.allowed_groups,
            allowed_email_domains=self.allowed_email_domains,
        )

    def secret_value(self) -> str | None:
        return self.token_secret.get_secret_value() if self.token_secret else None

    def service_token_value(self) -> str | None:
        return self.bearer_token.get_secret_value() if self.bearer_token else None

    # --- boot guard ---------------------------------------------------------

    def missing_for_http(self) -> list[str]:
        present = {
            "MCP_ALLOWED_HOST": self.allowed_host,
            "MCP_SERVER_SLUG": self.server_slug,
            "MCP_TOKEN_SECRET": self.secret_value(),
            "OKTA_ISSUER": self.okta_issuer,
            "OKTA_CLIENT_ID": self.okta_client_id,
            "OKTA_CLIENT_SECRET": (
                self.okta_client_secret.get_secret_value() if self.okta_client_secret else None
            ),
        }
        return [name for name in REQUIRED_FOR_HTTP if not present[name]]

    def require_http_complete(self) -> None:
        """Refuse to boot half-configured. Names every missing var at once."""
        missing = self.missing_for_http()
        if missing:
            raise RuntimeError(
                f"Missing required env vars for an HTTP MCP deployment: {', '.join(missing)}. "
                "Okta SSO and stateless tokens cannot run without them. Generate "
                'MCP_TOKEN_SECRET with: python3 -c "import secrets; print(secrets.token_urlsafe(48))"'
            )
