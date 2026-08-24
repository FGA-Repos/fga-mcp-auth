"""Canonical config: parsing, derived values, and the fail-loud boot guard.

Q1/Q2. The env var names live in the package, and a half-configured HTTP
deployment must refuse to start rather than boot with SSO silently disabled.
"""

from __future__ import annotations

import pytest
from conftest import HOST, OKTA_ISSUER, REQUIRED_ENV, SECRET, make_settings

from fga_mcp_auth import FGAAuthProvider, Settings
from fga_mcp_auth.settings import REQUIRED_FOR_HTTP, OktaConfig


class TestConfig:
    def test_allowed_groups_defaults_to_empty(self):
        assert Settings().allowed_groups == frozenset()

    def test_allowed_groups_parses_csv(self, monkeypatch):
        monkeypatch.setenv("OKTA_ALLOWED_GROUPS", " A , B ,, C ")
        assert Settings().allowed_groups == frozenset({"A", "B", "C"})

    def test_allowed_email_domains_parses_csv_and_lowercases(self, monkeypatch):
        monkeypatch.setenv("OKTA_ALLOWED_EMAIL_DOMAINS", "Example.ORG, @other.example ")
        assert Settings().allowed_email_domains == frozenset({"example.org", "other.example"})

    def test_env_vars_populate_every_field(self, monkeypatch):
        for name, value in REQUIRED_ENV.items():
            monkeypatch.setenv(name, value)
        monkeypatch.setenv("MCP_BEARER_TOKEN", "svc")
        monkeypatch.setenv("MCP_TOOL_GATING", "true")
        settings = Settings()
        assert settings.allowed_host == HOST
        assert settings.server_slug == "fga-quorum"
        assert settings.secret_value() == SECRET
        assert settings.service_token_value() == "svc"
        assert settings.okta_issuer == OKTA_ISSUER
        assert settings.tool_gating_enabled is True

    def test_okta_enabled_needs_all_three(self):
        assert make_settings().okta.enabled
        assert not OktaConfig(issuer=OKTA_ISSUER, client_id="c", client_secret=None).enabled
        assert not OktaConfig(issuer=None, client_id="c", client_secret="s").enabled
        assert not make_settings(okta=False).okta.enabled

    def test_discovery_url_shape(self):
        assert (
            make_settings().okta.discovery_url
            == "https://example.okta.com/.well-known/openid-configuration"
        )
        # a trailing slash on OKTA_ISSUER must not produce a double slash
        assert (
            OktaConfig(
                issuer="https://example.okta.com/", client_id="c", client_secret="s"
            ).discovery_url
            == "https://example.okta.com/.well-known/openid-configuration"
        )

    def test_public_base_url_prefers_allowed_host(self):
        assert make_settings().public_base_url == f"https://{HOST}"

    def test_unset_allowed_host_falls_back_to_a_non_unique_issuer(self):
        """Kept as documentation of WHY MCP_ALLOWED_HOST is boot-required: the
        fallback is the same string on every FGA MCP server. `aud` is now the
        second boundary, but the guard is still the first."""
        fallback = make_settings(host=None)
        assert fallback.public_base_url == "http://localhost:8080"
        assert "quorum" not in fallback.public_base_url

    def test_the_two_operational_switches_default_off(self):
        """Both change how a LIVE server behaves at deploy time, so neither may
        be inherited: MCP_REQUIRE_BOUND_BEARER would break socialbot's bearer,
        MCP_ACCEPT_LEGACY_TOKENS would relax a claim check. Opt in, per server,
        per deploy."""
        settings = Settings()
        assert settings.require_bound_bearer is False
        assert settings.accept_legacy_tokens is False

    def test_the_two_operational_switches_read_their_env_vars(self, monkeypatch):
        monkeypatch.setenv("MCP_REQUIRE_BOUND_BEARER", "true")
        monkeypatch.setenv("MCP_ACCEPT_LEGACY_TOKENS", "true")
        settings = Settings()
        assert settings.require_bound_bearer is True
        assert settings.accept_legacy_tokens is True

    def test_secrets_are_not_repr_leaked(self):
        """SecretStr, so a config dump in a log or an exception can't spill it."""
        assert SECRET not in repr(make_settings())
        assert "okta-client-secret" not in repr(make_settings())


class TestSecretStrength:
    @pytest.mark.parametrize("secret", ["", "short", "a" * 31])
    def test_weak_secret_refuses_to_start(self, secret):
        """A brute-forceable HS256 key means forgeable tokens (RFC 7518 §3.2)."""
        with pytest.raises(ValueError, match="at least 32 bytes"):
            FGAAuthProvider(make_settings(secret=secret))

    def test_adequate_secret_accepted(self):
        assert FGAAuthProvider(make_settings(secret="b" * 32)) is not None


class TestHttpBootGuard:
    """D6/Q2. fga-quorum-mcp refuses to boot half-configured; fga-ob3-mcp would
    boot with Okta silently disabled. The package takes quorum's side, in both
    wiring helpers — a deliberate behavior change to ob3."""

    def test_a_complete_config_passes(self, monkeypatch):
        for name, value in REQUIRED_ENV.items():
            monkeypatch.setenv(name, value)
        Settings().require_http_complete()

    @pytest.mark.parametrize("var", list(REQUIRED_ENV))
    def test_each_missing_var_refuses_to_start(self, monkeypatch, var):
        for name, value in REQUIRED_ENV.items():
            if name != var:
                monkeypatch.setenv(name, value)
        with pytest.raises(RuntimeError, match=var):
            Settings().require_http_complete()

    def test_all_missing_vars_are_named_at_once(self):
        with pytest.raises(RuntimeError) as exc:
            Settings().require_http_complete()
        for var in REQUIRED_FOR_HTTP:
            assert var in str(exc.value)

    def test_server_slug_is_required(self, monkeypatch):
        """New in the package: MCP_SERVER_SLUG is the `aud` claim, so an empty
        one would re-open cross-server replay. Boot-required, not defaulted."""
        for name, value in REQUIRED_ENV.items():
            if name != "MCP_SERVER_SLUG":
                monkeypatch.setenv(name, value)
        assert Settings().missing_for_http() == ["MCP_SERVER_SLUG"]

    def test_guard_error_does_not_echo_secret_values(self, monkeypatch):
        monkeypatch.setenv("MCP_TOKEN_SECRET", SECRET)
        with pytest.raises(RuntimeError) as exc:
            Settings().require_http_complete()
        assert SECRET not in str(exc.value)
