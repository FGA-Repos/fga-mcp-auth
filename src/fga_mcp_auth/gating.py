"""Per-tool Okta group gating.

    gate = GroupGate(settings)

    @mcp.tool()
    @gate.require("MCP Teamtailor Users")
    async def get_candidate(...): ...

SHIPS DEFAULT-OFF (`MCP_TOOL_GATING` unset). The shared FGA Okta OIDC app emits
no `groups` claim today, so a gate that actually enforced would deny everyone.
Turning it on is two coordinated changes: add the groups claim to the Okta app,
then set MCP_TOOL_GATING=true on the server. Do them in that order.

This is authorization — it denies the call. It is deliberately not folded into
any server's response redaction, which is data shaping and a separate concern.
"""

from __future__ import annotations

import functools
import logging
from collections.abc import Callable
from typing import Any, TypeVar

from ._compat import tool_error_class
from .constants import SERVICE_CLIENT_ID
from .settings import Settings

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


def current_access_token() -> Any:
    """The authenticated principal for this call, or None.

    `mcp.server.auth.middleware.auth_context` exists in both SDK lines, but the
    contextvar is only populated on the HTTP path — on stdio there is no auth at
    all, which is why a gated server must not be run over stdio with gating on.
    """
    try:
        from mcp.server.auth.middleware.auth_context import get_access_token

        return get_access_token()
    except Exception:  # pragma: no cover - import guard for exotic SDK builds
        return None


class GroupGate:
    """Wraps tools so only members of an Okta group may call them."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.enabled = settings.tool_gating_enabled

    def require(self, *groups: str) -> Callable[[F], F]:
        """Decorator: allow the call only for a member of one of `groups`.

        With gating disabled the function is returned UNWRAPPED — no runtime
        cost, no behavior change, and nothing to reason about on the servers
        that have not opted in.
        """
        if not groups:
            raise ValueError("GroupGate.require() needs at least one group name")

        def decorate(func: F) -> F:
            if not self.enabled:
                return func

            @functools.wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                self._check(func.__name__, groups)
                return await func(*args, **kwargs)

            return wrapper  # type: ignore[return-value]

        return decorate

    def _check(self, tool_name: str, groups: tuple[str, ...]) -> None:
        token = current_access_token()
        if token is None:
            # Fail closed. No principal (stdio, or an unauthenticated path that
            # should never have reached a tool) means no access.
            self._deny(tool_name, groups, "no authenticated caller")

        client_id = getattr(token, "client_id", None)
        if client_id == SERVICE_CLIENT_ID:
            # Parity with today: the static service token (socialbot, scripts)
            # has unrestricted access. Documented in the README — narrowing it
            # is a deliberate future change, not a side effect of gating.
            return

        held = getattr(token, "groups", None)
        if isinstance(held, list) and set(groups).intersection(held):
            return
        self._deny(tool_name, groups, "caller is not in a permitted group")

    def _deny(self, tool_name: str, groups: tuple[str, ...], why: str) -> None:
        wanted = " or ".join(sorted(groups))
        logger.warning(
            "Tool call denied by group gate",
            extra={
                "tool": tool_name,
                "required_groups": wanted,
                "reason": why,
                "server": self.settings.audience,
                "event_category": "auth.tool.denied",
            },
        )
        raise tool_error_class()(
            f"Access to {tool_name} requires membership of the Okta group {wanted}. "
            "Ask #it-help to be added."
        )
