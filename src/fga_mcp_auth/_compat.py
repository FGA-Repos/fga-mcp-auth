"""MCP SDK major-version detection and the few version-gated imports.

Most of what this package touches is at the SAME import path in mcp 1.26+ and
mcp 2.x — `mcp.server.auth.provider`, `mcp.server.auth.settings`,
`mcp.shared.auth`, `mcp.server.transport_security`,
`mcp.server.auth.middleware.auth_context`. Those are imported directly.

What differs is the *server object*: 1.x has `mcp.server.fastmcp.FastMCP` and
takes auth via private attributes; 2.0 has `mcp.server.MCPServer` and takes it
via constructor kwargs. Each wiring helper does its SDK-touching imports inside
the function body, after the gate below, so `import fga_mcp_auth` works under
either pin and the core test suite never trips on whichever SDK is absent.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version


class SdkMismatch(RuntimeError):
    """Wiring helper called against the wrong MCP SDK major version."""


def sdk_version() -> str:
    try:
        return version("mcp")
    except PackageNotFoundError:  # pragma: no cover - mcp is a hard dependency
        return "0"


def sdk_major() -> int:
    raw = sdk_version().split(".", 1)[0]
    try:
        return int(raw)
    except ValueError:  # pragma: no cover - non-numeric prerelease epoch
        return 0


def require_sdk1() -> None:
    if sdk_major() >= 2:
        raise SdkMismatch(
            f"wire_sdk1() needs the MCP SDK 1.x line (found mcp {sdk_version()}). "
            "On SDK 2.0 use fga_mcp_auth.auth_kwargs() + register_auth_routes() instead."
        )


def require_sdk2() -> None:
    if sdk_major() < 2:
        raise SdkMismatch(
            f"auth_kwargs()/register_auth_routes() need the MCP SDK 2.x line "
            f"(found mcp {sdk_version()}). On SDK 1.x use fga_mcp_auth.wire_sdk1() instead."
        )


def tool_error_class() -> type[Exception]:
    """The SDK's tool-layer error, whose message reaches the caller as a tool error.

    Moved between SDK lines (`mcp.server.fastmcp.exceptions` ->
    `mcp.server.mcpserver.exceptions`), so resolve it lazily and fall back to a
    plain exception rather than making group gating unimportable.
    """
    for module, name in (
        ("mcp.server.mcpserver.exceptions", "ToolError"),
        ("mcp.server.fastmcp.exceptions", "ToolError"),
    ):
        try:
            mod = __import__(module, fromlist=[name])
            return getattr(mod, name)
        except (ImportError, AttributeError):  # pragma: no cover - one path always hits
            continue
    return RuntimeError  # pragma: no cover - both SDK lines define one
