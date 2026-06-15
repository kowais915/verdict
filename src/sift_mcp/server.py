"""MCP server entrypoint — registers typed, read-only forensic tools (PILLAR 1).

Architectural read-only enforcement
-----------------------------------
The server exposes a *fixed, closed* set of read-only forensic tools plus a
single ``evaluate_findings`` falsification endpoint. :data:`READONLY_TOOLS` is
the one source of truth for what is exposed, and :meth:`VerdictServer.register`
registers *only* those. There is deliberately:

* no ``execute_shell`` / ``run`` / generic-command tool,
* no write/delete/modify tool,
* no tool that takes an arbitrary command string.

Destructive operations are therefore impossible **by construction**, not by
instruction. A unit test asserts the exposed surface never grows a shell-like
tool.

The tool logic lives in plain methods on :class:`VerdictServer`, decoupled from
the MCP SDK so it can be unit-tested without launching a transport. The actual
FastMCP wiring is a thin, lazily-imported layer in :meth:`register` /
:func:`build_server`.
"""

from __future__ import annotations

from typing import Any

from .config import Config, load_config, startup_check
from .falsification import FalsificationEngine, build_claims_from_results
from .provenance import JsonlLogger, utc_now_iso
from .tools import (
    get_amcache,
    get_mft_timeline,
    get_prefetch,
    get_registry_run_keys,
    parse_evtx,
)

__all__ = ["READONLY_TOOLS", "VerdictServer", "build_server", "main"]

# The complete, closed set of exposed tools. Read-only by construction.
READONLY_TOOLS: tuple[str, ...] = (
    "get_prefetch",
    "get_mft_timeline",
    "get_amcache",
    "get_registry_run_keys",
    "parse_evtx",
    "evaluate_findings",
)

# Substrings that must never appear in an exposed tool name (defense in depth).
_FORBIDDEN_TOOL_SUBSTRINGS = ("shell", "exec", "delete", "write", "remove", "run_command", "system")


class _Prov:
    """Tiny provenance shim so dicts coming back from the agent can be fed to
    :func:`build_claims_from_results` (which expects ``.provenance.record_id``)."""

    def __init__(self, record_id: str | None):
        self.record_id = record_id


class _ArtifactShim:
    """Wrap an artifact dict as an object exposing ``.records`` / ``.provenance``."""

    def __init__(self, records: list[dict], provenance_id: str | None):
        self.records = records or []
        self.provenance = _Prov(provenance_id)


class VerdictServer:
    """Holds runtime config + logger and implements each read-only tool.

    Every method returns a JSON-serializable dict and never raises for runtime
    conditions (missing binaries degrade gracefully upstream).
    """

    def __init__(self, config: Config | None = None, logger: JsonlLogger | None = None):
        self.config = config or load_config()
        self.logger = logger or JsonlLogger(self.config.log_dir / "verdict_run.jsonl")
        self.engine = FalsificationEngine(logger=self.logger)

    # --- read-only forensic tools ----------------------------------------- #
    def get_prefetch(self, evidence_dir: str | None = None) -> dict[str, Any]:
        """Parse Windows Prefetch (program execution) and return normalized records."""
        return get_prefetch(self.config, evidence_dir, logger=self.logger).to_dict()

    def get_mft_timeline(self, mft_path: str | None = None) -> dict[str, Any]:
        """Parse the NTFS $MFT into a filesystem timeline of normalized records."""
        return get_mft_timeline(self.config, mft_path, logger=self.logger).to_dict()

    def get_amcache(self, amcache_path: str | None = None) -> dict[str, Any]:
        """Parse Amcache.hve (program presence/execution) into normalized records."""
        return get_amcache(self.config, amcache_path, logger=self.logger).to_dict()

    def get_registry_run_keys(self, hive_path: str | None = None) -> dict[str, Any]:
        """Parse registry autostart (Run/RunOnce) keys for persistence."""
        return get_registry_run_keys(self.config, hive_path, logger=self.logger).to_dict()

    def parse_evtx(
        self, evtx_path: str | None = None, event_ids: list[int] | None = None
    ) -> dict[str, Any]:
        """Parse a Windows .evtx event log; optionally filter by event id."""
        return parse_evtx(self.config, evtx_path, event_ids=event_ids, logger=self.logger).to_dict()

    # --- falsification endpoint (PILLAR 2) -------------------------------- #
    def evaluate_findings(self, artifacts: list[dict[str, Any]]) -> dict[str, Any]:
        """Falsify candidate findings from previously-collected artifact outputs.

        ``artifacts`` is a list of the dicts returned by the read-only tools
        above (each carrying ``records`` and a ``provenance`` block). The engine
        builds cross-artifact claims, computes a CONFIRMED/INFERRED/CONTRADICTED/
        RETRACTED verdict for each (>= 2 independent sources required to
        confirm), and logs every verdict and contradiction.
        """
        shims = []
        for a in artifacts or []:
            prov_id = None
            prov = a.get("provenance")
            if isinstance(prov, dict):
                prov_id = prov.get("record_id")
            prov_id = prov_id or a.get("provenance_id")
            shims.append(_ArtifactShim(a.get("records", []), prov_id))

        claims = build_claims_from_results(shims)
        result = self.engine.evaluate_all(claims)
        result["evaluated_at"] = utc_now_iso()
        return result

    # --- MCP wiring (thin) ------------------------------------------------- #
    def register(self, mcp: Any) -> Any:
        """Register exactly the read-only tools onto a FastMCP instance."""
        mcp.tool(name="get_prefetch")(self.get_prefetch)
        mcp.tool(name="get_mft_timeline")(self.get_mft_timeline)
        mcp.tool(name="get_amcache")(self.get_amcache)
        mcp.tool(name="get_registry_run_keys")(self.get_registry_run_keys)
        mcp.tool(name="parse_evtx")(self.parse_evtx)
        mcp.tool(name="evaluate_findings")(self.evaluate_findings)
        return mcp


def _assert_readonly_surface() -> None:
    """Guard: fail fast if the exposed surface ever gains a destructive tool."""
    for name in READONLY_TOOLS:
        low = name.lower()
        for bad in _FORBIDDEN_TOOL_SUBSTRINGS:
            if bad in low:
                raise RuntimeError(
                    f"Refusing to start: exposed tool {name!r} matches forbidden "
                    f"pattern {bad!r}. Verdict is read-only by construction."
                )


def build_server(config: Config | None = None):
    """Construct a FastMCP server with the read-only tools registered.

    FastMCP is imported lazily so this module imports cleanly even where the
    ``mcp`` SDK is not installed (e.g. running the unit tests).
    """
    _assert_readonly_surface()
    from mcp.server.fastmcp import FastMCP  # lazy import

    mcp = FastMCP("verdict-sift-mcp")
    VerdictServer(config=config).register(mcp)
    return mcp


def main() -> None:
    """Console-script entrypoint (`sift-mcp`). Prints a capability banner, then
    serves over stdio for Claude Code."""
    cfg = load_config()
    startup_check(cfg)
    build_server(cfg).run()


if __name__ == "__main__":
    main()
