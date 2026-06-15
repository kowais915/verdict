"""Generic read-only tool adapter (PILLAR 1 enforcement point).

The adapter is the *only* place in Verdict that ever spawns a subprocess. It is
deliberately narrow:

* It runs **only allow-listed logical tools** (the keys of
  :data:`sift_mcp.config.TOOL_ENV_MAP`). There is no path by which an arbitrary
  command can be executed — there is no shell, no ``shell=True``, and no
  generic "run this string" entry point. Destructive operations are impossible
  *by construction*, not by instruction.
* Arguments are always passed as an argv **list** (never a shell string), so
  shell metacharacters in arguments are inert.
* Every invocation captures stdout, SHA-256 hashes it, and produces a
  :class:`~sift_mcp.provenance.ProvenanceRecord` (PILLAR 3).
* A missing/unresolvable binary yields a structured ``unavailable`` result
  instead of crashing the agent (graceful degradation).
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from typing import Any, Sequence

from .config import Config, TOOL_ENV_MAP, resolve_binary
from .provenance import JsonlLogger, ProvenanceRecord, make_provenance

__all__ = ["ToolResult", "AdapterError", "run_readonly_tool"]

# The allow-list IS the set of logical tools we expose. Anything not here is
# rejected before a process is ever spawned.
ALLOWED_TOOLS: frozenset[str] = frozenset(TOOL_ENV_MAP)

_DEFAULT_TIMEOUT = 120  # seconds; bounds any single tool call


class AdapterError(Exception):
    """Raised for programmer errors (e.g. a non-allow-listed logical name).

    Note: runtime conditions like a missing binary are NOT errors — they are
    returned as a structured :class:`ToolResult` with ``status='unavailable'``.
    """


@dataclass(frozen=True)
class ToolResult:
    """Structured result of one read-only tool invocation."""

    tool_name: str  # logical name
    binary: str | None  # resolved absolute path (None if unavailable)
    command: str  # exact command string, for the provenance record
    status: str  # "ok" | "unavailable" | "error"
    returncode: int | None
    stdout: str
    stderr: str
    output_sha256: str
    provenance: ProvenanceRecord
    error: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def to_dict(self) -> dict[str, Any]:
        d = {
            "tool_name": self.tool_name,
            "binary": self.binary,
            "command": self.command,
            "status": self.status,
            "returncode": self.returncode,
            "output_sha256": self.output_sha256,
            "error": self.error,
            "provenance": self.provenance.to_dict(),
        }
        if self.extra:
            d["extra"] = self.extra
        return d


def _command_string(binary: str, args: Sequence[str]) -> str:
    return " ".join([binary, *args])


def run_readonly_tool(
    config: Config,
    logical_name: str,
    args: Sequence[str] | None = None,
    *,
    evidence_file: str | None = None,
    offset: int | None = None,
    inode: str | None = None,
    finding_id: str | None = None,
    timeout: int = _DEFAULT_TIMEOUT,
    logger: JsonlLogger | None = None,
) -> ToolResult:
    """Run an allow-listed forensic binary read-only and return a structured result.

    Parameters mirror the provenance schema so the resulting record is fully
    traceable. If ``logger`` is given, the provenance record is appended to the
    JSONL execution log.

    Raises :class:`AdapterError` only for an unknown/non-allow-listed
    ``logical_name`` (a programming error). All runtime conditions (missing
    binary, non-zero exit, timeout) are reported via :class:`ToolResult`.
    """
    if logical_name not in ALLOWED_TOOLS:
        raise AdapterError(
            f"Refusing to run non-allow-listed tool {logical_name!r}. "
            f"Allowed: {sorted(ALLOWED_TOOLS)}"
        )

    args = list(args or [])
    if any(not isinstance(a, str) for a in args):
        raise AdapterError("All tool arguments must be strings (argv list, never a shell string).")

    configured = config.tool_paths.get(logical_name)
    binary = resolve_binary(configured)

    def _result(status, returncode, stdout, stderr, error=None) -> ToolResult:
        display = binary or configured or logical_name
        command = _command_string(display, args)
        prov = make_provenance(
            tool_name=logical_name,
            command=command,
            output=stdout if status == "ok" else (error or ""),
            evidence_file=evidence_file,
            offset=offset,
            inode=inode,
            finding_id=finding_id,
            tool_version=None,
            extra={"status": status, "returncode": returncode},
        )
        if logger is not None:
            logger.log_record(prov)
        return ToolResult(
            tool_name=logical_name,
            binary=binary,
            command=command,
            status=status,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            output_sha256=prov.output_sha256,
            provenance=prov,
            error=error,
        )

    if binary is None:
        return _result(
            "unavailable",
            None,
            "",
            "",
            error=(
                f"Tool {logical_name!r} is not available on this host "
                f"(configured={configured!r}). Set {TOOL_ENV_MAP[logical_name]}."
            ),
        )

    try:
        proc = subprocess.run(
            [binary, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,  # explicit: NEVER use a shell
            check=False,
        )
    except subprocess.TimeoutExpired:
        return _result("error", None, "", "", error=f"Tool {logical_name!r} timed out after {timeout}s")
    except OSError as exc:
        return _result("error", None, "", "", error=f"Failed to execute {logical_name!r}: {exc}")

    status = "ok" if proc.returncode == 0 else "error"
    error = None if status == "ok" else f"{logical_name!r} exited with code {proc.returncode}"
    return _result(status, proc.returncode, proc.stdout, proc.stderr, error=error)
