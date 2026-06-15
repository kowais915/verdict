"""Environment configuration + startup tool-availability detection.

Loads configuration from the environment (optionally seeded by a ``.env.local``
file) and resolves the swappable forensic-tool binaries. Tool *binary names*
vary across SIFT versions, so every logical tool maps to an env var that can be
re-pointed without code changes (PILLAR 1 supporting infrastructure).

The Verdict server is **model-agnostic**: no model name lives here. The agent
model is selected inside Claude Code. An optional ``ANTHROPIC_API_KEY`` /
``ANTHROPIC_MODEL`` pair exists solely for an opt-in live-LLM benchmark mode and
is unused on the default path.
"""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, TextIO

__all__ = [
    "TOOL_ENV_MAP",
    "Config",
    "ToolStatus",
    "load_config",
    "resolve_binary",
    "check_tools",
    "startup_check",
]

# Logical tool name -> environment variable holding its binary path/name.
# Logical names are the *only* identifiers the rest of the codebase uses, so the
# actual binary is fully swappable per SIFT version.
TOOL_ENV_MAP: dict[str, str] = {
    "mft": "TOOL_MFTECMD",
    "prefetch": "TOOL_PECMD",
    "amcache": "TOOL_AMCACHEPARSER",
    "registry": "TOOL_RECMD",
    "evtx": "TOOL_EVTXECMD",
    "fls": "TOOL_FLS",
    "mactime": "TOOL_MACTIME",
}

_DEFAULTS = {
    "EVIDENCE_DIR": "./evidence",
    "LOG_DIR": "./logs",
    "MAX_ITERATIONS": "25",
}


@dataclass(frozen=True)
class Config:
    """Resolved runtime configuration."""

    evidence_dir: Path
    log_dir: Path
    max_iterations: int
    tool_paths: dict[str, str] = field(default_factory=dict)  # logical -> configured binary
    anthropic_api_key: str | None = None  # OPTIONAL, benchmark-only
    anthropic_model: str | None = None  # OPTIONAL, benchmark-only

    @property
    def llm_mode_available(self) -> bool:
        """True only if the opt-in live-LLM benchmark mode is fully configured."""
        return bool(self.anthropic_api_key)


@dataclass(frozen=True)
class ToolStatus:
    """Availability of a single logical forensic tool."""

    logical: str
    configured: str | None  # what the env var said (may be None if unset)
    resolved_path: str | None  # absolute path if found, else None
    available: bool


# --------------------------------------------------------------------------- #
# .env file loading
# --------------------------------------------------------------------------- #
def _parse_env_file(path: Path) -> dict[str, str]:
    """Minimal ``KEY=VALUE`` parser (fallback when python-dotenv is absent).

    Honors ``#`` comments, blank lines, optional ``export`` prefix, and single/
    double quoted values. Never raises on a malformed line — it is skipped, in
    keeping with the project's graceful-degradation rule.
    """
    out: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return out
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export ") :]
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("#").strip()  # drop trailing inline comments cheaply
        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            value = value[1:-1]
        if key:
            out[key] = value
    return out


def _load_env_file(path: Path) -> dict[str, str]:
    """Prefer python-dotenv if installed; otherwise fall back to the parser."""
    try:
        from dotenv import dotenv_values  # type: ignore

        return {k: v for k, v in dotenv_values(str(path)).items() if v is not None}
    except Exception:
        return _parse_env_file(path)


def _to_int(value: str, default: int, minimum: int = 1) -> int:
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return max(minimum, n)


def load_config(
    env_file: str | os.PathLike[str] | None = ".env.local",
    environ: Mapping[str, str] | None = None,
) -> Config:
    """Build a :class:`Config`.

    Precedence (highest wins): process environment > ``env_file`` values >
    built-in defaults. Pass ``environ`` explicitly (e.g. ``{}``) for hermetic
    tests; pass ``env_file=None`` to skip file loading.
    """
    environ = os.environ if environ is None else environ

    merged: dict[str, str] = dict(_DEFAULTS)
    if env_file is not None:
        p = Path(env_file)
        if p.exists():
            merged.update(_load_env_file(p))
    merged.update({k: v for k, v in environ.items() if v is not None})

    tool_paths = {
        logical: merged[env_var]
        for logical, env_var in TOOL_ENV_MAP.items()
        if merged.get(env_var)
    }

    return Config(
        evidence_dir=Path(merged["EVIDENCE_DIR"]).expanduser(),
        log_dir=Path(merged["LOG_DIR"]).expanduser(),
        max_iterations=_to_int(merged["MAX_ITERATIONS"], default=25),
        tool_paths=tool_paths,
        anthropic_api_key=merged.get("ANTHROPIC_API_KEY") or None,
        anthropic_model=merged.get("ANTHROPIC_MODEL") or None,
    )


# --------------------------------------------------------------------------- #
# Tool-availability detection
# --------------------------------------------------------------------------- #
def resolve_binary(binary: str | None) -> str | None:
    """Resolve a configured binary to an absolute path, or None if not found.

    Accepts an explicit path (file must exist) or a bare name resolved on PATH.
    """
    if not binary:
        return None
    p = Path(binary).expanduser()
    if p.exists() and p.is_file():
        return str(p.resolve())
    found = shutil.which(binary)
    return found


def check_tools(config: Config) -> dict[str, ToolStatus]:
    """Return availability status for every logical tool."""
    statuses: dict[str, ToolStatus] = {}
    for logical in TOOL_ENV_MAP:
        configured = config.tool_paths.get(logical)
        resolved = resolve_binary(configured)
        statuses[logical] = ToolStatus(
            logical=logical,
            configured=configured,
            resolved_path=resolved,
            available=resolved is not None,
        )
    return statuses


def startup_check(config: Config, stream: TextIO | None = None) -> dict[str, ToolStatus]:
    """Print a human-readable availability banner and return the statuses.

    Missing tools produce a clear warning but never abort startup — the matching
    wrappers degrade to structured 'unavailable' results at call time.
    """
    stream = stream if stream is not None else sys.stderr
    statuses = check_tools(config)
    available = [s.logical for s in statuses.values() if s.available]
    missing = [s.logical for s in statuses.values() if not s.available]

    print("Verdict MCP — startup capability check", file=stream)
    print(f"  evidence_dir   : {config.evidence_dir}", file=stream)
    print(f"  log_dir        : {config.log_dir}", file=stream)
    print(f"  max_iterations : {config.max_iterations}", file=stream)
    print(f"  available tools: {', '.join(available) or '(none)'}", file=stream)
    if missing:
        print(f"  WARNING: unavailable tools (will degrade gracefully): {', '.join(missing)}",
              file=stream)
        for logical in missing:
            env_var = TOOL_ENV_MAP[logical]
            print(f"    - {logical}: set {env_var} to a valid binary on this host", file=stream)
    if config.llm_mode_available:
        print("  optional live-LLM benchmark mode: CONFIGURED", file=stream)
    return statuses
