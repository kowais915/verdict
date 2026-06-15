"""Shared scaffolding for the read-only forensic tool wrappers.

Each wrapper normalizes a forensic tool's CSV output into typed records and
returns an :class:`ArtifactResult` carrying a provenance record over the actual
artifact output (PILLAR 3). The CSV-parsing logic lives in pure ``parse_*``
functions per module so it is deterministically unit-testable without any real
evidence or installed binary.

The Eric-Zimmerman family (PECmd/MFTECmd/AmcacheParser/RECmd/EvtxECmd) writes
CSV into an output directory; the live runner therefore points the tool at a
temp dir, reads the resulting CSV back, and hashes that content for provenance.
"""

from __future__ import annotations

import csv
import io
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..adapter import run_readonly_tool
from ..config import Config
from ..provenance import JsonlLogger, ProvenanceRecord, make_provenance

__all__ = [
    "ArtifactResult",
    "read_csv_rows",
    "pick",
    "as_int",
    "run_csv_artifact",
]


@dataclass(frozen=True)
class ArtifactResult:
    """Normalized, provenance-bearing result of one forensic artifact query."""

    artifact: str  # logical artifact type, e.g. "prefetch"
    status: str  # "ok" | "unavailable" | "error"
    records: list[dict[str, Any]]
    count: int
    output_sha256: str
    provenance: ProvenanceRecord
    evidence_file: str | None = None
    error: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact,
            "status": self.status,
            "count": self.count,
            "records": self.records,
            "evidence_file": self.evidence_file,
            "output_sha256": self.output_sha256,
            "error": self.error,
            "provenance": self.provenance.to_dict(),
            **({"extra": self.extra} if self.extra else {}),
        }


# --------------------------------------------------------------------------- #
# CSV parsing helpers (pure)
# --------------------------------------------------------------------------- #
def read_csv_rows(text: str) -> list[dict[str, str]]:
    """Parse CSV text into a list of row dicts. Empty/whitespace -> []."""
    if not text or not text.strip():
        return []
    reader = csv.DictReader(io.StringIO(text))
    return [{(k or "").strip(): (v or "") for k, v in row.items()} for row in reader]


def pick(row: dict[str, str], *candidates: str, default: str = "") -> str:
    """Return the first present, non-empty value among candidate column names.

    Tolerant of tool-version column renames: tries each candidate in order.
    """
    for name in candidates:
        if name in row and row[name] != "":
            return row[name]
    return default


def as_int(value: str, default: int | None = None) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


# --------------------------------------------------------------------------- #
# Live runner (executes the binary via the allow-listed adapter)
# --------------------------------------------------------------------------- #
def run_csv_artifact(
    config: Config,
    *,
    artifact: str,
    logical_tool: str,
    build_args: Callable[[str], list[str]],
    parser: Callable[[str], list[dict[str, Any]]],
    evidence_file: str | None,
    logger: JsonlLogger | None = None,
    pick_csv: Callable[[list[Path]], Path | None] | None = None,
    timeout: int = 300,
) -> ArtifactResult:
    """Execute a CSV-producing forensic tool and return a normalized result.

    * ``build_args(out_dir)`` -> argv for the tool, writing CSV into ``out_dir``.
    * ``parser(csv_text)`` -> normalized record dicts.
    * ``pick_csv(csv_paths)`` selects which CSV to read when a tool emits several
      (defaults to the largest file).

    A missing binary returns ``status='unavailable'``; any execution/parse
    problem returns ``status='error'``. Never raises for runtime conditions.
    """

    def _finalize(status: str, records: list[dict], raw: str, command: str,
                  error: str | None) -> ArtifactResult:
        prov = make_provenance(
            tool_name=artifact,
            command=command,
            output=raw if raw else (error or ""),
            evidence_file=evidence_file,
            extra={"status": status, "record_count": len(records)},
        )
        if logger is not None:
            logger.log_record(prov)
        return ArtifactResult(
            artifact=artifact,
            status=status,
            records=records,
            count=len(records),
            output_sha256=prov.output_sha256,
            provenance=prov,
            evidence_file=evidence_file,
            error=error,
        )

    with tempfile.TemporaryDirectory(prefix="verdict_") as td:
        args = build_args(td)
        exec_res = run_readonly_tool(
            config, logical_tool, args, evidence_file=evidence_file, timeout=timeout
        )
        if exec_res.status == "unavailable":
            return _finalize("unavailable", [], "", exec_res.command, exec_res.error)
        if exec_res.status == "error":
            return _finalize("error", [], exec_res.stderr, exec_res.command, exec_res.error)

        csv_paths = sorted(Path(td).glob("**/*.csv"))
        if not csv_paths:
            return _finalize(
                "error", [], exec_res.stdout, exec_res.command,
                error=f"{artifact}: tool produced no CSV output",
            )
        chosen = (pick_csv or _largest)(csv_paths)
        if chosen is None:
            return _finalize("error", [], "", exec_res.command,
                             error=f"{artifact}: no usable CSV among {len(csv_paths)} files")
        try:
            raw = chosen.read_text(encoding="utf-8", errors="replace")
            records = parser(raw)
        except Exception as exc:  # parsing must never crash the agent
            return _finalize("error", [], "", exec_res.command,
                             error=f"{artifact}: failed to parse CSV: {exc}")
        return _finalize("ok", records, raw, exec_res.command, None)


def _largest(paths: list[Path]) -> Path | None:
    return max(paths, key=lambda p: p.stat().st_size, default=None) if paths else None
