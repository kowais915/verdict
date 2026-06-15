"""get_prefetch — Windows Prefetch (program execution) via PECmd.

Prefetch (.pf) files are strong evidence of program *execution*: each carries an
executable name, a run count, and up to 8 recent run timestamps. Wraps Eric
Zimmerman's ``PECmd`` (logical tool ``prefetch``) and normalizes its CSV.
"""

from __future__ import annotations

from typing import Any

from ..config import Config
from ..provenance import JsonlLogger
from ._common import ArtifactResult, as_int, pick, read_csv_rows, run_csv_artifact

__all__ = ["parse_prefetch_csv", "get_prefetch"]

_RUN_COLS = [f"PreviousRun{i}" for i in range(7)]


def parse_prefetch_csv(text: str) -> list[dict[str, Any]]:
    """Normalize PECmd CSV rows into prefetch execution records (pure function)."""
    records: list[dict[str, Any]] = []
    for row in read_csv_rows(text):
        last_run = pick(row, "LastRun")
        previous = [row[c] for c in _RUN_COLS if row.get(c)]
        all_runs = [t for t in [last_run, *previous] if t]
        records.append(
            {
                "source_artifact": "prefetch",
                "executable": pick(row, "ExecutableName", "Executable"),
                "source_file": pick(row, "SourceFilename", "SourceFile"),
                "run_count": as_int(pick(row, "RunCount"), default=None),
                "last_run": last_run,
                "all_run_times": all_runs,
                "claim_type": "program_execution",
            }
        )
    return records


def get_prefetch(
    config: Config,
    evidence_dir: str | None = None,
    *,
    logger: JsonlLogger | None = None,
) -> ArtifactResult:
    """Run PECmd over a prefetch directory and return normalized records.

    ``evidence_dir`` defaults to ``<EVIDENCE_DIR>/prefetch`` if not given.
    """
    target = evidence_dir or str(config.evidence_dir / "prefetch")
    return run_csv_artifact(
        config,
        artifact="prefetch",
        logical_tool="prefetch",
        build_args=lambda out: ["-d", target, "--csv", out, "--csvf", "prefetch.csv"],
        parser=parse_prefetch_csv,
        evidence_file=target,
        logger=logger,
    )
