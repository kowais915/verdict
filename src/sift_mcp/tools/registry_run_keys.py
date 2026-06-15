"""get_registry_run_keys — registry autostart (persistence) via RECmd.

Run/RunOnce keys are a classic persistence mechanism. Wraps Eric Zimmerman's
``RECmd`` (logical tool ``registry``) driven by a batch file that targets the
canonical autostart locations, and normalizes its CSV. The set of inspected
keys is documented in :data:`RUN_KEY_PATHS`.
"""

from __future__ import annotations

from typing import Any

from ..config import Config
from ..provenance import JsonlLogger
from ._common import ArtifactResult, pick, read_csv_rows, run_csv_artifact

__all__ = ["RUN_KEY_PATHS", "parse_run_keys_csv", "get_registry_run_keys"]

# Canonical autostart locations inspected for persistence claims.
RUN_KEY_PATHS: tuple[str, ...] = (
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
)


def parse_run_keys_csv(text: str) -> list[dict[str, Any]]:
    """Normalize RECmd CSV rows into autostart/persistence records (pure)."""
    records: list[dict[str, Any]] = []
    for row in read_csv_rows(text):
        records.append(
            {
                "source_artifact": "registry_run_keys",
                "hive": pick(row, "HiveType", "HivePath"),
                "key_path": pick(row, "KeyPath"),
                "value_name": pick(row, "ValueName"),
                "value_data": pick(row, "ValueData"),
                "last_write": pick(row, "LastWriteTimestamp", "LastWrite"),
                "claim_type": "persistence",
            }
        )
    return records


def get_registry_run_keys(
    config: Config,
    hive_path: str | None = None,
    *,
    batch_file: str | None = None,
    logger: JsonlLogger | None = None,
) -> ArtifactResult:
    """Run RECmd over a registry hive and return normalized autostart records.

    ``hive_path`` defaults to ``<EVIDENCE_DIR>/SOFTWARE``. ``batch_file`` is the
    RECmd batch describing which keys to extract; if unset, RECmd's bundled
    ``RunKeys`` batch is referenced by name (resolvable on SIFT).
    """
    target = hive_path or str(config.evidence_dir / "SOFTWARE")
    batch = batch_file or "BatchExamples/RECmd_RunKeys.reb"
    return run_csv_artifact(
        config,
        artifact="registry_run_keys",
        logical_tool="registry",
        build_args=lambda out: ["-f", target, "--bn", batch, "--csv", out, "--nl", "false"],
        parser=parse_run_keys_csv,
        evidence_file=target,
        logger=logger,
    )
