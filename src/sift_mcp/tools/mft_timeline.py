"""get_mft_timeline — NTFS $MFT filesystem timeline via MFTECmd.

The $MFT records every file's standard-information ($SI) and filename ($FN)
timestamps, plus path, size and allocation state. Wraps Eric Zimmerman's
``MFTECmd`` (logical tool ``mft``) and normalizes its CSV into timeline rows.
Useful for corroborating that a file referenced by another artifact actually
exists on disk and when it was created/modified.
"""

from __future__ import annotations

import os
from typing import Any

from ..config import Config
from ..provenance import JsonlLogger
from ._common import ArtifactResult, as_int, pick, read_csv_rows, run_csv_artifact

__all__ = ["parse_mft_csv", "get_mft_timeline"]


def parse_mft_csv(text: str) -> list[dict[str, Any]]:
    """Normalize MFTECmd CSV rows into filesystem timeline records (pure)."""
    records: list[dict[str, Any]] = []
    for row in read_csv_rows(text):
        parent = pick(row, "ParentPath")
        name = pick(row, "FileName", "Name")
        full_path = "\\".join(p for p in (parent.rstrip("\\"), name) if p) if (parent or name) else ""
        is_dir = pick(row, "IsDirectory").strip().lower() in ("true", "1", "yes")
        records.append(
            {
                "source_artifact": "mft",
                "path": full_path,
                "file_name": name,
                "is_directory": is_dir,
                "size": as_int(pick(row, "FileSize"), default=None),
                "entry_number": as_int(pick(row, "EntryNumber"), default=None),
                "in_use": pick(row, "InUse").strip().lower() in ("true", "1", "yes"),
                "created": pick(row, "Created0x10", "Created0x30"),
                "modified": pick(row, "LastModified0x10", "LastModified0x30"),
                "accessed": pick(row, "LastAccess0x10", "LastAccess0x30"),
                "mft_changed": pick(row, "LastRecordChange0x10", "LastRecordChange0x30"),
                "claim_type": "file_existence",
            }
        )
    return records


def get_mft_timeline(
    config: Config,
    mft_path: str | None = None,
    *,
    logger: JsonlLogger | None = None,
) -> ArtifactResult:
    """Run MFTECmd over a ``$MFT`` file and return normalized timeline rows.

    ``mft_path`` defaults to ``<EVIDENCE_DIR>/$MFT`` if not given.
    """
    target = mft_path or os.path.join(str(config.evidence_dir), "$MFT")
    return run_csv_artifact(
        config,
        artifact="mft",
        logical_tool="mft",
        build_args=lambda out: ["-f", target, "--csv", out, "--csvf", "mft.csv"],
        parser=parse_mft_csv,
        evidence_file=target,
        logger=logger,
    )
