"""get_amcache — Amcache.hve (program presence/execution) via AmcacheParser.

Amcache records metadata about executables that have been present/run on a
system, including full path, SHA-1 and a key last-write timestamp. It is an
independent corroborator for prefetch-derived execution claims. Wraps Eric
Zimmerman's ``AmcacheParser`` (logical tool ``amcache``).
"""

from __future__ import annotations

import os
from typing import Any

from ..config import Config
from ..provenance import JsonlLogger
from ._common import ArtifactResult, pick, read_csv_rows, run_csv_artifact

__all__ = ["parse_amcache_csv", "get_amcache"]


def parse_amcache_csv(text: str) -> list[dict[str, Any]]:
    """Normalize AmcacheParser CSV rows into program-presence records (pure)."""
    records: list[dict[str, Any]] = []
    for row in read_csv_rows(text):
        records.append(
            {
                "source_artifact": "amcache",
                "name": pick(row, "Name", "ApplicationName"),
                "full_path": pick(row, "FullPath", "Path"),
                "sha1": pick(row, "SHA1", "Sha1").lower(),
                "last_modified": pick(row, "FileKeyLastWriteTimestamp", "LastModified"),
                "product_name": pick(row, "ProductName"),
                "claim_type": "program_execution",
            }
        )
    return records


def get_amcache(
    config: Config,
    amcache_path: str | None = None,
    *,
    logger: JsonlLogger | None = None,
) -> ArtifactResult:
    """Run AmcacheParser over an ``Amcache.hve`` and return normalized records.

    ``amcache_path`` defaults to ``<EVIDENCE_DIR>/Amcache.hve`` if not given.
    AmcacheParser emits several CSVs; we read the largest (the file-entry table).
    """
    target = amcache_path or os.path.join(str(config.evidence_dir), "Amcache.hve")
    return run_csv_artifact(
        config,
        artifact="amcache",
        logical_tool="amcache",
        build_args=lambda out: ["-f", target, "--csv", out],
        parser=parse_amcache_csv,
        evidence_file=target,
        logger=logger,
    )
