"""parse_evtx — Windows Event Log parsing via EvtxECmd.

Event logs corroborate many claims: 4688 (process creation) supports execution,
7045 (service install) and 4624/4625 (logon) support persistence/access, etc.
Wraps Eric Zimmerman's ``EvtxECmd`` (logical tool ``evtx``) and normalizes its
CSV. An optional ``event_ids`` filter narrows the returned records.
"""

from __future__ import annotations

from typing import Any, Iterable

from ..config import Config
from ..provenance import JsonlLogger
from ._common import ArtifactResult, as_int, pick, read_csv_rows, run_csv_artifact

__all__ = ["parse_evtx_csv", "parse_evtx"]


def parse_evtx_csv(text: str, event_ids: Iterable[int] | None = None) -> list[dict[str, Any]]:
    """Normalize EvtxECmd CSV rows into event records (pure function).

    If ``event_ids`` is given, only matching events are returned.
    """
    wanted = {int(e) for e in event_ids} if event_ids is not None else None
    records: list[dict[str, Any]] = []
    for row in read_csv_rows(text):
        eid = as_int(pick(row, "EventId", "EventID"), default=None)
        if wanted is not None and eid not in wanted:
            continue
        records.append(
            {
                "source_artifact": "evtx",
                "event_id": eid,
                "time_created": pick(row, "TimeCreated"),
                "provider": pick(row, "Provider", "ProviderName"),
                "channel": pick(row, "Channel", "ChannelName"),
                "computer": pick(row, "Computer"),
                "description": pick(row, "MapDescription", "Description"),
                "record_number": as_int(pick(row, "RecordNumber", "EventRecordId"), default=None),
                "payload": pick(row, "Payload"),
                "claim_type": "event_log",
            }
        )
    return records


def parse_evtx(
    config: Config,
    evtx_path: str | None = None,
    *,
    event_ids: Iterable[int] | None = None,
    logger: JsonlLogger | None = None,
) -> ArtifactResult:
    """Run EvtxECmd over an ``.evtx`` file and return normalized event records.

    ``evtx_path`` defaults to ``<EVIDENCE_DIR>/Security.evtx``. ``event_ids``
    optionally filters the normalized output (filtering is applied after parsing
    so the provenance hash still covers the full tool output).
    """
    target = evtx_path or str(config.evidence_dir / "Security.evtx")
    return run_csv_artifact(
        config,
        artifact="evtx",
        logical_tool="evtx",
        build_args=lambda out: ["-f", target, "--csv", out, "--csvf", "evtx.csv"],
        parser=lambda raw: parse_evtx_csv(raw, event_ids=event_ids),
        evidence_file=target,
        logger=logger,
    )
