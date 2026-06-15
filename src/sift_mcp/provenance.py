"""Cryptographic provenance + structured JSONL execution logging.

This module is part of Verdict's **novel contribution** (PILLAR 3: cryptographic
provenance). Every forensic tool output is SHA-256 hashed and every execution
produces a tamper-evident :class:`ProvenanceRecord` that ties a finding back to
the exact tool invocation that produced it.

Design goals
------------
* **Deterministic & testable** — hashing is canonical (sorted keys, compact
  separators) so the same logical payload always yields the same digest,
  regardless of dict ordering. No real evidence is required to test this module.
* **Content-addressed, tamper-evident** — each record's ``record_id`` is derived
  from a SHA-256 over the record's own contents. :func:`verify_record` recomputes
  it, so any later mutation of a logged record is detectable.
* **Traceability** — records carry tool name, exact underlying command, evidence
  file, offset/inode (where applicable), timestamp, token usage and finding id,
  which is exactly the JSONL schema the hackathon brief requires under
  deliverable #8 (agent execution logs).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__all__ = [
    "sha256_hex",
    "canonical_json",
    "hash_payload",
    "utc_now_iso",
    "ProvenanceRecord",
    "make_provenance",
    "verify_record",
    "JsonlLogger",
]

# The record_id is the first N hex chars of a SHA-256 digest over the record's
# canonical contents. 16 hex chars (64 bits) is ample to avoid collisions across
# a single triage run while staying readable in logs.
_RECORD_ID_LEN = 16


# --------------------------------------------------------------------------- #
# Hashing primitives
# --------------------------------------------------------------------------- #
def sha256_hex(data: str | bytes) -> str:
    """Return the hex SHA-256 of ``data`` (str is UTF-8 encoded)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    elif not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"sha256_hex expects str or bytes, got {type(data).__name__}")
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> str:
    """Serialize ``obj`` to a canonical JSON string.

    Keys are sorted and separators are compact so that two logically-equal
    payloads (e.g. dicts built in different orders) serialize identically and
    therefore hash identically. This is what makes provenance hashing
    reproducible and testable.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def hash_payload(payload: Any) -> str:
    """SHA-256 of an arbitrary tool output.

    * ``bytes`` are hashed directly (raw binary tool output).
    * ``str`` is hashed as UTF-8.
    * Anything else (dict/list/etc.) is canonicalized to JSON first.
    """
    if isinstance(payload, (bytes, bytearray)):
        return sha256_hex(bytes(payload))
    if isinstance(payload, str):
        return sha256_hex(payload)
    return sha256_hex(canonical_json(payload))


def utc_now_iso() -> str:
    """Current UTC time as a second-precision ISO-8601 string with ``Z`` suffix."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------------- #
# Provenance record
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ProvenanceRecord:
    """Tamper-evident record of a single read-only tool execution.

    ``record_id`` is derived from the record's contents (see
    :func:`make_provenance`); do not set it by hand. Use
    :func:`make_provenance` to construct records so the id and timestamp are
    filled consistently.
    """

    tool_name: str
    command: str
    output_sha256: str
    timestamp: str
    record_id: str
    evidence_file: str | None = None
    offset: int | None = None
    inode: str | None = None
    token_usage: dict[str, int] | None = None
    finding_id: str | None = None
    tool_version: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return canonical_json(self.to_dict())


def _record_fingerprint(d: dict[str, Any]) -> str:
    """Canonical SHA-256 over every field *except* record_id."""
    payload = {k: v for k, v in d.items() if k != "record_id"}
    return sha256_hex(canonical_json(payload))


def make_provenance(
    *,
    tool_name: str,
    command: str,
    output: Any = None,
    output_sha256: str | None = None,
    evidence_file: str | None = None,
    offset: int | None = None,
    inode: str | None = None,
    token_usage: dict[str, int] | None = None,
    finding_id: str | None = None,
    tool_version: str | None = None,
    timestamp: str | None = None,
    extra: dict[str, Any] | None = None,
) -> ProvenanceRecord:
    """Build a content-addressed :class:`ProvenanceRecord`.

    Supply either ``output`` (which will be hashed) or a precomputed
    ``output_sha256``. ``timestamp`` defaults to now (UTC); tests may pass an
    explicit value for full determinism.
    """
    if output_sha256 is None:
        if output is None:
            raise ValueError("make_provenance requires either 'output' or 'output_sha256'")
        output_sha256 = hash_payload(output)

    fields: dict[str, Any] = {
        "tool_name": tool_name,
        "command": command,
        "output_sha256": output_sha256,
        "timestamp": timestamp or utc_now_iso(),
        "evidence_file": evidence_file,
        "offset": offset,
        "inode": inode,
        "token_usage": token_usage,
        "finding_id": finding_id,
        "tool_version": tool_version,
        "extra": extra or {},
    }
    record_id = _record_fingerprint(fields)[:_RECORD_ID_LEN]
    return ProvenanceRecord(record_id=record_id, **fields)


def verify_record(record: ProvenanceRecord | dict[str, Any]) -> bool:
    """Return ``True`` iff ``record.record_id`` matches a freshly recomputed
    fingerprint of its contents (i.e. the record has not been tampered with).
    """
    d = record.to_dict() if isinstance(record, ProvenanceRecord) else dict(record)
    expected = _record_fingerprint(d)[:_RECORD_ID_LEN]
    return d.get("record_id") == expected


# --------------------------------------------------------------------------- #
# JSONL execution logger (deliverable #8)
# --------------------------------------------------------------------------- #
class JsonlLogger:
    """Append-only JSONL logger for agent/tool execution records.

    Each line is one JSON object. Provenance records are logged with their full
    schema (timestamp, tool, command, evidence ref, offset/inode, token usage,
    finding id) so the resulting ``.jsonl`` is the auditable execution log the
    brief requires. The file is opened append-only; existing history is never
    rewritten.
    """

    def __init__(self, log_path: str | os.PathLike[str]):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _append(self, obj: dict[str, Any]) -> dict[str, Any]:
        line = canonical_json(obj)
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        return obj

    def log_record(self, record: ProvenanceRecord) -> dict[str, Any]:
        """Append a provenance record as one JSONL line; returns what was written."""
        return self._append({"event": "tool_execution", **record.to_dict()})

    def log_event(self, event: str, **fields: Any) -> dict[str, Any]:
        """Append an arbitrary structured event (e.g. a finding verdict).

        A ``timestamp`` is added automatically if not supplied.
        """
        fields.setdefault("timestamp", utc_now_iso())
        return self._append({"event": event, **fields})

    def read_all(self) -> list[dict[str, Any]]:
        """Read back every logged line (convenience for tests/benchmarks)."""
        if not self.log_path.exists():
            return []
        with open(self.log_path, encoding="utf-8") as fh:
            return [json.loads(ln) for ln in fh if ln.strip()]
