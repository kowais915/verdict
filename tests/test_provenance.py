"""Deterministic unit tests for the cryptographic provenance core (PILLAR 3).

These tests require no real forensic evidence and no network/LLM access.
"""

from __future__ import annotations

import hashlib

import pytest

from sift_mcp.provenance import (
    JsonlLogger,
    ProvenanceRecord,
    canonical_json,
    hash_payload,
    make_provenance,
    sha256_hex,
    utc_now_iso,
    verify_record,
)

FIXED_TS = "2026-06-15T00:00:00Z"


# --------------------------------------------------------------------------- #
# Hashing primitives
# --------------------------------------------------------------------------- #
def test_sha256_matches_hashlib_for_str_and_bytes():
    assert sha256_hex("hello") == hashlib.sha256(b"hello").hexdigest()
    assert sha256_hex(b"hello") == hashlib.sha256(b"hello").hexdigest()


def test_sha256_str_and_equivalent_bytes_agree():
    assert sha256_hex("café") == sha256_hex("café".encode("utf-8"))


def test_sha256_rejects_bad_type():
    with pytest.raises(TypeError):
        sha256_hex(12345)  # type: ignore[arg-type]


def test_canonical_json_is_order_independent():
    a = {"b": 1, "a": 2, "c": [3, 2, 1]}
    b = {"c": [3, 2, 1], "a": 2, "b": 1}
    assert canonical_json(a) == canonical_json(b)


def test_hash_payload_order_independent_for_dicts():
    assert hash_payload({"x": 1, "y": 2}) == hash_payload({"y": 2, "x": 1})


def test_hash_payload_distinguishes_different_content():
    assert hash_payload({"x": 1}) != hash_payload({"x": 2})


def test_hash_payload_bytes_vs_canonical_str():
    # Raw bytes are hashed directly, not JSON-wrapped.
    assert hash_payload(b"abc") == sha256_hex(b"abc")
    assert hash_payload("abc") == sha256_hex("abc")


def test_utc_now_iso_has_z_suffix():
    assert utc_now_iso().endswith("Z")


# --------------------------------------------------------------------------- #
# Provenance records
# --------------------------------------------------------------------------- #
def test_make_provenance_hashes_output():
    rec = make_provenance(
        tool_name="get_prefetch",
        command="PECmd.exe -f CALC.EXE-XXXX.pf",
        output={"executable": "CALC.EXE", "run_count": 3},
        evidence_file="/cases/img.E01",
        timestamp=FIXED_TS,
    )
    assert rec.output_sha256 == hash_payload({"executable": "CALC.EXE", "run_count": 3})
    assert rec.tool_name == "get_prefetch"
    assert rec.timestamp == FIXED_TS


def test_record_id_is_deterministic_for_same_inputs():
    kw = dict(
        tool_name="get_amcache",
        command="AmcacheParser.exe -f amcache.hve",
        output={"a": 1},
        timestamp=FIXED_TS,
    )
    assert make_provenance(**kw).record_id == make_provenance(**kw).record_id


def test_record_id_changes_when_content_changes():
    base = dict(tool_name="t", command="c", timestamp=FIXED_TS)
    r1 = make_provenance(output={"a": 1}, **base)
    r2 = make_provenance(output={"a": 2}, **base)
    assert r1.record_id != r2.record_id


def test_make_provenance_accepts_precomputed_hash():
    digest = hash_payload({"k": "v"})
    rec = make_provenance(
        tool_name="t", command="c", output_sha256=digest, timestamp=FIXED_TS
    )
    assert rec.output_sha256 == digest


def test_make_provenance_requires_output_or_hash():
    with pytest.raises(ValueError):
        make_provenance(tool_name="t", command="c", timestamp=FIXED_TS)


def test_verify_record_true_for_untampered():
    rec = make_provenance(tool_name="t", command="c", output={"a": 1}, timestamp=FIXED_TS)
    assert verify_record(rec) is True


def test_verify_record_detects_tampering():
    rec = make_provenance(tool_name="t", command="c", output={"a": 1}, timestamp=FIXED_TS)
    tampered = rec.to_dict()
    tampered["output_sha256"] = "0" * 64  # attacker swaps the evidence hash
    assert verify_record(tampered) is False


def test_record_roundtrips_through_dict_and_json():
    rec = make_provenance(
        tool_name="parse_evtx",
        command="EvtxECmd.exe -f Security.evtx",
        output=[{"event_id": 4624}],
        offset=4096,
        inode="64-128-1",
        token_usage={"input": 10, "output": 5},
        finding_id="F-001",
        timestamp=FIXED_TS,
    )
    d = rec.to_dict()
    assert d["offset"] == 4096 and d["inode"] == "64-128-1"
    assert d["finding_id"] == "F-001"
    # Reconstruct and confirm integrity survives the round trip.
    assert verify_record(ProvenanceRecord(**d)) is True


# --------------------------------------------------------------------------- #
# JSONL logger (deliverable #8)
# --------------------------------------------------------------------------- #
def test_logger_appends_one_line_per_record(tmp_path):
    log = JsonlLogger(tmp_path / "sub" / "run.jsonl")  # parent auto-created
    r1 = make_provenance(tool_name="t1", command="c1", output={"a": 1}, timestamp=FIXED_TS)
    r2 = make_provenance(tool_name="t2", command="c2", output={"a": 2}, timestamp=FIXED_TS)
    log.log_record(r1)
    log.log_record(r2)
    rows = log.read_all()
    assert len(rows) == 2
    assert rows[0]["tool_name"] == "t1" and rows[0]["event"] == "tool_execution"
    assert rows[1]["output_sha256"] == r2.output_sha256


def test_logger_is_append_only_across_instances(tmp_path):
    path = tmp_path / "run.jsonl"
    JsonlLogger(path).log_record(
        make_provenance(tool_name="t", command="c", output={"a": 1}, timestamp=FIXED_TS)
    )
    JsonlLogger(path).log_event("finding_verdict", finding_id="F-1", verdict="INFERRED")
    rows = JsonlLogger(path).read_all()
    assert len(rows) == 2
    assert rows[1]["event"] == "finding_verdict"
    assert rows[1]["verdict"] == "INFERRED"
    assert "timestamp" in rows[1]  # auto-added


def test_logged_record_fields_match_deliverable_schema(tmp_path):
    log = JsonlLogger(tmp_path / "run.jsonl")
    rec = make_provenance(
        tool_name="get_mft_timeline",
        command="MFTECmd.exe -f $MFT",
        output={"rows": 10},
        evidence_file="/cases/img.E01",
        token_usage={"input": 1, "output": 2},
        finding_id="F-42",
        timestamp=FIXED_TS,
    )
    written = log.log_record(rec)
    for required in ("timestamp", "tool_name", "command", "evidence_file", "token_usage", "finding_id"):
        assert required in written
