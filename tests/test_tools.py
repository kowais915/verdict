"""Deterministic tests for the forensic tool wrappers.

Two layers are tested without any real evidence or installed binary:
  1. The pure ``parse_*_csv`` normalizers, against synthetic CSV.
  2. Graceful degradation of the live ``get_*`` runners when a binary is absent.
"""

from __future__ import annotations

from sift_mcp.config import load_config
from sift_mcp.provenance import JsonlLogger, verify_record
from sift_mcp.tools import (
    RUN_KEY_PATHS,
    get_amcache,
    get_mft_timeline,
    get_prefetch,
    get_registry_run_keys,
    parse_amcache_csv,
    parse_evtx,
    parse_evtx_csv,
    parse_mft_csv,
    parse_prefetch_csv,
    parse_run_keys_csv,
)


# --------------------------------------------------------------------------- #
# Pure parsers
# --------------------------------------------------------------------------- #
def test_parse_prefetch_csv_normalizes_execution():
    csv = (
        "SourceFilename,ExecutableName,RunCount,LastRun,PreviousRun0,PreviousRun1\n"
        "CALC.EXE-9A.pf,CALC.EXE,3,2026-06-01 10:00:00,2026-05-31 09:00:00,\n"
    )
    rows = parse_prefetch_csv(csv)
    assert len(rows) == 1
    r = rows[0]
    assert r["executable"] == "CALC.EXE"
    assert r["run_count"] == 3
    assert r["last_run"] == "2026-06-01 10:00:00"
    assert r["all_run_times"] == ["2026-06-01 10:00:00", "2026-05-31 09:00:00"]
    assert r["claim_type"] == "program_execution"
    assert r["source_artifact"] == "prefetch"


def test_parse_prefetch_empty_and_blank():
    assert parse_prefetch_csv("") == []
    assert parse_prefetch_csv("   \n  ") == []


def test_parse_mft_csv_builds_path_and_flags():
    csv = (
        "EntryNumber,ParentPath,FileName,IsDirectory,FileSize,InUse,"
        "Created0x10,LastModified0x10,LastAccess0x10,LastRecordChange0x10\n"
        "42,.\\Users\\evil,beacon.exe,False,8192,True,"
        "2026-06-01 08:00:00,2026-06-01 08:05:00,2026-06-01 09:00:00,2026-06-01 08:06:00\n"
    )
    rows = parse_mft_csv(csv)
    r = rows[0]
    assert r["file_name"] == "beacon.exe"
    assert r["path"].endswith("evil\\beacon.exe")
    assert r["is_directory"] is False
    assert r["in_use"] is True
    assert r["size"] == 8192
    assert r["entry_number"] == 42
    assert r["created"] == "2026-06-01 08:00:00"
    assert r["claim_type"] == "file_existence"


def test_parse_amcache_csv_normalizes_and_lowercases_sha1():
    csv = (
        "Name,FullPath,SHA1,FileKeyLastWriteTimestamp,ProductName\n"
        "beacon.exe,C:\\Users\\evil\\beacon.exe,ABCDEF0123,2026-06-01 08:10:00,Evil\n"
    )
    r = parse_amcache_csv(csv)[0]
    assert r["name"] == "beacon.exe"
    assert r["sha1"] == "abcdef0123"
    assert r["last_modified"] == "2026-06-01 08:10:00"
    assert r["claim_type"] == "program_execution"


def test_parse_run_keys_csv_normalizes_persistence():
    csv = (
        "HiveType,KeyPath,ValueName,ValueData,LastWriteTimestamp\n"
        "SOFTWARE,Software\\Microsoft\\Windows\\CurrentVersion\\Run,Updater,"
        "C:\\Users\\evil\\beacon.exe,2026-06-01 08:20:00\n"
    )
    r = parse_run_keys_csv(csv)[0]
    assert r["value_name"] == "Updater"
    assert r["value_data"].endswith("beacon.exe")
    assert r["last_write"] == "2026-06-01 08:20:00"
    assert r["claim_type"] == "persistence"


def test_run_key_paths_documented():
    assert any("CurrentVersion\\Run" in p for p in RUN_KEY_PATHS)


def test_parse_evtx_csv_and_event_id_filter():
    csv = (
        "RecordNumber,TimeCreated,EventId,Provider,Channel,Computer,MapDescription,Payload\n"
        "1,2026-06-01 08:00:00,4688,Microsoft-Windows-Security-Auditing,Security,HOST,"
        "Process Created,{}\n"
        "2,2026-06-01 08:01:00,4624,Microsoft-Windows-Security-Auditing,Security,HOST,Logon,{}\n"
    )
    allrows = parse_evtx_csv(csv)
    assert len(allrows) == 2
    only_4688 = parse_evtx_csv(csv, event_ids=[4688])
    assert len(only_4688) == 1
    assert only_4688[0]["event_id"] == 4688
    assert only_4688[0]["description"] == "Process Created"
    assert only_4688[0]["claim_type"] == "event_log"


def test_parsers_tolerate_renamed_columns():
    # 'Executable' instead of 'ExecutableName', 'EventID' instead of 'EventId'.
    assert parse_prefetch_csv("Executable,RunCount\nX.EXE,1\n")[0]["executable"] == "X.EXE"
    assert parse_evtx_csv("EventID,TimeCreated\n4688,t\n")[0]["event_id"] == 4688


# --------------------------------------------------------------------------- #
# Graceful degradation of live runners (no binaries present)
# --------------------------------------------------------------------------- #
def _empty_cfg(tmp_path):
    # No TOOL_* vars -> every binary unavailable.
    return load_config(env_file=None, environ={"EVIDENCE_DIR": str(tmp_path)})


def test_all_runners_degrade_to_unavailable(tmp_path):
    cfg = _empty_cfg(tmp_path)
    for fn in (get_prefetch, get_mft_timeline, get_amcache, get_registry_run_keys, parse_evtx):
        res = fn(cfg)
        assert res.status == "unavailable", fn.__name__
        assert res.count == 0
        assert res.records == []
        assert res.error and "not available" in res.error
        # Provenance still produced and intact for the failed attempt.
        assert verify_record(res.provenance) is True
        assert res.provenance.output_sha256 == res.output_sha256


def test_runner_logs_artifact_record(tmp_path):
    cfg = _empty_cfg(tmp_path)
    log = JsonlLogger(tmp_path / "run.jsonl")
    get_prefetch(cfg, logger=log)
    rows = log.read_all()
    assert len(rows) == 1
    assert rows[0]["tool_name"] == "prefetch"
    assert rows[0]["event"] == "tool_execution"


def test_artifact_result_to_dict_shape(tmp_path):
    res = get_amcache(_empty_cfg(tmp_path))
    d = res.to_dict()
    for key in ("artifact", "status", "count", "records", "output_sha256", "provenance"):
        assert key in d
    assert d["artifact"] == "amcache"
