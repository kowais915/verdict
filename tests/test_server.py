"""Tests for the MCP server wiring (PILLAR 1 enforcement + endpoint behavior).

These do not launch an MCP transport; they exercise VerdictServer directly and
assert the exposed surface is read-only by construction. If the `mcp` SDK is
installed, a build-and-introspect test also confirms FastMCP registers exactly
the read-only tools.
"""

from __future__ import annotations

import pytest

from sift_mcp.config import load_config
from sift_mcp.provenance import JsonlLogger
from sift_mcp.server import (
    READONLY_TOOLS,
    VerdictServer,
    _assert_readonly_surface,
    build_server,
)


def _server(tmp_path):
    cfg = load_config(env_file=None, environ={"EVIDENCE_DIR": str(tmp_path)})
    log = JsonlLogger(tmp_path / "run.jsonl")
    return VerdictServer(config=cfg, logger=log)


# --------------------------------------------------------------------------- #
# PILLAR 1: read-only surface
# --------------------------------------------------------------------------- #
def test_no_destructive_or_shell_tool_is_exposed():
    for name in READONLY_TOOLS:
        low = name.lower()
        for bad in ("shell", "exec", "delete", "write", "remove", "system", "run_command"):
            assert bad not in low, f"{name} looks destructive"


def test_exposed_surface_is_the_expected_closed_set():
    assert set(READONLY_TOOLS) == {
        "get_prefetch",
        "get_mft_timeline",
        "get_amcache",
        "get_registry_run_keys",
        "parse_evtx",
        "evaluate_findings",
    }


def test_readonly_surface_guard_passes():
    _assert_readonly_surface()  # must not raise


def test_server_methods_match_declared_tools(tmp_path):
    srv = _server(tmp_path)
    for name in READONLY_TOOLS:
        assert callable(getattr(srv, name)), f"missing handler {name}"


# --------------------------------------------------------------------------- #
# Tool behavior (graceful degradation, no real binaries)
# --------------------------------------------------------------------------- #
def test_readonly_tools_return_serializable_unavailable(tmp_path):
    srv = _server(tmp_path)
    for name in ("get_prefetch", "get_mft_timeline", "get_amcache",
                 "get_registry_run_keys", "parse_evtx"):
        out = getattr(srv, name)()
        assert out["status"] == "unavailable"
        assert out["count"] == 0
        assert "provenance" in out


def test_parse_evtx_accepts_event_id_filter(tmp_path):
    out = _server(tmp_path).parse_evtx(event_ids=[4688])
    assert out["artifact"] == "evtx"  # still degrades gracefully


# --------------------------------------------------------------------------- #
# evaluate_findings endpoint (PILLAR 2 over the wire shape)
# --------------------------------------------------------------------------- #
def test_evaluate_findings_confirms_across_artifacts(tmp_path):
    srv = _server(tmp_path)
    artifacts = [
        {
            "provenance": {"record_id": "pf1"},
            "records": [{"source_artifact": "prefetch", "executable": "beacon.exe", "run_count": 2}],
        },
        {
            "provenance": {"record_id": "am1"},
            "records": [{"source_artifact": "amcache", "name": "beacon.exe", "sha1": "x"}],
        },
    ]
    result = srv.evaluate_findings(artifacts)
    assert result["total"] == 1
    assert result["summary"]["CONFIRMED"] == 1
    assert result["findings"][0]["verdict"] == "CONFIRMED"
    assert "evaluated_at" in result


def test_evaluate_findings_single_source_inferred(tmp_path):
    srv = _server(tmp_path)
    artifacts = [
        {"provenance": {"record_id": "pf1"},
         "records": [{"source_artifact": "prefetch", "executable": "lol.exe", "run_count": 1}]},
    ]
    result = srv.evaluate_findings(artifacts)
    assert result["summary"]["INFERRED"] == 1


def test_evaluate_findings_logs_verdicts(tmp_path):
    log = JsonlLogger(tmp_path / "run.jsonl")
    cfg = load_config(env_file=None, environ={"EVIDENCE_DIR": str(tmp_path)})
    srv = VerdictServer(config=cfg, logger=log)
    srv.evaluate_findings([
        {"provenance": {"record_id": "pf1"},
         "records": [{"source_artifact": "prefetch", "executable": "a.exe", "run_count": 1}]},
    ])
    events = [r.get("event") for r in log.read_all()]
    assert "finding_verdict" in events


def test_evaluate_findings_handles_empty_input(tmp_path):
    out = _server(tmp_path).evaluate_findings([])
    assert out["total"] == 0


# --------------------------------------------------------------------------- #
# FastMCP wiring (only if the mcp SDK is present)
# --------------------------------------------------------------------------- #
def test_build_server_registers_exactly_readonly_tools(tmp_path):
    pytest.importorskip("mcp")
    cfg = load_config(env_file=None, environ={"EVIDENCE_DIR": str(tmp_path)})
    mcp = build_server(cfg)
    # FastMCP exposes registered tools via its internal tool manager.
    import anyio

    tools = anyio.run(mcp.list_tools)
    names = {t.name for t in tools}
    assert names == set(READONLY_TOOLS)
    assert not any("shell" in n or "exec" in n for n in names)
