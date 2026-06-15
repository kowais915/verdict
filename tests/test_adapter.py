"""Deterministic tests for the read-only tool adapter (PILLAR 1 + PILLAR 3).

No real forensic binaries are needed: a logical tool is pointed at the Python
interpreter, which is used as a controllable stand-in process.
"""

from __future__ import annotations

import sys

import pytest

from sift_mcp.adapter import ALLOWED_TOOLS, AdapterError, run_readonly_tool
from sift_mcp.config import load_config
from sift_mcp.provenance import JsonlLogger, hash_payload, verify_record


def _cfg_with(logical_env: dict[str, str]):
    return load_config(env_file=None, environ=logical_env)


def test_no_generic_shell_tool_exists():
    # PILLAR 1: the allow-list contains only typed forensic tools, never a shell.
    assert "shell" not in ALLOWED_TOOLS
    assert "exec" not in ALLOWED_TOOLS
    assert "execute_shell" not in ALLOWED_TOOLS
    assert ALLOWED_TOOLS == {"mft", "prefetch", "amcache", "registry", "evtx", "fls", "mactime"}


def test_non_allowlisted_tool_is_refused():
    cfg = _cfg_with({})
    with pytest.raises(AdapterError):
        run_readonly_tool(cfg, "rm", ["-rf", "/"])


def test_unavailable_binary_degrades_gracefully():
    cfg = _cfg_with({"TOOL_PECMD": "definitely-not-real-xyz"})
    res = run_readonly_tool(cfg, "prefetch", ["-f", "x.pf"])
    assert res.status == "unavailable"
    assert res.ok is False
    assert res.returncode is None
    assert "not available" in (res.error or "")
    # A provenance record is still produced for the failed attempt.
    assert verify_record(res.provenance) is True


def test_successful_run_captures_and_hashes_output():
    cfg = _cfg_with({"TOOL_PECMD": sys.executable})
    res = run_readonly_tool(cfg, "prefetch", ["-c", "import sys; sys.stdout.write('HELLO')"])
    assert res.status == "ok"
    assert res.ok is True
    assert res.returncode == 0
    assert res.stdout == "HELLO"
    assert res.output_sha256 == hash_payload("HELLO")
    assert res.provenance.tool_name == "prefetch"
    # The configured binary is resolved to its canonical absolute path, which is
    # what appears in the command string / provenance record.
    assert res.binary is not None and res.command.startswith(res.binary)
    assert verify_record(res.provenance) is True


def test_nonzero_exit_reported_as_error():
    cfg = _cfg_with({"TOOL_PECMD": sys.executable})
    res = run_readonly_tool(cfg, "prefetch", ["-c", "import sys; sys.exit(3)"])
    assert res.status == "error"
    assert res.returncode == 3
    assert "exited with code 3" in (res.error or "")


def test_args_must_be_strings():
    cfg = _cfg_with({"TOOL_PECMD": sys.executable})
    with pytest.raises(AdapterError):
        run_readonly_tool(cfg, "prefetch", ["-c", 123])  # type: ignore[list-item]


def test_shell_metacharacters_in_args_are_inert():
    # argv list, shell=False -> metacharacters are literal data, not executed.
    cfg = _cfg_with({"TOOL_PECMD": sys.executable})
    payload = "; echo PWNED"
    res = run_readonly_tool(
        cfg, "prefetch", ["-c", f"import sys; sys.stdout.write({payload!r})"]
    )
    assert res.stdout == payload  # printed literally, nothing executed
    assert "PWNED" not in res.stderr


def test_logger_receives_provenance_record(tmp_path):
    cfg = _cfg_with({"TOOL_PECMD": sys.executable})
    log = JsonlLogger(tmp_path / "run.jsonl")
    res = run_readonly_tool(
        cfg,
        "prefetch",
        ["-c", "print('x')"],
        evidence_file="/cases/img.E01",
        finding_id="F-1",
        logger=log,
    )
    rows = log.read_all()
    assert len(rows) == 1
    assert rows[0]["tool_name"] == "prefetch"
    assert rows[0]["evidence_file"] == "/cases/img.E01"
    assert rows[0]["finding_id"] == "F-1"
    assert rows[0]["output_sha256"] == res.output_sha256
