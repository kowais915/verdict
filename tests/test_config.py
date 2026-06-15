"""Deterministic tests for env config + tool-availability detection."""

from __future__ import annotations

import sys

from sift_mcp.config import (
    TOOL_ENV_MAP,
    check_tools,
    load_config,
    resolve_binary,
    startup_check,
)


def test_defaults_apply_with_empty_environ():
    cfg = load_config(env_file=None, environ={})
    assert cfg.max_iterations == 25
    assert str(cfg.log_dir) == "logs"
    assert cfg.tool_paths == {}  # no tool env vars set
    assert cfg.anthropic_api_key is None


def test_process_env_overrides_and_parses_tools():
    env = {
        "EVIDENCE_DIR": "/cases/x",
        "MAX_ITERATIONS": "7",
        "TOOL_PECMD": "PECmd.exe",
        "TOOL_FLS": "fls",
    }
    cfg = load_config(env_file=None, environ=env)
    assert str(cfg.evidence_dir) == "/cases/x"
    assert cfg.max_iterations == 7
    assert cfg.tool_paths == {"prefetch": "PECmd.exe", "fls": "fls"}


def test_max_iterations_invalid_falls_back_and_clamps():
    assert load_config(env_file=None, environ={"MAX_ITERATIONS": "abc"}).max_iterations == 25
    assert load_config(env_file=None, environ={"MAX_ITERATIONS": "0"}).max_iterations == 1
    assert load_config(env_file=None, environ={"MAX_ITERATIONS": "-5"}).max_iterations == 1


def test_no_model_name_concept_in_config():
    # Model-agnostic: a MODEL_NAME env var must have no effect.
    cfg = load_config(env_file=None, environ={"MODEL_NAME": "whatever"})
    assert not hasattr(cfg, "model_name")
    assert cfg.anthropic_model is None


def test_optional_llm_mode_detected_only_with_key():
    assert load_config(env_file=None, environ={}).llm_mode_available is False
    cfg = load_config(env_file=None, environ={"ANTHROPIC_API_KEY": "sk-test"})
    assert cfg.llm_mode_available is True


def test_env_file_loaded_and_overridden_by_process_env(tmp_path):
    f = tmp_path / ".env.local"
    f.write_text(
        "# comment\nEVIDENCE_DIR=/from/file\nexport MAX_ITERATIONS=9\nTOOL_PECMD='PECmd.exe'\n",
        encoding="utf-8",
    )
    # process env wins over file
    cfg = load_config(env_file=f, environ={"MAX_ITERATIONS": "3"})
    assert str(cfg.evidence_dir) == "/from/file"  # from file
    assert cfg.max_iterations == 3  # process env overrode file's 9
    assert cfg.tool_paths["prefetch"] == "PECmd.exe"  # quotes stripped


def test_resolve_binary_path_and_name_and_missing():
    assert resolve_binary(sys.executable) == sys.executable or resolve_binary(sys.executable)
    assert resolve_binary("definitely-not-a-real-binary-xyz") is None
    assert resolve_binary(None) is None


def test_check_tools_marks_available_and_missing():
    env = {"TOOL_PECMD": sys.executable, "TOOL_FLS": "definitely-not-real-xyz"}
    cfg = load_config(env_file=None, environ=env)
    statuses = check_tools(cfg)
    assert statuses["prefetch"].available is True
    assert statuses["prefetch"].resolved_path is not None
    assert statuses["fls"].available is False
    assert statuses["mft"].configured is None  # unset -> unavailable
    assert statuses["mft"].available is False


def test_startup_check_returns_statuses_and_writes_banner(capsys):
    cfg = load_config(env_file=None, environ={"TOOL_PECMD": sys.executable})
    statuses = startup_check(cfg)
    out = capsys.readouterr().err
    assert "startup capability check" in out
    assert "WARNING" in out  # most tools missing locally
    assert set(statuses) == set(TOOL_ENV_MAP)
