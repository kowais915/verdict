"""Tests for the benchmark harness + naive baseline (deliverable #6).

Runs the real harness over the committed ground-truth scenario into temp output
paths and asserts the headline guarantees hold: Verdict has higher precision and
fewer false positives than the naive baseline, and the report is generated.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "benchmark"))

import harness  # noqa: E402
from baseline import naive_evaluate_all  # noqa: E402

from sift_mcp.config import load_config  # noqa: E402
from sift_mcp.falsification import Claim, Evidence  # noqa: E402


def _run(tmp_path):
    cfg = load_config(env_file=None, environ={})
    return harness.run_benchmark(
        docs_out=tmp_path / "accuracy_report.md",
        samples_logs=tmp_path / "run.jsonl",
        samples_output=tmp_path / "triage.md",
        config=cfg,
    )


def test_report_and_samples_are_generated(tmp_path):
    res = _run(tmp_path)
    assert (tmp_path / "accuracy_report.md").exists()
    assert (tmp_path / "run.jsonl").exists()
    assert (tmp_path / "triage.md").exists()
    assert "Accuracy Report" in (tmp_path / "accuracy_report.md").read_text()


def test_verdict_beats_baseline_on_precision_and_fp(tmp_path):
    res = _run(tmp_path)
    agg = harness._aggregate(res["scenarios"])
    assert agg["engine"]["precision"] >= agg["baseline"]["precision"]
    assert agg["engine"]["fp"] <= agg["baseline"]["fp"]
    # Headline guarantee for the bundled scenario: zero false positives.
    assert agg["engine"]["fp"] == 0
    assert agg["baseline"]["fp"] > 0


def test_engine_surfaces_a_contradiction(tmp_path):
    res = _run(tmp_path)
    breakdown = res["scenarios"][0]["breakdown"]
    assert breakdown["CONTRADICTED"] >= 1


def test_detection_recall_at_least_confirmed_recall(tmp_path):
    res = _run(tmp_path)
    s = res["scenarios"][0]
    assert s["engine_detection_metrics"]["recall"] >= s["engine_metrics"]["recall"]


def test_sample_log_contains_execution_and_verdict_events(tmp_path):
    _run(tmp_path)
    lines = [l for l in (tmp_path / "run.jsonl").read_text().splitlines() if l.strip()]
    events = {__import__("json").loads(l)["event"] for l in lines}
    assert "tool_execution" in events
    assert "finding_verdict" in events
    assert "contradiction" in events


def test_naive_baseline_confirms_on_single_source():
    claim = Claim(
        claim_id="program_execution:x",
        claim_type="program_execution",
        subject="x",
        statement="x",
        evidence=[Evidence(source_artifact="prefetch", supports=True)],
    )
    out = naive_evaluate_all([claim])
    assert out["findings"][0]["verdict"] == "CONFIRMED"  # overconfident by design


def test_naive_baseline_unsupported_when_no_evidence():
    claim = Claim(claim_id="t:x", claim_type="t", subject="x", statement="x", evidence=[])
    assert naive_evaluate_all([claim])["findings"][0]["verdict"] == "UNSUPPORTED"
