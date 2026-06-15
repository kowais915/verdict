"""Thorough deterministic tests for the falsification engine (PILLAR 2).

All synthetic — no real evidence. These tests lock in the headline behavior:
CONFIRMED requires >= 2 independent sources; verdicts are computed, not asserted;
contradictions are surfaced and logged.
"""

from __future__ import annotations

from sift_mcp.falsification import (
    DEFAULT_MATRIX,
    Claim,
    Evidence,
    FalsificationEngine,
    Verdict,
    build_claims_from_results,
    evaluate_claim,
    normalize_subject,
)
from sift_mcp.provenance import JsonlLogger, make_provenance


def _ev(artifact, supports=True, detail=""):
    return Evidence(source_artifact=artifact, supports=supports, detail=detail, provenance_id="p1")


def _claim(evidence, claim_type="program_execution", subject="beacon.exe"):
    return Claim(
        claim_id=f"{claim_type}:{subject}",
        claim_type=claim_type,
        subject=subject,
        statement="x",
        evidence=evidence,
    )


# --------------------------------------------------------------------------- #
# Core verdict computation
# --------------------------------------------------------------------------- #
def test_two_independent_sources_confirm():
    f = evaluate_claim(_claim([_ev("prefetch"), _ev("amcache")]))
    assert f.verdict is Verdict.CONFIRMED
    assert f.independent_support_count == 2
    assert f.supporting_sources == ["amcache", "prefetch"]


def test_single_source_only_inferred():
    f = evaluate_claim(_claim([_ev("prefetch")]))
    assert f.verdict is Verdict.INFERRED
    assert f.independent_support_count == 1


def test_two_records_same_artifact_count_as_one():
    # Independence: two prefetch records are NOT two independent sources.
    f = evaluate_claim(_claim([_ev("prefetch"), _ev("prefetch")]))
    assert f.verdict is Verdict.INFERRED
    assert f.independent_support_count == 1


def test_no_evidence_is_unsupported():
    f = evaluate_claim(_claim([]))
    assert f.verdict is Verdict.UNSUPPORTED
    assert f.independent_support_count == 0


def test_conflict_with_support_is_contradicted():
    f = evaluate_claim(
        _claim([_ev("prefetch"), _ev("amcache"), _ev("mft", supports=False, detail="impossible ts")])
    )
    assert f.verdict is Verdict.CONTRADICTED
    assert "mft" in f.contradicting_sources
    assert any("impossible ts" in n for n in f.contradictions)


def test_only_contradiction_is_retracted():
    f = evaluate_claim(_claim([_ev("prefetch", supports=False, detail="run_count 0")]))
    assert f.verdict is Verdict.RETRACTED
    assert f.independent_support_count == 0
    assert f.contradictions


def test_non_corroborating_source_does_not_count():
    # 'registry_run_keys' is NOT an allowed corroborator for program_execution.
    f = evaluate_claim(_claim([_ev("prefetch"), _ev("registry_run_keys")]))
    assert f.verdict is Verdict.INFERRED  # only prefetch counts
    assert f.supporting_sources == ["prefetch"]


def test_account_logon_single_source_cannot_confirm():
    # Even with many evtx records, single allowed source -> at most INFERRED.
    f = evaluate_claim(
        _claim([_ev("evtx"), _ev("evtx")], claim_type="account_logon", subject="admin")
    )
    assert f.verdict is Verdict.INFERRED


def test_unknown_claim_type_any_distinct_source_counts():
    f = evaluate_claim(
        _claim([_ev("foo"), _ev("bar")], claim_type="mystery", subject="z")
    )
    assert f.verdict is Verdict.CONFIRMED


def test_persistence_confirmed_by_key_plus_execution():
    f = evaluate_claim(
        _claim([_ev("registry_run_keys"), _ev("prefetch")], claim_type="persistence")
    )
    assert f.verdict is Verdict.CONFIRMED


def test_finding_to_dict_has_rationale_and_verdict():
    d = evaluate_claim(_claim([_ev("prefetch"), _ev("amcache")])).to_dict()
    assert d["verdict"] == "CONFIRMED"
    assert "independent sources" in d["rationale"]
    assert len(d["evidence"]) == 2


# --------------------------------------------------------------------------- #
# Engine: logging of verdicts and contradictions
# --------------------------------------------------------------------------- #
def test_engine_logs_verdict_and_contradiction(tmp_path):
    log = JsonlLogger(tmp_path / "run.jsonl")
    engine = FalsificationEngine(logger=log)
    engine.evaluate(_claim([_ev("prefetch"), _ev("amcache")]))  # CONFIRMED
    engine.evaluate(_claim([_ev("prefetch"), _ev("amcache", supports=False)]))  # CONTRADICTED
    events = [r["event"] for r in log.read_all()]
    assert events.count("finding_verdict") == 2
    assert events.count("contradiction") == 1


def test_engine_evaluate_all_summary():
    engine = FalsificationEngine()
    claims = [
        _claim([_ev("prefetch"), _ev("amcache")], subject="a"),  # CONFIRMED
        _claim([_ev("prefetch")], subject="b"),  # INFERRED
        _claim([], subject="c"),  # UNSUPPORTED
        _claim([_ev("prefetch", supports=False)], subject="d"),  # RETRACTED
    ]
    out = engine.evaluate_all(claims)
    assert out["total"] == 4
    assert out["summary"]["CONFIRMED"] == 1
    assert out["summary"]["INFERRED"] == 1
    assert out["summary"]["UNSUPPORTED"] == 1
    assert out["summary"]["RETRACTED"] == 1


# --------------------------------------------------------------------------- #
# Bridge: building claims from artifact results
# --------------------------------------------------------------------------- #
class _FakeResult:
    def __init__(self, records):
        self.records = records
        self.provenance = make_provenance(
            tool_name="t", command="c", output=records, timestamp="2026-06-15T00:00:00Z"
        )


def test_normalize_subject_basename_lowercase():
    assert normalize_subject("C:\\Users\\evil\\Beacon.EXE") == "beacon.exe"
    assert normalize_subject("/tmp/Foo.bin") == "foo.bin"
    assert normalize_subject("") == ""


def test_build_claims_corroborates_across_artifacts():
    prefetch = _FakeResult(
        [{"source_artifact": "prefetch", "executable": "BEACON.EXE", "run_count": 3}]
    )
    amcache = _FakeResult(
        [{"source_artifact": "amcache", "name": "beacon.exe", "sha1": "abc"}]
    )
    claims = build_claims_from_results([prefetch, amcache])
    exec_claims = [c for c in claims if c.claim_type == "program_execution"]
    assert len(exec_claims) == 1
    f = evaluate_claim(exec_claims[0])
    assert f.verdict is Verdict.CONFIRMED  # prefetch + amcache, same subject


def test_build_claims_detects_runcount_zero_contradiction():
    pf = _FakeResult([{"source_artifact": "prefetch", "executable": "x.exe", "run_count": 0}])
    am = _FakeResult([{"source_artifact": "amcache", "name": "x.exe"}])
    claims = build_claims_from_results([pf, am])
    f = evaluate_claim(next(c for c in claims if c.claim_type == "program_execution"))
    # amcache supports, prefetch contradicts -> conflict.
    assert f.verdict is Verdict.CONTRADICTED


def test_build_claims_links_persistence_to_execution():
    reg = _FakeResult(
        [{
            "source_artifact": "registry_run_keys",
            "value_name": "Updater",
            "value_data": "C:\\Users\\evil\\beacon.exe",
        }]
    )
    pf = _FakeResult([{"source_artifact": "prefetch", "executable": "beacon.exe", "run_count": 2}])
    claims = build_claims_from_results([reg, pf])
    persistence = next(c for c in claims if c.claim_type == "persistence")
    f = evaluate_claim(persistence)
    # registry key + execution of same binary -> CONFIRMED persistence.
    assert f.verdict is Verdict.CONFIRMED
    assert "registry_run_keys" in f.supporting_sources
    assert "prefetch" in f.supporting_sources


def test_build_claims_from_evtx_4688_process_creation():
    evtx = _FakeResult(
        [{
            "source_artifact": "evtx",
            "event_id": 4688,
            "description": "Process Created",
            "payload": '{"NewProcessName":"C:\\\\Users\\\\evil\\\\beacon.exe"}',
        }]
    )
    pf = _FakeResult([{"source_artifact": "prefetch", "executable": "beacon.exe", "run_count": 1}])
    claims = build_claims_from_results([evtx, pf])
    f = evaluate_claim(next(c for c in claims if c.claim_type == "program_execution"))
    assert f.verdict is Verdict.CONFIRMED  # evtx 4688 + prefetch
    assert set(f.supporting_sources) == {"evtx", "prefetch"}


def test_default_matrix_independence_is_documented():
    rule = DEFAULT_MATRIX["program_execution"]
    assert "registry_run_keys" not in rule.independent_sources
    assert rule.min_sources_confirmed == 2
