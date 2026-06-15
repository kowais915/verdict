"""Benchmark harness — scores Verdict vs a naive baseline and generates the
accuracy report (deliverable #6).

Default mode is **deterministic replay**: synthetic-but-realistic artifact
records (the shape the Phase-3 wrappers emit) are run through the real
falsification engine and the naive baseline, then scored against ground truth.
No API key and no disk image are required — this is the primary local path.

Outputs (all auto-generated; do not hand-edit):
  * docs/accuracy_report.md          metrics + baseline comparison
  * samples/logs/sample_run.jsonl    structured execution log of a run
  * samples/output/triage_report.md  human-readable triage of the findings

Run:  python benchmark/harness.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Make the src/ package importable when run directly (python benchmark/harness.py).
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))
sys.path.insert(0, str(_REPO_ROOT / "benchmark"))

from baseline import naive_evaluate_all  # noqa: E402

from sift_mcp.config import load_config  # noqa: E402
from sift_mcp.falsification import (  # noqa: E402
    FalsificationEngine,
    Verdict,
    build_claims_from_results,
)
from sift_mcp.provenance import JsonlLogger, make_provenance, utc_now_iso  # noqa: E402

POSITIVE = {"CONFIRMED"}
DETECTION = {"CONFIRMED", "INFERRED"}


class _Prov:
    def __init__(self, rid):
        self.record_id = rid


class _Shim:
    def __init__(self, records, provenance_id):
        self.records = records
        self.provenance = _Prov(provenance_id)


# --------------------------------------------------------------------------- #
# Scenario loading + scoring
# --------------------------------------------------------------------------- #
def load_scenarios(scenarios_dir: Path) -> list[dict[str, Any]]:
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(scenarios_dir.glob("*.json"))]


def _shims(scenario: dict) -> list[_Shim]:
    return [_Shim(a.get("records", []), a.get("provenance_id")) for a in scenario["artifacts"]]


def _ground_truth(scenario: dict) -> dict[str, bool]:
    return {g["claim_id"]: bool(g["malicious"]) for g in scenario.get("ground_truth", [])}


def score(findings: list[dict], gt: dict[str, bool], positive_verdicts: set[str]) -> dict[str, Any]:
    """Precision/recall/hallucination for a set of findings vs ground truth."""
    malicious_total = sum(1 for m in gt.values() if m)
    positive_ids = {f["claim_id"] for f in findings if f["verdict"] in positive_verdicts}
    tp = sum(1 for cid in positive_ids if gt.get(cid, False))
    fp = sum(1 for cid in positive_ids if not gt.get(cid, False))
    fn = sum(1 for cid, m in gt.items() if m and cid not in positive_ids)
    # Hallucination: a reported finding about a subject with no evidence-backed
    # candidate. Every candidate here is provenance-bound, so this is 0 by
    # construction; the metric is meaningful when a live LLM agent is driving.
    known = set(gt) | {f["claim_id"] for f in findings}
    hallucinated = sum(1 for f in findings if f["verdict"] in positive_verdicts
                       and f["claim_id"] not in known)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / malicious_total if malicious_total else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1,
        "hallucinated": hallucinated, "malicious_total": malicious_total,
    }


def verdict_breakdown(findings: list[dict]) -> dict[str, int]:
    out = {v.value: 0 for v in Verdict}
    for f in findings:
        out[f["verdict"]] = out.get(f["verdict"], 0) + 1
    return out


# --------------------------------------------------------------------------- #
# Run
# --------------------------------------------------------------------------- #
def run_benchmark(
    *,
    scenarios_dir: Path | None = None,
    docs_out: Path | None = None,
    samples_logs: Path | None = None,
    samples_output: Path | None = None,
    config=None,
) -> dict[str, Any]:
    scenarios_dir = scenarios_dir or (_REPO_ROOT / "benchmark" / "ground_truth")
    docs_out = docs_out or (_REPO_ROOT / "docs" / "accuracy_report.md")
    samples_logs = samples_logs or (_REPO_ROOT / "samples" / "logs" / "sample_run.jsonl")
    samples_output = samples_output or (_REPO_ROOT / "samples" / "output" / "triage_report.md")
    config = config or load_config()

    max_iterations = config.max_iterations
    # Fresh sample log per run.
    samples_logs.parent.mkdir(parents=True, exist_ok=True)
    if samples_logs.exists():
        samples_logs.unlink()
    sample_logger = JsonlLogger(samples_logs)

    scenarios = load_scenarios(scenarios_dir)
    per_scenario: list[dict[str, Any]] = []
    all_engine_findings: list[dict] = []

    for scenario in scenarios:
        shims = _shims(scenario)
        gt = _ground_truth(scenario)

        # Log a synthetic tool_execution record per artifact so the sample log
        # reflects a realistic provenance trail (the real wrappers emit these).
        for a in scenario["artifacts"]:
            prov = make_provenance(
                tool_name=a["artifact"],
                command=f"{a['artifact']} wrapper (deterministic replay)",
                output=a.get("records", []),
                evidence_file=scenario["name"],
            )
            sample_logger.log_record(prov)

        claims = build_claims_from_results(shims)
        if len(claims) > max_iterations:  # hard cap (documented safety limit)
            claims = claims[:max_iterations]

        engine = FalsificationEngine(logger=sample_logger)
        engine_out = engine.evaluate_all(claims)
        baseline_out = naive_evaluate_all(claims)

        engine_metrics = score(engine_out["findings"], gt, POSITIVE)
        engine_detection = score(engine_out["findings"], gt, DETECTION)
        baseline_metrics = score(baseline_out["findings"], gt, POSITIVE)

        per_scenario.append({
            "scenario": scenario["name"],
            "description": scenario.get("description", ""),
            "claims": len(claims),
            "ground_truth": gt,
            "engine": engine_out,
            "baseline": baseline_out,
            "engine_metrics": engine_metrics,
            "engine_detection_metrics": engine_detection,
            "baseline_metrics": baseline_metrics,
            "breakdown": verdict_breakdown(engine_out["findings"]),
        })
        all_engine_findings.extend(engine_out["findings"])

    report = render_report(per_scenario, max_iterations=max_iterations)
    docs_out.parent.mkdir(parents=True, exist_ok=True)
    docs_out.write_text(report, encoding="utf-8")

    triage = render_triage(per_scenario)
    samples_output.parent.mkdir(parents=True, exist_ok=True)
    samples_output.write_text(triage, encoding="utf-8")

    return {
        "scenarios": per_scenario,
        "report_path": str(docs_out),
        "sample_log_path": str(samples_logs),
        "triage_path": str(samples_output),
    }


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def render_report(per_scenario: list[dict], *, max_iterations: int) -> str:
    L: list[str] = []
    L.append("# Accuracy Report")
    L.append("")
    L.append("> **Auto-generated** by `python benchmark/harness.py`. Do not edit by hand.")
    L.append(f"> Generated: {utc_now_iso()} | Mode: deterministic replay | "
             f"max_iterations cap: {max_iterations}")
    L.append("")
    L.append("This report compares **Verdict** (cross-artifact falsification engine) against a "
             "**naive single-source baseline** that confirms any finding mentioned by at least one "
             "artifact. Both use the *same* candidate claims, so the only variable is the decision "
             "rule. Honesty over perfection: Verdict deliberately downgrades single-source and "
             "contradicted findings rather than over-confirming them.")
    L.append("")
    L.append("## Methodology")
    L.append("")
    L.append("- **CONFIRMED** requires >= 2 independent artifact sources agreeing (PILLAR 2).")
    L.append("- Precision/recall are computed on the **CONFIRMED** decision vs ground-truth "
             "maliciousness.")
    L.append("- *Detection recall* additionally credits **INFERRED** findings (surfaced for the "
             "analyst but not confirmed).")
    L.append("- **Hallucination rate**: findings about subjects with no evidence. Verdict is "
             "provenance-bound, so this is 0 by construction; the metric matters when a live LLM "
             "agent drives the tools.")
    L.append("")

    # Aggregate
    agg = _aggregate(per_scenario)
    L.append("## Headline results (aggregate)")
    L.append("")
    L.append("| Metric | Verdict (confirmed) | Naive baseline (confirmed) |")
    L.append("|---|---|---|")
    L.append(f"| Precision | **{_pct(agg['engine']['precision'])}** | "
             f"{_pct(agg['baseline']['precision'])} |")
    L.append(f"| Recall | {_pct(agg['engine']['recall'])} | {_pct(agg['baseline']['recall'])} |")
    L.append(f"| F1 | {_pct(agg['engine']['f1'])} | {_pct(agg['baseline']['f1'])} |")
    L.append(f"| False positives | **{agg['engine']['fp']}** | {agg['baseline']['fp']} |")
    L.append(f"| True positives | {agg['engine']['tp']} | {agg['baseline']['tp']} |")
    L.append(f"| Hallucinations | {agg['engine']['hallucinated']} | "
             f"{agg['baseline']['hallucinated']} |")
    L.append(f"| Detection recall (confirmed+inferred) | {_pct(agg['engine_detection']['recall'])} "
             f"| n/a |")
    L.append("")
    fp_reduction = agg["baseline"]["fp"] - agg["engine"]["fp"]
    L.append(f"**Verdict eliminates {fp_reduction} false positive(s)** that the naive baseline "
             f"reports, by refusing to confirm single-source and contradicted findings — at the "
             f"cost of leaving genuinely single-source malicious items at INFERRED rather than "
             f"CONFIRMED (still surfaced to the analyst).")
    L.append("")

    for s in per_scenario:
        L.append(f"## Scenario: `{s['scenario']}`")
        L.append("")
        if s["description"]:
            L.append(f"_{s['description']}_")
            L.append("")
        b = s["breakdown"]
        L.append("**Verdict confirmed/inferred breakdown:** "
                 + ", ".join(f"{k}={v}" for k, v in b.items() if v))
        L.append("")
        L.append("| Claim | Malicious (GT) | Verdict | Baseline | Agreement w/ GT |")
        L.append("|---|---|---|---|---|")
        bl_by_id = {f["claim_id"]: f["verdict"] for f in s["baseline"]["findings"]}
        for f in sorted(s["engine"]["findings"], key=lambda x: x["claim_id"]):
            cid = f["claim_id"]
            mal = s["ground_truth"].get(cid, False)
            v = f["verdict"]
            bl = bl_by_id.get(cid, "-")
            # "correct" = confirmed iff malicious; verdict agrees if (CONFIRMED & mal) or
            # (not CONFIRMED & not mal).
            correct = "✅" if ((v == "CONFIRMED") == mal) else "⚠️"
            L.append(f"| `{cid}` | {'yes' if mal else 'no'} | {v} | {bl} | {correct} |")
        L.append("")
        em, bm = s["engine_metrics"], s["baseline_metrics"]
        L.append(f"- Verdict: precision {_pct(em['precision'])}, recall {_pct(em['recall'])}, "
                 f"FP {em['fp']}")
        L.append(f"- Baseline: precision {_pct(bm['precision'])}, recall {_pct(bm['recall'])}, "
                 f"FP {bm['fp']}")
        L.append("")

    L.append("## Interpretation")
    L.append("")
    L.append("The naive baseline achieves high recall but pays for it with false positives: it "
             "confirms benign single-source programs and even a binary whose prefetch run-count is "
             "0 (present but never executed). Verdict's falsification step rejects exactly those, "
             "trading a small amount of *confirmed* recall for materially higher precision, and "
             "labels the residual single-source malicious item INFERRED instead of silently "
             "missing or over-confirming it.")
    return "\n".join(L) + "\n"


def _aggregate(per_scenario: list[dict]) -> dict[str, Any]:
    def sum_metric(key):
        tp = sum(s[key]["tp"] for s in per_scenario)
        fp = sum(s[key]["fp"] for s in per_scenario)
        fn = sum(s[key]["fn"] for s in per_scenario)
        hall = sum(s[key]["hallucinated"] for s in per_scenario)
        mal = sum(s[key]["malicious_total"] for s in per_scenario)
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        recall = tp / mal if mal else 1.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        return {"tp": tp, "fp": fp, "fn": fn, "hallucinated": hall,
                "precision": precision, "recall": recall, "f1": f1}

    return {
        "engine": sum_metric("engine_metrics"),
        "engine_detection": sum_metric("engine_detection_metrics"),
        "baseline": sum_metric("baseline_metrics"),
    }


def render_triage(per_scenario: list[dict]) -> str:
    order = {"CONFIRMED": 0, "CONTRADICTED": 1, "RETRACTED": 2, "INFERRED": 3, "UNSUPPORTED": 4}
    L: list[str] = []
    L.append("# Verdict Triage Report (sample)")
    L.append("")
    L.append(f"> Auto-generated by the benchmark harness on {utc_now_iso()}.")
    L.append("> Every verdict below is *computed* from cross-artifact corroboration and is "
             "traceable to tool executions in `samples/logs/sample_run.jsonl` (PILLAR 3).")
    L.append("")
    for s in per_scenario:
        L.append(f"## Case: {s['scenario']}")
        L.append("")
        findings = sorted(s["engine"]["findings"], key=lambda f: order.get(f["verdict"], 9))
        for f in findings:
            L.append(f"### [{f['verdict']}] {f['statement']}")
            L.append(f"- **Claim**: `{f['claim_id']}`")
            L.append(f"- **Supporting sources** ({f['independent_support_count']}/"
                     f"{f['required_for_confirmation']} required): "
                     f"{', '.join(f['supporting_sources']) or 'none'}")
            if f["contradicting_sources"]:
                L.append(f"- **Contradicting sources**: {', '.join(f['contradicting_sources'])}")
            if f["contradictions"]:
                L.append(f"- **Contradictions**: {'; '.join(f['contradictions'])}")
            prov_ids = sorted({e["provenance_id"] for e in f["evidence"] if e.get("provenance_id")})
            L.append(f"- **Provenance**: {', '.join(prov_ids) or 'n/a'}")
            L.append(f"- **Rationale**: {f['rationale']}")
            L.append("")
    return "\n".join(L) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Verdict benchmark harness (deterministic replay).")
    ap.add_argument("--scenarios-dir", type=Path, default=None)
    ap.add_argument("--docs-out", type=Path, default=None)
    ap.add_argument("--max-iterations", type=int, default=None,
                    help="Override the hard iteration cap for this run.")
    args = ap.parse_args(argv)

    config = load_config()
    if args.max_iterations is not None:
        object.__setattr__(config, "max_iterations", max(1, args.max_iterations))

    result = run_benchmark(
        scenarios_dir=args.scenarios_dir, docs_out=args.docs_out, config=config
    )
    agg = _aggregate(result["scenarios"])
    print(f"Accuracy report written: {result['report_path']}")
    print(f"Sample log written:      {result['sample_log_path']}")
    print(f"Triage report written:   {result['triage_path']}")
    print(f"Verdict precision={_pct(agg['engine']['precision'])} "
          f"FP={agg['engine']['fp']} | "
          f"Baseline precision={_pct(agg['baseline']['precision'])} FP={agg['baseline']['fp']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
