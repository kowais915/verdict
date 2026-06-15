# Accuracy Report

> **Auto-generated** by `python benchmark/harness.py`. Do not edit by hand.
> Generated: 2026-06-15T17:39:16Z | Mode: deterministic replay | max_iterations cap: 25

This report compares **Verdict** (cross-artifact falsification engine) against a **naive single-source baseline** that confirms any finding mentioned by at least one artifact. Both use the *same* candidate claims, so the only variable is the decision rule. Honesty over perfection: Verdict deliberately downgrades single-source and contradicted findings rather than over-confirming them.

## Methodology

- **CONFIRMED** requires >= 2 independent artifact sources agreeing (PILLAR 2).
- Precision/recall are computed on the **CONFIRMED** decision vs ground-truth maliciousness.
- *Detection recall* additionally credits **INFERRED** findings (surfaced for the analyst but not confirmed).
- **Hallucination rate**: findings about subjects with no evidence. Verdict is provenance-bound, so this is 0 by construction; the metric matters when a live LLM agent drives the tools.

## Headline results (aggregate)

| Metric | Verdict (confirmed) | Naive baseline (confirmed) |
|---|---|---|
| Precision | **100.0%** | 50.0% |
| Recall | 75.0% | 100.0% |
| F1 | 85.7% | 66.7% |
| False positives | **0** | 4 |
| True positives | 3 | 4 |
| Hallucinations | 0 | 0 |
| Detection recall (confirmed+inferred) | 100.0% | n/a |

**Verdict eliminates 4 false positive(s)** that the naive baseline reports, by refusing to confirm single-source and contradicted findings — at the cost of leaving genuinely single-source malicious items at INFERRED rather than CONFIRMED (still surfaced to the analyst).

## Scenario: `find-evil-sample`

_Synthetic 'Find Evil!' triage scenario exercising every verdict path. Records mimic the normalized output of the Phase-3 read-only wrappers (PECmd/MFTECmd/AmcacheParser/RECmd/EvtxECmd). No real disk image is required; this is the deterministic replay dataset used to generate the accuracy report._

**Verdict confirmed/inferred breakdown:** CONFIRMED=3, INFERRED=4, CONTRADICTED=1

| Claim | Malicious (GT) | Verdict | Baseline | Agreement w/ GT |
|---|---|---|---|---|
| `file_existence:beacon.exe` | yes | CONFIRMED | CONFIRMED | ✅ |
| `persistence:beacon.exe` | yes | CONFIRMED | CONFIRMED | ✅ |
| `persistence:onedrive.exe` | no | INFERRED | CONFIRMED | ✅ |
| `program_execution:beacon.exe` | yes | CONFIRMED | CONFIRMED | ✅ |
| `program_execution:calc.exe` | no | INFERRED | CONFIRMED | ✅ |
| `program_execution:chrome.exe` | no | INFERRED | CONFIRMED | ✅ |
| `program_execution:evil2.exe` | yes | INFERRED | CONFIRMED | ⚠️ |
| `program_execution:ghost.exe` | no | CONTRADICTED | CONFIRMED | ✅ |

- Verdict: precision 100.0%, recall 75.0%, FP 0
- Baseline: precision 50.0%, recall 100.0%, FP 4

## Interpretation

The naive baseline achieves high recall but pays for it with false positives: it confirms benign single-source programs and even a binary whose prefetch run-count is 0 (present but never executed). Verdict's falsification step rejects exactly those, trading a small amount of *confirmed* recall for materially higher precision, and labels the residual single-source malicious item INFERRED instead of silently missing or over-confirming it.
