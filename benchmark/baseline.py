"""Naive single-source baseline — the comparison point for the accuracy report.

A naive triage agent trusts the first artifact it sees: if *any* source mentions
a subject, it declares the finding CONFIRMED. It performs **no** cross-artifact
corroboration and **ignores contradictions**. This is exactly the failure mode
Verdict's falsification engine is designed to prevent, so it is the honest
baseline to measure against.

The baseline reuses the *same* candidate claims as the Verdict engine (built by
:func:`sift_mcp.falsification.build_claims_from_results`) so the only difference
measured is the decision rule, not the candidate generation.
"""

from __future__ import annotations

from typing import Any, Iterable

from sift_mcp.falsification import Claim

__all__ = ["naive_evaluate", "naive_evaluate_all"]


def naive_evaluate(claim: Claim) -> dict[str, Any]:
    """Confirm a claim if it has any evidence at all (no falsification)."""
    has_any = len(claim.evidence) > 0
    return {
        "claim_id": claim.claim_id,
        "claim_type": claim.claim_type,
        "subject": claim.subject,
        "verdict": "CONFIRMED" if has_any else "UNSUPPORTED",
        "rationale": "Naive: at least one artifact mentioned the subject."
        if has_any
        else "Naive: no artifact mentioned the subject.",
    }


def naive_evaluate_all(claims: Iterable[Claim]) -> dict[str, Any]:
    findings = [naive_evaluate(c) for c in claims]
    summary: dict[str, int] = {}
    for f in findings:
        summary[f["verdict"]] = summary.get(f["verdict"], 0) + 1
    return {"findings": findings, "summary": summary, "total": len(findings)}
