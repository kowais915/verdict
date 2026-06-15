"""Cross-artifact falsification / self-correction engine (PILLAR 2).

This is Verdict's **novel core contribution**. Rather than letting an agent
*assert* that something is true, every candidate finding is forced through a
falsification step: the engine demands corroboration from independent forensic
artifact sources and *computes* a verdict. A finding is only ``CONFIRMED`` when
at least two **independent** sources agree; otherwise it is downgraded to
``INFERRED`` (single source), ``CONTRADICTED`` (sources conflict),
``RETRACTED`` (only disproving evidence), or ``UNSUPPORTED`` (no evidence).
Contradictions are recorded, never silently dropped.

Key ideas
---------
* **Claim** — an assertion about evil (e.g. "beacon.exe executed").
* **Evidence** — a normalized artifact record that *supports* or *contradicts*
  a claim, tagged with the artifact type it came from and a provenance id.
* **Independence** — two records from the *same* artifact type count as ONE
  independent source. Confirmation requires >= 2 *distinct* artifact types.
* **Corroboration matrix** — data describing, per claim type, which artifact
  types may independently corroborate it.

The verdict computation is pure and deterministic, so it is fully unit-testable
with synthetic claims (no real evidence required).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from .provenance import JsonlLogger

__all__ = [
    "Verdict",
    "Evidence",
    "Claim",
    "CorroborationRule",
    "Finding",
    "DEFAULT_MATRIX",
    "DEFAULT_MIN_SOURCES",
    "evaluate_claim",
    "FalsificationEngine",
    "normalize_subject",
    "build_claims_from_results",
]

DEFAULT_MIN_SOURCES = 2  # the headline rule: >= 2 independent sources to CONFIRM


class Verdict(str, Enum):
    """Computed status of a candidate finding (never self-asserted)."""

    CONFIRMED = "CONFIRMED"  # >= min independent supporting sources, no conflict
    INFERRED = "INFERRED"  # exactly one supporting source
    CONTRADICTED = "CONTRADICTED"  # supporting AND contradicting sources conflict
    RETRACTED = "RETRACTED"  # only contradicting evidence; claim disproven
    UNSUPPORTED = "UNSUPPORTED"  # no relevant evidence at all


@dataclass(frozen=True)
class Evidence:
    """A single supporting/contradicting artifact record for a claim."""

    source_artifact: str  # e.g. "prefetch", "amcache", "evtx"
    supports: bool  # True = supports the claim, False = contradicts it
    detail: str = ""
    provenance_id: str | None = None  # links to ProvenanceRecord.record_id
    timestamp: str | None = None
    record: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_artifact": self.source_artifact,
            "supports": self.supports,
            "detail": self.detail,
            "provenance_id": self.provenance_id,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class Claim:
    """A candidate finding to be falsified."""

    claim_id: str
    claim_type: str
    subject: str
    statement: str
    evidence: list[Evidence] = field(default_factory=list)


@dataclass(frozen=True)
class CorroborationRule:
    """Which artifact types may independently corroborate a claim type."""

    claim_type: str
    independent_sources: frozenset[str]
    min_sources_confirmed: int = DEFAULT_MIN_SOURCES
    description: str = ""


# The corroboration matrix. Each claim type lists the artifact types that count
# as *independent* corroboration. A source not listed here is recorded as
# context but does NOT count toward confirmation (keeps independence honest).
DEFAULT_MATRIX: dict[str, CorroborationRule] = {
    "program_execution": CorroborationRule(
        claim_type="program_execution",
        independent_sources=frozenset({"prefetch", "amcache", "evtx"}),
        description="Execution corroborated by prefetch, Amcache, and/or 4688 events.",
    ),
    "persistence": CorroborationRule(
        claim_type="persistence",
        independent_sources=frozenset({"registry_run_keys", "evtx", "prefetch", "amcache"}),
        description="Autostart key plus evidence the target ran or a service-install event.",
    ),
    "file_existence": CorroborationRule(
        claim_type="file_existence",
        independent_sources=frozenset({"mft", "amcache", "prefetch"}),
        description="File presence corroborated across the filesystem and execution artifacts.",
    ),
    "account_logon": CorroborationRule(
        claim_type="account_logon",
        independent_sources=frozenset({"evtx"}),
        description="Logon activity. Single-source by nature: caps at INFERRED, never CONFIRMED.",
    ),
}


# --- DFIR reporting vocabulary (light, indicative — not a full ATT&CK mapping) #
# Each finding is annotated so the output reads as professional DFIR: a
# confidence band, an observation (what was seen) separated from the
# interpretation (what it means), candidate MITRE ATT&CK technique IDs, and IOCs.
_CONFIDENCE_BY_VERDICT: dict[str, str] = {
    "CONFIRMED": "high",
    "INFERRED": "low",
    "CONTRADICTED": "disputed",
    "RETRACTED": "rejected",
    "UNSUPPORTED": "none",
}

_MITRE_BY_CLAIM_TYPE: dict[str, list[str]] = {
    "program_execution": ["T1204"],  # User Execution
    "persistence": ["T1547.001"],  # Boot/Logon Autostart Execution: Registry Run Keys
    "account_logon": ["T1078"],  # Valid Accounts
    "file_existence": [],
}


def _iocs_for(subject: str) -> list[str]:
    """Derive simple file-name IOCs from a claim subject (best-effort, light)."""
    return [subject] if subject and "." in subject else []


def _rule_for(claim_type: str, matrix: dict[str, CorroborationRule]) -> CorroborationRule:
    """Return the rule for a claim type, or a permissive default if unknown."""
    if claim_type in matrix:
        return matrix[claim_type]
    return CorroborationRule(
        claim_type=claim_type,
        independent_sources=frozenset(),  # empty -> any artifact counts (see below)
        description="No specific rule; any distinct artifact type counts as independent.",
    )


# --------------------------------------------------------------------------- #
# Core verdict computation (pure & deterministic)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Finding:
    """The computed result of falsifying a claim."""

    claim_id: str
    claim_type: str
    subject: str
    statement: str
    verdict: Verdict
    supporting_sources: list[str]
    contradicting_sources: list[str]
    independent_support_count: int
    required_for_confirmation: int
    rationale: str
    contradictions: list[str]
    evidence: list[Evidence]
    # DFIR reporting vocabulary (computed; see _CONFIDENCE_BY_VERDICT / _MITRE_*).
    confidence: str = "none"
    observation: str = ""
    interpretation: str = ""
    mitre_attack: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "claim_type": self.claim_type,
            "subject": self.subject,
            "statement": self.statement,
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "observation": self.observation,
            "interpretation": self.interpretation,
            "mitre_attack": self.mitre_attack,
            "iocs": self.iocs,
            "supporting_sources": self.supporting_sources,
            "contradicting_sources": self.contradicting_sources,
            "independent_support_count": self.independent_support_count,
            "required_for_confirmation": self.required_for_confirmation,
            "rationale": self.rationale,
            "contradictions": self.contradictions,
            "evidence": [e.to_dict() for e in self.evidence],
        }


def evaluate_claim(
    claim: Claim,
    matrix: dict[str, CorroborationRule] | None = None,
) -> Finding:
    """Compute a :class:`Finding` for ``claim`` from its evidence.

    Decision rule (deterministic):

    * Let ``S`` = number of *distinct* artifact types that support the claim and
      are permitted corroborators; ``C`` = number of distinct artifact types
      that contradict it.
    * ``C > 0`` and ``S == 0``  -> RETRACTED
    * ``C > 0`` and ``S > 0``   -> CONTRADICTED
    * ``S >= threshold``        -> CONFIRMED
    * ``S == 1``                -> INFERRED
    * otherwise (``S == 0``)    -> UNSUPPORTED
    """
    matrix = matrix if matrix is not None else DEFAULT_MATRIX
    rule = _rule_for(claim.claim_type, matrix)
    threshold = rule.min_sources_confirmed
    allowed = rule.independent_sources

    def _counts(allowed_only: bool) -> tuple[set[str], set[str]]:
        s, c = set(), set()
        for ev in claim.evidence:
            if allowed_only and allowed and ev.source_artifact not in allowed:
                continue
            (s if ev.supports else c).add(ev.source_artifact)
        return s, c

    # If the rule names allowed corroborators, only those count toward S.
    # If it names none (unknown claim type), every distinct artifact counts.
    support, contradict = _counts(allowed_only=bool(allowed))
    # Contradictions are always honored regardless of the allow-list.
    _, contradict_all = _counts(allowed_only=False)
    contradict = contradict_all

    s = len(support)
    c = len(contradict)
    contradiction_notes = [
        ev.detail or f"{ev.source_artifact} contradicts the claim"
        for ev in claim.evidence
        if not ev.supports
    ]

    if c > 0 and s == 0:
        verdict = Verdict.RETRACTED
        rationale = (
            f"Only contradicting evidence ({', '.join(sorted(contradict))}); "
            f"claim disproven."
        )
    elif c > 0 and s > 0:
        verdict = Verdict.CONTRADICTED
        rationale = (
            f"Sources conflict: supported by {sorted(support)} but contradicted by "
            f"{sorted(contradict)}. Cannot confirm; analyst review required."
        )
    elif s >= threshold:
        verdict = Verdict.CONFIRMED
        rationale = (
            f"Corroborated by {s} independent sources {sorted(support)} "
            f"(>= {threshold} required)."
        )
    elif s == 1:
        verdict = Verdict.INFERRED
        rationale = (
            f"Only one independent source {sorted(support)} "
            f"(>= {threshold} required to confirm)."
        )
    else:
        verdict = Verdict.UNSUPPORTED
        rationale = "No permitted corroborating evidence found."

    # DFIR reporting vocabulary: separate the raw observation (what artifacts
    # show) from the interpretation (what the verdict means), and attach a
    # confidence band plus indicative ATT&CK techniques and IOCs.
    observation = (
        f"'{claim.subject}' appears in {sorted(support)} "
        f"({s} independent source(s))"
        + (f"; contradicted by {sorted(contradict)}" if c else "")
    )
    interpretation = f"{claim.statement} [{verdict.value}] {rationale}"

    return Finding(
        claim_id=claim.claim_id,
        claim_type=claim.claim_type,
        subject=claim.subject,
        statement=claim.statement,
        verdict=verdict,
        supporting_sources=sorted(support),
        contradicting_sources=sorted(contradict),
        independent_support_count=s,
        required_for_confirmation=threshold,
        rationale=rationale,
        contradictions=contradiction_notes,
        evidence=list(claim.evidence),
        confidence=_CONFIDENCE_BY_VERDICT.get(verdict.value, "none"),
        observation=observation,
        interpretation=interpretation,
        mitre_attack=list(_MITRE_BY_CLAIM_TYPE.get(claim.claim_type, [])),
        iocs=_iocs_for(claim.subject),
    )


class FalsificationEngine:
    """Stateful wrapper that evaluates claims and logs every verdict + contradiction.

    The engine logs a ``finding_verdict`` event for each claim and a separate
    ``contradiction`` event whenever sources conflict, satisfying the brief's
    requirement that contradictions are explicitly recorded.
    """

    def __init__(
        self,
        matrix: dict[str, CorroborationRule] | None = None,
        logger: JsonlLogger | None = None,
    ):
        self.matrix = matrix if matrix is not None else DEFAULT_MATRIX
        self.logger = logger

    def evaluate(self, claim: Claim) -> Finding:
        finding = evaluate_claim(claim, self.matrix)
        if self.logger is not None:
            self.logger.log_event(
                "finding_verdict",
                claim_id=finding.claim_id,
                claim_type=finding.claim_type,
                subject=finding.subject,
                verdict=finding.verdict.value,
                independent_support_count=finding.independent_support_count,
                supporting_sources=finding.supporting_sources,
                provenance_ids=[e.provenance_id for e in finding.evidence if e.provenance_id],
            )
            if finding.verdict in (Verdict.CONTRADICTED, Verdict.RETRACTED):
                self.logger.log_event(
                    "contradiction",
                    claim_id=finding.claim_id,
                    subject=finding.subject,
                    verdict=finding.verdict.value,
                    contradicting_sources=finding.contradicting_sources,
                    notes=finding.contradictions,
                )
        return finding

    def evaluate_all(self, claims: Iterable[Claim]) -> dict[str, Any]:
        """Evaluate many claims; return findings plus a verdict summary."""
        findings = [self.evaluate(c) for c in claims]
        summary = {v.value: 0 for v in Verdict}
        for f in findings:
            summary[f.verdict.value] += 1
        return {
            "findings": [f.to_dict() for f in findings],
            "summary": summary,
            "total": len(findings),
        }


# --------------------------------------------------------------------------- #
# Bridge: turn normalized artifact records into corroborated claims
# --------------------------------------------------------------------------- #
def normalize_subject(value: str) -> str:
    """Lowercased basename of a path/executable, for cross-artifact matching."""
    if not value:
        return ""
    v = value.strip().strip('"').replace("/", "\\")
    return v.split("\\")[-1].lower()


# Event-log events that contribute to other claim types, with the regex used to
# extract the relevant subject (executable / service binary) from the payload.
_EVTX_CLAIM_MAP: dict[int, tuple[str, str]] = {
    4688: ("program_execution", r'NewProcessName["\s:=>]+([^"\s,}]+)'),
    7045: ("persistence", r'ImagePath["\s:=>]+([^"\s,}]+)'),
}


def _evtx_subject_and_type(record: dict[str, Any]) -> tuple[str | None, str | None]:
    eid = record.get("event_id")
    if eid not in _EVTX_CLAIM_MAP:
        return None, None
    claim_type, pattern = _EVTX_CLAIM_MAP[eid]
    blob = f"{record.get('description', '')} {record.get('payload', '')}"
    m = re.search(pattern, blob)
    if not m:
        return None, claim_type
    return normalize_subject(m.group(1)), claim_type


def _record_subject_and_type(artifact: str, record: dict[str, Any]) -> tuple[str | None, str | None]:
    """Map a normalized artifact record to (subject, claim_type) for grouping."""
    if artifact == "prefetch":
        return normalize_subject(record.get("executable", "")), "program_execution"
    if artifact == "amcache":
        subj = record.get("name") or record.get("full_path", "")
        return normalize_subject(subj), "program_execution"
    if artifact == "mft":
        return normalize_subject(record.get("file_name") or record.get("path", "")), "file_existence"
    if artifact == "registry_run_keys":
        # The persistence subject is the autostart *target* binary.
        return normalize_subject(record.get("value_data", "")), "persistence"
    if artifact == "evtx":
        return _evtx_subject_and_type(record)
    return None, None


def _is_contradiction(artifact: str, claim_type: str, record: dict[str, Any]) -> str | None:
    """Deterministic contradiction detectors. Returns a note if contradicting."""
    if claim_type == "program_execution" and artifact == "prefetch":
        rc = record.get("run_count")
        if rc == 0:
            return "prefetch run_count is 0 (file present but never executed)"
    return None


def build_claims_from_results(
    results: Iterable[Any],
    *,
    extra_claim_types: Iterable[str] = ("file_existence",),
) -> list[Claim]:
    """Construct corroborated :class:`Claim` objects from tool results.

    ``results`` is an iterable of objects exposing ``.records`` (list of
    normalized dicts) and ``.provenance`` (with ``.record_id``) — i.e. the
    :class:`~sift_mcp.tools._common.ArtifactResult` objects returned by the
    Phase-3 wrappers.

    Records are mapped to ``(subject, claim_type)`` and grouped, so a single
    subject (e.g. ``beacon.exe``) accumulates evidence from every independent
    artifact that mentions it — which is exactly what enables cross-artifact
    corroboration. Persistence claims additionally pull in execution evidence
    for the same subject.
    """
    # subject -> claim_type -> list[Evidence]
    grouped: dict[tuple[str, str], list[Evidence]] = {}
    # subject -> set of execution Evidence (for cross-linking into persistence)
    exec_by_subject: dict[str, list[Evidence]] = {}

    for result in results:
        prov_id = getattr(getattr(result, "provenance", None), "record_id", None)
        for record in getattr(result, "records", []) or []:
            artifact = record.get("source_artifact", "")
            subject, claim_type = _record_subject_and_type(artifact, record)
            if not subject or not claim_type:
                continue
            note = _is_contradiction(artifact, claim_type, record)
            ev = Evidence(
                source_artifact=artifact,
                supports=note is None,
                detail=note or f"{artifact} record for {subject}",
                provenance_id=prov_id,
                timestamp=record.get("last_run")
                or record.get("time_created")
                or record.get("last_write")
                or record.get("last_modified")
                or record.get("modified"),
                record=record,
            )
            grouped.setdefault((subject, claim_type), []).append(ev)
            if claim_type == "program_execution":
                exec_by_subject.setdefault(subject, []).append(ev)

    # Cross-link: persistence and file-existence claims are corroborated if the
    # same binary also has execution evidence (a program that ran necessarily
    # existed; an autostart entry whose target ran is corroborated persistence).
    # NOTE: we only augment claims that already exist (from a registry/MFT
    # record); we never fabricate new claims from execution alone, so the
    # candidate set stays evidence-grounded.
    for (subject, claim_type), evlist in grouped.items():
        if claim_type in ("persistence", "file_existence"):
            for ev in exec_by_subject.get(subject, []):
                if ev not in evlist:
                    evlist.append(ev)

    claims: list[Claim] = []
    for (subject, claim_type), evlist in sorted(grouped.items()):
        claims.append(
            Claim(
                claim_id=f"{claim_type}:{subject}",
                claim_type=claim_type,
                subject=subject,
                statement=_statement_for(claim_type, subject),
                evidence=evlist,
            )
        )
    return claims


def _statement_for(claim_type: str, subject: str) -> str:
    return {
        "program_execution": f"Program '{subject}' was executed on the system.",
        "persistence": f"Persistence established via autostart of '{subject}'.",
        "file_existence": f"File '{subject}' exists on the filesystem.",
        "account_logon": f"Account logon activity involving '{subject}'.",
    }.get(claim_type, f"{claim_type} concerning '{subject}'.")
