# Security & Responsible Use

Verdict is a **read-only forensic triage aid** for digital forensics and incident
response (DFIR). It is built to *reduce* the risk an AI agent poses to evidence
and to *resist* over-confident findings — but it is a tool, not a substitute for
a qualified examiner. Please read the following before relying on it.

## Intended use

- Run Verdict against **forensic copies** of evidence, mounted **read-only**, in a
  dedicated analysis environment — never against the only copy of evidence and
  never against a live production system.
- Verdict is an **analysis environment, not an evidence store.** It does not
  preserve, image, or maintain chain of custody for source media. Acquisition,
  hashing of the original media, and custody tracking remain the examiner's
  responsibility, performed with appropriate tooling and process.
- All verdicts (`CONFIRMED` / `INFERRED` / `CONTRADICTED` / `RETRACTED` /
  `UNSUPPORTED`) are **investigative aids**. Final determinations — and anything
  presented in a report or in court — must be reviewed and owned by a human
  examiner.

## Threat model and its limits

Verdict's read-only guarantee is **architectural**: the agent is only ever
exposed to a closed set of read-only tools, the single subprocess gate runs an
allow-listed set of forensic binaries with `shell=False` and an argv list, and
the startup guard refuses to boot if a forbidden (shell/exec/write/delete) tool
name ever appears. This means an agent **cannot** issue a destructive command
through Verdict's interface by construction, not by instruction.

**However:** Verdict is **not designed to defend against a deliberately malicious
AI model or a compromised host.** A model with separate, out-of-band tool access,
or an attacker with shell access to the workstation, is outside this tool's
boundary. Verdict hardens the *agent-to-evidence* path; it does not sandbox the
operating system. Run it on a trusted analysis host.

Likewise, the falsification engine raises the bar for confirmation (≥ 2
independent artifact sources) but cannot detect **anti-forensic tampering** that
is consistently reflected across multiple artifacts. Corroboration reduces, but
does not eliminate, the risk of a planted-but-consistent narrative.

## Reporting a vulnerability

If you find a security issue in Verdict itself (e.g. a way to coax a write or
shell execution through the read-only surface), please open a private report to
the maintainers rather than a public issue, and allow reasonable time to remediate
before disclosure.
