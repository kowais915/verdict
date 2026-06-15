# Verdict — Devpost Description

## Inspiration

LLM agents are eager to please. Point one at a disk image and ask "find evil"
and it will happily report a confident list of compromises — some real, some
hallucinated, most uncorroborated. In digital forensics that is dangerous: a
false "CONFIRMED" can send an incident response down the wrong path, and an
agent with a shell tool can trample the very evidence it is examining. We wanted
an agent that is *structurally* incapable of damaging evidence and that is
forced to **disprove its own findings** before it dares to confirm them.

## What it does

Verdict is a read-only Model Context Protocol (MCP) server that plugs into Claude
Code on the SIFT Workstation. It exposes SIFT's forensic tools as typed,
read-only functions and adds a falsification layer:

- **Architectural read-only enforcement.** The agent only ever sees six
  read-only tools (prefetch, MFT timeline, Amcache, registry run keys, EVTX) plus
  a falsification endpoint. There is no shell/exec/write tool — destructive
  actions are impossible by construction.
- **Cross-artifact falsification.** Every candidate finding must be corroborated
  by ≥ 2 *independent* artifact sources to be **CONFIRMED**. One source →
  **INFERRED**; conflicting sources → **CONTRADICTED**; only-disproving evidence
  → **RETRACTED**. The verdict is *computed*, never asserted by the model.
- **Cryptographic provenance.** Every tool output is SHA-256 hashed; every
  finding carries a tamper-evident record (tool, exact command, evidence file,
  offset/inode, timestamp, token usage) written to a JSONL execution log.

On our benchmark, this raises a naive single-source agent from 50% precision
(four false positives) to **100% precision with zero false positives**, while
honestly labeling genuinely single-source findings as INFERRED rather than
hiding or over-confirming them.

**Why this is different.** Many AI-DFIR setups keep the agent safe and honest by
*instructing* it to be — "only read evidence," "corroborate before concluding."
That is discipline the model can ignore the instant a prompt is rephrased or
context is truncated. Verdict makes those two properties **structural** instead:
the read-only boundary is a closed tool surface the agent cannot call past, and
the confirmed-vs-inferred verdict is **computed** from cross-artifact
corroboration rather than declared by the model. It is complementary to
human-approval workflows — rather than a person gating each action after the
fact, the unsafe action is never expressible and the verdict is a deterministic
function of the evidence.

## How we built it

- **Python 3.11+** with the official **MCP SDK** (`mcp` / FastMCP) for the
  server, and `python-dotenv` for config.
- **`adapter.py`** is the single subprocess gate: an allow-list of forensic
  binaries, `shell=False`, argv-only — so shell metacharacters in arguments are
  inert data. Tool binaries are swappable per SIFT version via env vars, with
  graceful degradation when a binary is missing.
- **`provenance.py`** uses canonical JSON hashing so logically-equal payloads
  hash identically, and content-addressed record IDs that make tampering
  detectable.
- **`falsification.py`** holds a data-driven corroboration matrix and a pure,
  deterministic verdict function, plus a bridge that correlates the same subject
  (e.g. `beacon.exe`) across prefetch, Amcache, MFT, registry and EVTX 4688/7045.
- **`benchmark/harness.py`** runs a deterministic replay over a synthetic
  ground-truth scenario, scores Verdict against a naive baseline, and *generates*
  the accuracy report. No API key required.
- **86 pytest tests**, all deterministic and runnable without real evidence.

## Challenges we ran into

- **Independence is subtle.** Two prefetch records are *not* two independent
  sources. We made the corroboration matrix name exactly which artifact types
  count, so confirmation can't be gamed by repeated evidence from one tool.
- **Honest recall.** Some malicious artifacts only appear in one source. Rather
  than over-confirm, we surface them as INFERRED — and we measure and report the
  recall cost openly in the accuracy report.
- **Provenance over the right bytes.** Eric-Zimmerman tools write CSV to a
  directory, not stdout, so we hash the actual artifact CSV the finding derives
  from, not console chatter.
- **Testability without evidence.** We split every wrapper into a pure CSV parser
  (unit-tested with synthetic data) and a thin live runner (tested via graceful
  degradation), so the whole suite passes on a laptop with no forensic tools.

## What we learned

- Safety properties belong in the *architecture*, not the prompt. If the system
  prompt were ignored, our read-only and corroboration guarantees still hold.
- Making an agent *fail loudly and honestly* (CONTRADICTED/INFERRED) is more
  valuable to an investigator than a clean but overconfident list.
- Cheap, content-addressed provenance turns "the AI said so" into "here is the
  exact command, evidence file, and hash."

## What's next

- More claim types (lateral movement, scheduled tasks, WMI persistence) and
  richer EVTX→claim mappings.
- A timeline-consistency falsifier (reject claims whose timestamps are causally
  impossible).
- A signed, exportable case report bundling findings + provenance for court-grade
  chain of custody.
- Optional live-LLM benchmark mode to measure hallucination rate of a real
  Claude Code run against the same ground truth.

## Built with

`python` · `mcp` · `claude-code` · `sift-workstation` · `sleuthkit` ·
`eric-zimmerman-tools` · `pytest`
