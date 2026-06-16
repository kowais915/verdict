# Verdict — Read-Only Forensic MCP Server with Falsification & Provenance

> A SANS *"Find Evil!"* hackathon submission. A custom, **read-only** Model
> Context Protocol (MCP) server that exposes SIFT Workstation forensic tools as
> typed, structured functions to a [Claude Code](https://claude.com/claude-code)
> agent — plus a **falsification-driven self-correction layer** that forces the
> agent to disprove its own findings before reporting them.

[![CI](https://github.com/kowais915/verdict/actions/workflows/ci.yml/badge.svg)](https://github.com/kowais915/verdict/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## In plain English

When you ask an AI agent to "find evil" on a hacked computer, it tends to do two
dangerous things: it **over-confirms** (reports findings it can't actually back
up) and, if given the power, it can **alter the evidence** it's examining.

Verdict fixes both. It gives a Claude Code agent a fixed set of **look-but-don't-touch**
forensic tools — so it physically *cannot* run a command that changes the disk —
and it forces the agent to **prove each finding against at least two independent
pieces of evidence** before it's allowed to say "confirmed." If the evidence only
half-agrees, the finding is marked *inferred*; if two sources contradict each
other, it's flagged and the agent must back down. Every result is stamped with a
cryptographic hash so you can trace it back to the exact tool that produced it.

The result: an agent that says "I'm sure" far less often, but is right when it
does — and that can never damage the crime scene.

---

## Headline behavior

The agent refuses to label a finding **CONFIRMED** unless it is corroborated by
**≥ 2 independent forensic artifact sources**. Otherwise it downgrades the
finding to **INFERRED** or **RETRACTED**, and logs the contradiction. The
verdict is *computed*, never asserted.

On the bundled benchmark, this turns a naive single-source agent's **50%
precision (4 false positives)** into **100% precision (0 false positives)** —
see [`docs/accuracy_report.md`](docs/accuracy_report.md) (auto-generated).

## Example: watch the agent correct itself

The agent collects artifacts with the read-only tools, then calls
`evaluate_findings`. The verdict is *computed* from how the evidence lines up.

**Case 1 — a file that looks executed but wasn't.** Amcache shows `ghost.exe` is
present, so a naive agent confirms "it ran." Verdict also checks Prefetch, which
shows a run count of **0** — the file exists but never executed. The two sources
conflict, so the agent must retract:

```json
{
  "claim_id": "program_execution:ghost.exe",
  "verdict": "CONTRADICTED",
  "supporting_sources": ["amcache"],
  "contradicting_sources": ["prefetch"],
  "contradictions": ["prefetch run_count is 0 (file present but never executed)"],
  "rationale": "Sources conflict: supported by ['amcache'] but contradicted by ['prefetch']. Cannot confirm; analyst review required."
}
```

**Case 2 — a real threat, corroborated.** `beacon.exe` shows up independently in
Prefetch, Amcache, *and* a Windows 4688 process-creation event. Three independent
sources agree, so it is confirmed:

```json
{
  "claim_id": "program_execution:beacon.exe",
  "verdict": "CONFIRMED",
  "supporting_sources": ["amcache", "evtx", "prefetch"],
  "rationale": "Corroborated by 3 independent sources ['amcache', 'evtx', 'prefetch'] (>= 2 required)."
}
```

Reproduce both (no evidence or API key needed): `python benchmark/harness.py`,
then read [`samples/output/triage_report.md`](samples/output/triage_report.md).

## The three pillars

1. **Architectural read-only enforcement** — only read-only typed functions are
   exposed (`get_prefetch`, `get_mft_timeline`, `get_amcache`,
   `get_registry_run_keys`, `parse_evtx`). There is **no** `execute_shell` tool.
   The single subprocess entry point ([`adapter.py`](src/sift_mcp/adapter.py))
   runs only an allow-listed set of forensic binaries, never a shell. Destructive
   operations are impossible **by construction**, not by instruction.
2. **Cross-artifact falsification / self-correction** — per candidate finding, a
   corroboration matrix demands agreement across **independent** sources. The
   verdict (CONFIRMED / INFERRED / CONTRADICTED / RETRACTED / UNSUPPORTED) is
   computed by [`falsification.py`](src/sift_mcp/falsification.py); contradictions
   are logged.
3. **Cryptographic provenance** — every tool output is SHA-256 hashed; every
   finding carries a tamper-evident provenance record (tool, exact command,
   evidence file, offset/inode, timestamp, token usage) written to a JSONL
   execution log ([`provenance.py`](src/sift_mcp/provenance.py)).

> Novel contribution (ours): the MCP server design, the falsification engine, and
> the provenance layer are original work for this hackathon. We *wrap* (not
> reimplement) standard SIFT / Sleuth Kit / Eric-Zimmerman tools.

### How this differs from prompt-based discipline

Many AI-DFIR setups keep the agent safe and honest by *telling* it to be — "only
read evidence," "don't over-confirm," "corroborate before you conclude." That is
discipline the model can quietly ignore the moment a prompt is rephrased, an
instruction is forgotten, or context is truncated. Verdict moves those two
properties out of the prompt and into the **architecture**: the read-only
boundary is a closed tool surface the agent *cannot* call past, and the
confirmed-vs-inferred verdict is **computed** from cross-artifact corroboration
rather than declared by the model. This is complementary to human-approval
models — instead of a person gating each action after the fact, the unsafe action
is never expressible and the verdict is a deterministic function of the evidence.

---

## Architecture at a glance

![Verdict system design — a Claude Code agent asks "was this machine hacked?"; the read-only MCP server exposes only typed look-don't-touch tools; the falsification engine confirms a finding only when two or more independent artifacts agree (otherwise INFERRED/RETRACTED); the provenance layer SHA-256-stamps every step into a triage report.](docs/images/system-design.png)

The agent only ever reaches evidence through the read-only MCP server. Findings
pass through the falsification engine (≥ 2 independent sources to confirm) and
the provenance layer before reaching the triage report. Full diagram, trust
boundaries, and the architectural-vs-prompt guardrail breakdown live in
[`docs/architecture.md`](docs/architecture.md).

---

## Quick start (SIFT Workstation, Linux)

```bash
# 1. Clone and enter
git clone <your-fork-url> verdict && cd verdict

# 2. Create a venv and install
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# 3. Configure (copy the example, then edit paths)
cp .env.example .env.local
$EDITOR .env.local          # set EVIDENCE_DIR, LOG_DIR, TOOL_* binary paths

# 4. Sanity check tool availability (prints a capability banner)
python -c "from sift_mcp.config import load_config, startup_check; startup_check(load_config())"

# 5. Run the benchmark (no evidence/API key needed) to generate the accuracy report
python benchmark/harness.py

# 6. Run the unit test suite
pip install pytest && pytest -q
```

### Verify the three pillars in seconds (no evidence/API key)

```bash
# PILLAR 1 — no shell/exec/write tool can exist:
python -c "from sift_mcp.server import READONLY_TOOLS; print(READONLY_TOOLS)"
pytest tests/test_server.py -q

# PILLAR 2 — verdicts are computed, contradictions logged:
pytest tests/test_falsification.py -q
grep -c '"event":"contradiction"' samples/logs/sample_run.jsonl   # >= 1

# PILLAR 3 — tamper-evident provenance:
pytest tests/test_provenance.py -q
```

### Run it live in Claude Code (against evidence)

Copy the `verdict` block from
[`claude_code_config/mcp_config.example.json`](claude_code_config/mcp_config.example.json)
into your Claude Code MCP config (project `.mcp.json` or `~/.claude/mcp.json`),
adjusting `EVIDENCE_DIR`, `LOG_DIR`, and the `TOOL_*` binary paths for your host.
Then start Claude Code — the six read-only tools appear under the `verdict`
server.

Suggested prompts to the agent:

1. "Using only the verdict tools, triage `EVIDENCE_DIR` for signs of malicious
   program execution and persistence."
2. "For each candidate, call `evaluate_findings` and report only the computed
   verdict with its provenance IDs. Do not assert CONFIRMED yourself."
3. *(self-correction beat)* "You flagged `ghost.exe` as executed — verify it
   against prefetch before confirming." → the agent observes `run_count = 0` and
   `evaluate_findings` returns **CONTRADICTED**.

Afterward, every tool execution (hashed), every verdict, and every contradiction
is in `${LOG_DIR}/verdict_run.jsonl`. The agent's final report should contain
**no** CONFIRMED finding lacking ≥ 2 independent provenance IDs.

> The server is **model-agnostic**: the agent model is selected inside Claude
> Code, never by this server.

---

## Configuration

All config is via environment variables (see [`.env.example`](.env.example)).
Nothing is hardcoded.

| Variable | Purpose | Default |
|---|---|---|
| `EVIDENCE_DIR` | Root of mounted/extracted evidence | `./evidence` |
| `LOG_DIR` | Where JSONL execution logs are written | `./logs` |
| `MAX_ITERATIONS` | Hard cap on any agent/tool loop (runaway guard) | `25` |
| `TOOL_PECMD` / `TOOL_MFTECMD` / `TOOL_AMCACHEPARSER` / `TOOL_RECMD` / `TOOL_EVTXECMD` / `TOOL_FLS` / `TOOL_MACTIME` | Swappable forensic binary names/paths | tool names |
| `ANTHROPIC_API_KEY` / `ANTHROPIC_MODEL` | **Optional**, benchmark live-LLM mode only; unused on the default path | unset |

Tool binary names vary across SIFT versions, so every logical tool is
re-pointable via env var. Missing binaries **degrade gracefully** (structured
`unavailable` result), never crash the agent.

---

## Exposed tools (the complete, closed read-only surface)

| Tool | Wraps | Artifact / claim |
|---|---|---|
| `get_prefetch` | PECmd | Prefetch → program execution |
| `get_mft_timeline` | MFTECmd | `$MFT` → filesystem timeline / file existence |
| `get_amcache` | AmcacheParser | Amcache.hve → program presence/execution |
| `get_registry_run_keys` | RECmd | Run/RunOnce → persistence |
| `parse_evtx` | EvtxECmd | Windows Event Logs |
| `evaluate_findings` | *(ours)* | Cross-artifact falsification verdicts |

There is intentionally **no** generic command/shell/write/delete tool. A unit
test (`tests/test_server.py`) asserts the surface never grows one.

---

## Repository layout

```
src/sift_mcp/
  server.py          MCP entrypoint; registers ONLY the read-only tools
  adapter.py         single subprocess gate; allow-listed, no shell (PILLAR 1)
  tools/             one wrapper module per forensic artifact -> typed JSON
  provenance.py      SHA-256 hashing + tamper-evident records + JSONL log (PILLAR 3)
  falsification.py   corroboration matrix; computed verdicts (PILLAR 2)
  config.py          env loading + startup tool-availability check
benchmark/
  harness.py         deterministic replay eval -> generates accuracy_report.md
  baseline.py        naive single-source comparison
  ground_truth/      synthetic scenario + ground-truth labels
tests/               pytest: provenance, config, adapter, tools, falsification, server, benchmark
docs/                architecture (+ images/), devpost draft, dataset, accuracy report (generated)
samples/             committed sample JSONL run + triage output
claude_code_config/  how to register the server with Claude Code
```

## Deliverables

Each SANS "Find Evil!" submission component and where to find it:

| Submission requirement | Where |
|---|---|
| Public code repository (MIT licensed) | this repo · [`LICENSE`](LICENSE) |
| README with setup + local run-against-evidence steps | this README → [Quick start](#quick-start-sift-workstation-linux) and [Run it live](#run-it-live-in-claude-code-against-evidence) |
| Text description (features/functionality) | entered on the Devpost form; draft in [`docs/devpost_description.md`](docs/devpost_description.md) |
| Demonstration video (live terminal, ≥1 self-correction) | YouTube link provided on the Devpost submission |
| Architecture diagram | [`docs/architecture.md`](docs/architecture.md) |
| Evidence dataset documentation | [`docs/dataset.md`](docs/dataset.md) |
| Accuracy report (FPs, missed artifacts, hallucinations, baseline) | [`docs/accuracy_report.md`](docs/accuracy_report.md) *(generated)* |
| Agent execution logs (timestamp, tool, command, evidence ref, token usage, finding id) | [`samples/logs/sample_run.jsonl`](samples/logs/sample_run.jsonl) |

## Testing

```bash
pytest -q      # 86 deterministic tests; no real evidence or network required
```


## License

[MIT](LICENSE).
