# Architecture & Trust Boundaries

Verdict sits between a Claude Code agent and the SIFT Workstation's forensic
tooling. It is deliberately the *only* path from the agent to the underlying
system, and that path is read-only by construction.

## System design

![Verdict system design — Claude Code agent asks "was this machine hacked?", the read-only MCP server exposes only typed look-don't-touch tools, the falsification engine computes CONFIRMED/INFERRED/RETRACTED verdicts, and the provenance layer produces a tamper-evident triage report.](images/system-design.png)

The agent only ever reaches evidence through the read-only MCP server. Findings
flow through the falsification engine (≥ 2 independent sources to confirm) and
the provenance layer before reaching the triage report.

### Detailed architecture & trust boundaries

![Detailed Verdict architecture showing Trust Boundary 1 (MCP stdio, typed tool calls only) at server.py, Trust Boundary 2 (single subprocess gate) at adapter.py, the read-only tool wrappers, the falsification corroboration matrix, the provenance/JSONL layer, and read-only SIFT Workstation evidence — each architectural guardrail labeled.](images/architecture-trust-boundaries.png)

<details>
<summary>Mermaid source for the diagram above</summary>

```mermaid
flowchart TB
    subgraph AGENT["Claude Code Agent (model chosen in Claude Code)"]
        LLM["LLM reasoning loop<br/>(MAX_ITERATIONS cap)"]
    end

    subgraph TB1["TRUST BOUNDARY 1 — MCP stdio (typed tool calls only)"]
        SRV["server.py<br/>registers ONLY the closed read-only tool set<br/>(ARCHITECTURAL guardrail)"]
    end

    subgraph VERDICT["Verdict MCP Server (our novel contribution)"]
        TOOLS["tools/*<br/>get_prefetch · get_mft_timeline · get_amcache<br/>get_registry_run_keys · parse_evtx"]
        FALS["falsification.py<br/>corroboration matrix → computed verdict<br/>(ARCHITECTURAL guardrail)"]
        PROV["provenance.py<br/>SHA-256 + tamper-evident records + JSONL log"]
        CFG["config.py<br/>env + tool availability"]
    end

    subgraph TB2["TRUST BOUNDARY 2 — single subprocess gate"]
        ADP["adapter.py<br/>allow-listed binaries only · no shell · argv list<br/>(ARCHITECTURAL guardrail)"]
    end

    subgraph SIFT["SIFT Workstation (read-only evidence)"]
        BINS["PECmd · MFTECmd · AmcacheParser<br/>RECmd · EvtxECmd · fls/mactime"]
        EVID[("Evidence: $MFT, hives,<br/>.evtx, prefetch<br/>(mounted read-only)")]
    end

    LLM -->|"typed call"| SRV
    SRV --> TOOLS
    SRV --> FALS
    TOOLS --> ADP
    TOOLS --> PROV
    FALS --> PROV
    ADP -->|"exec, read-only"| BINS
    BINS -->|"parse"| EVID
    PROV -->|"append"| LOG[("/logs/*.jsonl<br/>execution log")]
    FALS -->|"verdict + contradictions"| LOG

    classDef boundary fill:#fff3cd,stroke:#d39e00,stroke-width:2px;
    classDef ours fill:#d1ecf1,stroke:#0c5460,stroke-width:2px;
    class TB1,TB2 boundary;
    class TOOLS,FALS,PROV,CFG,ADP,SRV ours;
```

</details>

## Trust boundaries

| # | Boundary | What crosses it | Enforcement |
|---|----------|-----------------|-------------|
| 1 | Agent ↔ MCP server (stdio) | Only typed calls to the closed tool set in `READONLY_TOOLS` | **Architectural** — the server registers nothing else; `_assert_readonly_surface()` refuses to start if a forbidden tool name appears |
| 2 | Server ↔ operating system | Only allow-listed forensic binaries, as an argv list, `shell=False` | **Architectural** — `adapter.py` is the sole `subprocess` call site; non-allow-listed logical names raise before any process spawns |
| 3 | Server ↔ evidence | Read-only parsing only | **Architectural + operational** — wrappers only ever read; evidence should be mounted read-only on SIFT |

## Architectural vs prompt-based guardrails

This is the distinction the rubric asks us to be explicit about.

| Guardrail | Type | Why |
|-----------|------|-----|
| No shell/exec/write/delete tool exists | **Architectural** | The agent *cannot* call what is not registered. Not a request — a structural impossibility. |
| Subprocess allow-list, no shell, argv-only | **Architectural** | Enforced in code (`adapter.ALLOWED_TOOLS`, `shell=False`); shell metacharacters are inert data. |
| CONFIRMED requires ≥2 independent sources | **Architectural** | Verdicts are *computed* by `evaluate_claim`, not produced by the model's say-so. The model cannot mark something CONFIRMED. |
| Tamper-evident provenance on every output | **Architectural** | `record_id` is a hash of the record; `verify_record` detects mutation. |
| `MAX_ITERATIONS` runaway cap | **Architectural** | Enforced by the harness/agent loop, from config. |
| "Prefer corroborated findings; explain uncertainty" | **Prompt-based** | Helpful guidance to the agent, but *not* relied upon for safety — the architecture already enforces the outcome. |

The design principle: **safety-critical properties are architectural; prompt
guidance is only an ergonomic layer on top.** If the prompt were adversarially
ignored, the read-only and corroboration guarantees still hold.

## Data flow for a single finding

1. Agent calls `get_prefetch` / `get_amcache` / … → `adapter.py` runs the
   allow-listed binary read-only, captures + SHA-256 hashes the output, writes a
   provenance record to the JSONL log.
2. Wrapper normalizes the CSV into typed records tagged with `source_artifact`
   and `claim_type`.
3. Agent passes the collected outputs to `evaluate_findings`.
4. `falsification.py` builds cross-artifact claims (matching subjects across
   independent artifacts), computes a verdict, and logs the verdict + any
   contradiction.
5. Every reported finding is traceable through provenance IDs back to the exact
   tool execution that produced its evidence.
