# Verdict — Read-Only Forensic MCP Server with Falsification & Provenance

> A SANS *"Find Evil!"* hackathon submission. A custom, **read-only** Model
> Context Protocol (MCP) server that exposes SIFT Workstation forensic tools as
> typed, structured functions to a [Claude Code](https://claude.com/claude-code)
> agent — plus a **falsification-driven self-correction layer** that forces the
> agent to disprove its own findings before reporting them.

## Headline behavior

The agent refuses to label a finding **CONFIRMED** unless it is corroborated by
**≥ 2 independent forensic artifact sources**. Otherwise it downgrades the
finding to **INFERRED** or **RETRACTED**, and logs the contradiction. The
verdict is *computed*, never asserted.

## Three pillars

1. **Architectural read-only enforcement** — only read-only typed functions are
   exposed (`get_prefetch`, `get_mft_timeline`, `get_amcache`,
   `get_registry_run_keys`, `parse_evtx`, …). There is **no** generic
   `execute_shell` tool. Destructive operations are impossible *by construction*.
2. **Cross-artifact falsification / self-correction** — per candidate finding, a
   corroboration matrix demands agreement across independent sources.
3. **Cryptographic provenance** — every tool output is SHA-256 hashed; every
   finding carries a provenance record (tool, exact command, evidence file,
   offset/inode, timestamp, token usage).

## Status

🚧 Under active construction (phased build). See the phase checkpoints in the
project brief. This README is filled out fully in **PHASE 7**.

## Repository layout

```
src/sift_mcp/      MCP server, tool wrappers, provenance, falsification, config
benchmark/         eval harness + naive baseline + ground truth
tests/             pytest (falsification logic + provenance hashing)
docs/              architecture, demo script, devpost, dataset, accuracy report
samples/           committed sample run logs + triage output
claude_code_config/ how to register this server with Claude Code
```

## License

[MIT](LICENSE).
