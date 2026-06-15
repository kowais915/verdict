"""Verdict — a read-only MCP server exposing SIFT forensic tools to Claude Code.

Novel contribution (ours):
  1. Architectural read-only enforcement — only typed read-only forensic
     functions are exposed; no generic shell/execute tool exists by construction.
  2. Cross-artifact falsification engine — findings are CONFIRMED only when
     corroborated by >= 2 independent forensic sources; otherwise downgraded to
     INFERRED or RETRACTED, with contradictions logged.
  3. Cryptographic provenance — every tool output is SHA-256 hashed and every
     finding carries a full provenance record traceable to a tool execution.
"""

__version__ = "0.1.0"
