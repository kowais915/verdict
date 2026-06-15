# Dataset Documentation

Verdict is evaluated two ways: (1) a **bundled synthetic scenario** used for the
reproducible accuracy report, and (2) **real public evidence** the wrappers are
designed for on a SIFT Workstation.

## 1. Bundled deterministic scenario (committed)

- **File:** [`benchmark/ground_truth/scenario_findevil.json`](../benchmark/ground_truth/scenario_findevil.json)
- **Source:** authored by us. It is *synthetic* — the records have the exact
  normalized shape the Phase-3 wrappers emit (PECmd/MFTECmd/AmcacheParser/RECmd/
  EvtxECmd), so the falsification engine and benchmark run identically with or
  without real binaries. This is what makes the accuracy report reproducible on
  any machine with no disk image and no API key.
- **Why synthetic:** it deterministically exercises *every* verdict path,
  including a planted contradiction that a single-source tool gets wrong. Real
  images are large, license-encumbered, and non-deterministic.

### Ground-truth findings

| Claim | Malicious? | Evidence in scenario | Expected verdict | Why |
|---|---|---|---|---|
| `program_execution:beacon.exe` | ✅ yes | prefetch (run 5) + amcache + EVTX 4688 | **CONFIRMED** | 3 independent sources agree |
| `persistence:beacon.exe` | ✅ yes | Run key + execution of same binary | **CONFIRMED** | autostart corroborated by execution |
| `file_existence:beacon.exe` | ✅ yes | MFT + amcache + prefetch | **CONFIRMED** | present and executed |
| `program_execution:evil2.exe` | ✅ yes | amcache only | **INFERRED** | genuinely single-source → honestly not confirmed |
| `program_execution:ghost.exe` | ❌ no | amcache present **but** prefetch run_count = 0 | **CONTRADICTED** | file present, never executed |
| `program_execution:chrome.exe` | ❌ no | prefetch only | **INFERRED** | benign, single source |
| `program_execution:calc.exe` | ❌ no | amcache only | **INFERRED** | benign, single source |
| `persistence:onedrive.exe` | ❌ no | Run key only, legit binary | **INFERRED** | legitimate autostart |

### Results on this dataset (see generated report)

| | Verdict | Naive baseline |
|---|---|---|
| Precision (CONFIRMED) | **100%** | 50% |
| Recall (CONFIRMED) | 75% | 100% |
| F1 | **85.7%** | 66.7% |
| False positives | **0** | 4 |
| Hallucinations | 0 | 0 |

Full, timestamped numbers: [`docs/accuracy_report.md`](accuracy_report.md)
(regenerate with `python benchmark/harness.py`).

## 2. Recommended real evidence (for live SIFT demos)

The wrappers target standard Windows artifacts. Suggested public sources:

- **Eric Zimmerman's sample data** (prefetch, Amcache, registry hives, EVTX) —
  ideal for exercising each wrapper individually.
- **DFIR public images / CTF artifacts** (e.g. AboutDFIR, Digital Corpora,
  past SANS/DFIR challenge images) — mount **read-only**, then point
  `EVIDENCE_DIR` and the `TOOL_*` paths at the extracted artifacts and the
  installed binaries.

> Evidence files are **never committed** to this repo (`.gitignore` excludes
> `*.E01`, `*.raw`, `*.dd`, `*.vmdk`, and `/evidence/`). Provide your own and set
> `EVIDENCE_DIR`.

### Expected artifact → tool → claim mapping

| Artifact on disk | Wrapper | Claim type |
|---|---|---|
| `C:\Windows\Prefetch\*.pf` | `get_prefetch` | program_execution |
| `$MFT` | `get_mft_timeline` | file_existence |
| `C:\Windows\AppCompat\Programs\Amcache.hve` | `get_amcache` | program_execution |
| `SOFTWARE` / `NTUSER.DAT` hives | `get_registry_run_keys` | persistence |
| `*.evtx` (Security, System) | `parse_evtx` | event_log (4688/7045/4624…) |

## Reproducing

```bash
python benchmark/harness.py     # regenerates docs/accuracy_report.md + samples/
pytest -q                       # 86 deterministic tests
```
