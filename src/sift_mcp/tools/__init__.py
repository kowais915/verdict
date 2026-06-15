"""Read-only forensic tool wrappers (one module per artifact type).

Each wrapper invokes an allow-listed SIFT/Sleuth Kit/Eric-Zimmerman-style
binary read-only (via :mod:`sift_mcp.adapter`), returns structured JSON records
plus a provenance record, and degrades gracefully when the binary is absent.

Public surface:
    get_prefetch            (prefetch.py)      program execution
    get_mft_timeline        (mft_timeline.py)  filesystem timeline / file existence
    get_amcache             (amcache.py)       program presence/execution
    get_registry_run_keys   (registry_run_keys.py) autostart persistence
    parse_evtx              (evtx.py)          Windows event logs
"""

from ._common import ArtifactResult
from .amcache import get_amcache, parse_amcache_csv
from .evtx import parse_evtx, parse_evtx_csv
from .mft_timeline import get_mft_timeline, parse_mft_csv
from .prefetch import get_prefetch, parse_prefetch_csv
from .registry_run_keys import RUN_KEY_PATHS, get_registry_run_keys, parse_run_keys_csv

__all__ = [
    "ArtifactResult",
    "get_prefetch",
    "parse_prefetch_csv",
    "get_mft_timeline",
    "parse_mft_csv",
    "get_amcache",
    "parse_amcache_csv",
    "get_registry_run_keys",
    "parse_run_keys_csv",
    "RUN_KEY_PATHS",
    "parse_evtx",
    "parse_evtx_csv",
]
