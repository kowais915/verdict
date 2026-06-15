"""Read-only forensic tool wrappers (one module per artifact type).

Each wrapper invokes an allow-listed SIFT/Sleuth Kit/Eric-Zimmerman-style
binary read-only, returns structured JSON, and degrades gracefully when the
binary is absent. Modules added in PHASE 3:

    prefetch.py        get_prefetch
    mft_timeline.py    get_mft_timeline
    amcache.py         get_amcache
    registry_run.py    get_registry_run_keys
    evtx.py            parse_evtx
"""
