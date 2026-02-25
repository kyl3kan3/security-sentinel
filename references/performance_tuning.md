# Performance Tuning

If the daemon is using excessive CPU or RAM on a Pi, apply these tweaks.

## Quick Fixes

**Increase poll intervals** (edit `/usr/local/bin/sentinel_daemon.py`):
```python
POLL_PROCESS  = 30   # was 10
POLL_PORTS    = 60   # was 15
POLL_NETWORK  = 120  # was 30
POLL_DOCKER   = 60   # was 20
POLL_RESOURCES = 300 # was 60
```

**Reduce watched directories** (remove low-value paths from WATCH_DIRS):
```python
WATCH_DIRS = ["/etc", "/root"]  # minimal set
```

**Disable Docker monitoring** if not using Docker:
Comment out the Docker thread in `main()`.

## Expected Resource Usage (Pi 5)

| Config | CPU (idle) | RAM |
|--------|-----------|-----|
| Default | 1-3% | ~45MB |
| Minimal | <1% | ~30MB |
| Full (all monitors active) | 2-5% | ~60MB |

The filesystem monitor (inotifywait) is the most efficient — it's kernel-driven, not polling.
The process monitor is the heaviest — increase POLL_PROCESS first if needed.
