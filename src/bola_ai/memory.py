"""Memory measurement (process RSS and optional system). Stdlib-only where possible."""

import resource
import sys
from pathlib import Path


def get_process_rss_mb() -> float:
    """Current process RSS in MB. Uses resource on Unix; fallback 0 on Windows."""
    try:
        # Linux: maxrss is in KB
        usage = resource.getrusage(resource.RUSAGE_SELF)
        rss_kb = getattr(usage, "ru_maxrss", 0)
        if sys.platform == "darwin":
            # macOS reports in bytes
            return rss_kb / (1024 * 1024)
        return rss_kb / 1024
    except Exception:
        return 0.0


def get_process_rss_from_proc_mb() -> float | None:
    """Current process RSS in MB from /proc/self/status (Linux). Returns None if not available."""
    try:
        status = Path("/proc/self/status").read_text()
        for line in status.splitlines():
            if line.startswith("VmRSS:"):
                parts = line.split()
                if len(parts) >= 2:
                    val = int(parts[1])
                    unit = parts[2].upper() if len(parts) > 2 else "KB"
                    if unit == "KB":
                        return val / 1024
                    if unit == "MB":
                        return float(val)
                return None
    except Exception:
        pass
    return None


def log_memory(logger, label: str) -> None:
    """Log current process RSS if BOLA_AI_LOG_MEMORY is set. Call at each step."""
    import os
    if os.environ.get("BOLA_AI_LOG_MEMORY", "").lower() not in ("1", "true", "yes"):
        return
    rss_proc = get_process_rss_from_proc_mb()
    if rss_proc is None:
        rss_proc = get_process_rss_mb()
    logger.info("[memory] %s: process RSS %.2f MB", label, rss_proc or 0)
