#!/bin/sh
# Check memory of Python processes (BOLA AI tool, agent, etc.). Run regularly to prevent runaway.
# If any Python process exceeds 10 GB (tool limit) or 6 GB (agent limit), consider killing it.
# Usage: sh scripts/check_memory.sh [interval_seconds]
#   With no args: print once. With interval (e.g. 2): loop every 2 seconds.

interval="${1:-0}"

report() {
    echo "--- $(date '+%H:%M:%S') ---"
    if [ -r /proc/meminfo ]; then
        awk '/MemTotal/ { t=$2/1024; } /MemAvailable/ { a=$2/1024; } END { printf "System: %.0f MB total, %.0f MB available\n", t, a }' /proc/meminfo
    fi
    echo "Python processes (RSS MB, PID, command):"
    ps -eo rss,pid,args --no-headers 2>/dev/null | awk '/[p]ython|[u]vicorn/ {
        rss_mb=$1/1024; pid=$2; $1=""; $2=""; cmd=$0;
        if (rss_mb >= 1024) printf "  %.0f MB  %s  %s\n", rss_mb, pid, cmd;
        else printf "  %.1f MB  %s  %s\n", rss_mb, pid, cmd;
    }' | head -20
    echo "Target: tool <= 10 GB, agent/IDE <= 6 GB. Kill if exceeded."
}

if [ "$interval" -gt 0 ] 2>/dev/null; then
    while true; do report; sleep "$interval"; done
else
    report
fi
