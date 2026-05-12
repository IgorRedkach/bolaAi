#!/usr/bin/env python3
"""Memory guard: monitors system RAM and kills a target PID if available RAM drops below threshold.

Usage:
    python scripts/mem_guard.py --pid <TRAINING_PID> --min-avail-gb 2.0 --log logs/mem_guard.log
"""
from __future__ import annotations
import argparse
import json
import os
import signal
import time
from datetime import datetime, timezone
from pathlib import Path


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _read_meminfo() -> dict[str, int]:
    """Return selected /proc/meminfo fields in kB."""
    data: dict[str, int] = {}
    with open("/proc/meminfo") as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 2:
                key = parts[0].rstrip(":")
                try:
                    data[key] = int(parts[1])
                except ValueError:
                    pass
    return data


def _process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # process exists but we can't signal it


def main() -> None:
    parser = argparse.ArgumentParser(description="RAM guard for training processes")
    parser.add_argument("--pid", type=int, required=True, help="PID of training process to watch")
    parser.add_argument("--min-avail-gb", type=float, default=2.0,
                        help="Kill training if available RAM drops below this (default 2.0 GB)")
    parser.add_argument("--interval", type=float, default=10.0,
                        help="Check interval in seconds (default 10)")
    parser.add_argument("--log", default="logs/mem_guard.log",
                        help="Log file path")
    args = parser.parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    min_avail_kb = int(args.min_avail_gb * 1024 * 1024)

    def _log(msg: str, level: str = "INFO") -> None:
        line = f"[{_now()}] [{level}] {msg}"
        print(line, flush=True)
        with log_path.open("a") as f:
            f.write(line + "\n")

    _log(f"Memory guard started — watching PID {args.pid}, min_avail={args.min_avail_gb:.1f} GB, interval={args.interval}s")

    check_num = 0
    while True:
        time.sleep(args.interval)
        check_num += 1

        if not _process_alive(args.pid):
            _log(f"PID {args.pid} no longer alive — guard exiting normally.")
            break

        mem = _read_meminfo()
        total_kb = mem.get("MemTotal", 0)
        avail_kb = mem.get("MemAvailable", 0)
        used_kb = total_kb - avail_kb
        swap_used_kb = mem.get("SwapTotal", 0) - mem.get("SwapFree", 0)

        avail_gb = avail_kb / 1024 / 1024
        used_gb = used_kb / 1024 / 1024
        swap_gb = swap_used_kb / 1024 / 1024
        total_gb = total_kb / 1024 / 1024

        status = {
            "check": check_num,
            "pid": args.pid,
            "avail_gb": round(avail_gb, 2),
            "used_gb": round(used_gb, 2),
            "total_gb": round(total_gb, 2),
            "swap_used_gb": round(swap_gb, 2),
        }

        if check_num % 6 == 0:  # full status every minute
            _log(f"RAM: {used_gb:.1f}/{total_gb:.1f} GB used | avail={avail_gb:.2f} GB | swap={swap_gb:.1f} GB")

        if avail_kb < min_avail_kb:
            _log(
                f"CRITICAL: available RAM {avail_gb:.2f} GB < threshold {args.min_avail_gb:.1f} GB. "
                f"Sending SIGTERM to PID {args.pid} to prevent OOM kill.",
                level="WARN",
            )
            try:
                os.kill(args.pid, signal.SIGTERM)
            except ProcessLookupError:
                _log(f"PID {args.pid} already gone.", level="WARN")
            time.sleep(5)
            if _process_alive(args.pid):
                _log(f"PID {args.pid} still alive after SIGTERM, sending SIGKILL.", level="WARN")
                try:
                    os.kill(args.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            _log("Training process terminated by memory guard. Training can be resumed with --resume latest.")
            break

        # Warn if getting close
        warn_threshold_kb = int(min_avail_kb * 1.5)
        if avail_kb < warn_threshold_kb:
            _log(f"WARNING: available RAM {avail_gb:.2f} GB approaching threshold {args.min_avail_gb:.1f} GB")


if __name__ == "__main__":
    main()
