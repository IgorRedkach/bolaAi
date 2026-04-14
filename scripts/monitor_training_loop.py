#!/usr/bin/env python3
"""Continuous nonstop training monitor.

Runs forever until the training process completes or exceeds a max-wait threshold.
Checks every 5 minutes. Writes checkpoints to docs/monitor_ledger.jsonl.
If training stops unexpectedly, attempts restart once.

Usage:
  python scripts/monitor_training_loop.py --train-pid <PID>
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HEARTBEAT_PATH = ROOT / "docs" / "retrain_live_heartbeat.json"
ACTIVITY_LOG = ROOT / "docs" / "training_activity_log.jsonl"
MONITOR_LEDGER = ROOT / "docs" / "monitor_ledger.jsonl"
TRAIN_LOG = ROOT / "docs" / "train_3b_run.log"


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S UTC")


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log(msg: str, **kw) -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    extras = "  ".join(f"{k}={v}" for k, v in kw.items())
    print(f"[{ts}] [MONITOR] {msg}  {extras}".rstrip(), flush=True)
    entry = {"ts": _iso(), "msg": msg}
    entry.update(kw)
    MONITOR_LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with MONITOR_LEDGER.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def _read_heartbeat() -> dict:
    try:
        return json.loads(HEARTBEAT_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _proc_alive(pid: int) -> bool:
    return os.path.exists(f"/proc/{pid}")


def _cpu_ticks(pid: int) -> int:
    """Sum CPU ticks across all processes in the process group (parent + threads + children)."""
    total_ticks = 0
    found = False
    # Check parent
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        parts = stat.split()
        total_ticks += int(parts[13]) + int(parts[14])
        found = True
    except Exception:
        pass
    # Check all threads under this PID
    try:
        for tid_path in Path(f"/proc/{pid}/task").iterdir():
            try:
                tstat = (tid_path / "stat").read_text()
                tparts = tstat.split()
                total_ticks += int(tparts[13]) + int(tparts[14])
                found = True
            except Exception:
                pass
    except Exception:
        pass
    # Also check children
    try:
        children_txt = Path(f"/proc/{pid}/task/{pid}/children").read_text().strip()
        for child_pid in children_txt.split():
            try:
                cstat = Path(f"/proc/{child_pid}/stat").read_text()
                cparts = cstat.split()
                total_ticks += int(cparts[13]) + int(cparts[14])
            except Exception:
                pass
    except Exception:
        pass
    return total_ticks if found else -1


def _mem_available_gb() -> float:
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) / 1024 / 1024
    except Exception:
        pass
    return -1.0


def _check_artifacts(run_id: str = "") -> dict:
    """Check training artifacts to determine completion."""
    if run_id:
        # Only look for the current run's artifacts
        candidate = ROOT / "models" / "adapters" / run_id / "training_result.json"
        if candidate.exists():
            try:
                res = json.loads(candidate.read_text())
                return {"found": True, "path": str(candidate), "status": res.get("status", "?"), "loss": res.get("train_metrics", {}).get("train_loss")}
            except Exception:
                return {"found": True, "path": str(candidate), "status": "parse_error"}
        return {"found": False}
    # Fallback: latest any run (old behavior)
    adapters = sorted(ROOT.glob("models/adapters/qlora_*/training_result.json"))
    latest = adapters[-1] if adapters else None
    if latest:
        try:
            res = json.loads(latest.read_text())
            return {"found": True, "path": str(latest), "status": res.get("status", "?"), "loss": res.get("train_metrics", {}).get("train_loss")}
        except Exception:
            return {"found": True, "path": str(latest), "status": "parse_error"}
    return {"found": False}


def _emit_checkpoint(checkpoint_id: str, pid: int, heartbeat: dict, prev_ticks: int, run_id: str = "") -> tuple[str, int]:
    """Run the mandatory checkpoint sequence and return (decision, new_ticks)."""
    # 1. Liveness check
    alive = _proc_alive(pid)
    # 2. Progress signal (CPU ticks)
    curr_ticks = _cpu_ticks(pid) if alive else -1
    tick_delta = curr_ticks - prev_ticks if prev_ticks > 0 and curr_ticks > 0 else -1
    # 3. Artifacts check
    artifacts = _check_artifacts(run_id=run_id)
    # 4. Heartbeat data
    step = heartbeat.get("global_step", 0)
    max_steps = heartbeat.get("max_steps", 540)
    pct = heartbeat.get("pct_done", 0)
    loss = heartbeat.get("loss")
    eta = heartbeat.get("eta_human", "unknown")
    elapsed = heartbeat.get("elapsed_sec", 0)
    mem_gb = _mem_available_gb()

    # 5. Decision
    if artifacts["found"]:
        decision = "completed"
    elif not alive:
        decision = "restart"
    elif tick_delta == 0 and prev_ticks > 0:
        decision = "intervene"  # No CPU progress
    else:
        decision = "continue"

    _log(
        f"CHECKPOINT {checkpoint_id}",
        process_alive=alive,
        cpu_ticks_total=curr_ticks,
        cpu_tick_delta=tick_delta,
        artifact_status="found" if artifacts["found"] else "pending",
        training_result=artifacts.get("path", ""),
        step=f"{step}/{max_steps}",
        pct_done=f"{pct:.1f}%",
        loss=f"{loss:.4f}" if isinstance(loss, float) else str(loss),
        eta=eta,
        elapsed_min=f"{elapsed/60:.0f}m",
        mem_available_gb=f"{mem_gb:.1f}",
        decision=decision,
    )
    return decision, curr_ticks


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--train-pid", type=int, required=True, help="PID of the training process to monitor")
    parser.add_argument("--run-id", default="", help="Training run_id to check for artifacts (e.g. qlora_20260410T145439Z)")
    parser.add_argument("--check-interval-sec", type=int, default=300, help="Seconds between checks (default 5 min)")
    parser.add_argument("--max-wait-hours", type=float, default=72, help="Max hours to wait (default 3 days)")
    parser.add_argument("--restart-cmd", default="", help="Command to restart training if it dies (optional)")
    args = parser.parse_args()

    pid = args.train_pid
    max_wait_sec = args.max_wait_hours * 3600
    start = time.time()
    checkpoint_num = 0
    prev_ticks = _cpu_ticks(pid)
    restarted = False

    _log(f"Monitor started for PID {pid}", interval_sec=args.check_interval_sec, max_wait_hours=args.max_wait_hours)

    while True:
        elapsed_total = time.time() - start
        if elapsed_total > max_wait_sec:
            _log(f"MAX WAIT EXCEEDED ({args.max_wait_hours}h). Stopping monitor.")
            return 1

        time.sleep(args.check_interval_sec)

        checkpoint_num += 1
        heartbeat = _read_heartbeat()
        run_id = args.run_id or heartbeat.get("run_id", "")
        cid = f"MON-{checkpoint_num:04d}"
        decision, new_ticks = _emit_checkpoint(cid, pid, heartbeat, prev_ticks, run_id=run_id)
        prev_ticks = new_ticks if new_ticks > 0 else prev_ticks

        if decision == "completed":
            _log("Training COMPLETED. Artifacts verified.")
            return 0

        if decision == "restart":
            if restarted:
                _log("Process died AGAIN after restart. Giving up.")
                return 2
            if args.restart_cmd:
                _log("Process died. Attempting restart...")
                subprocess.Popen(shlex.split(args.restart_cmd), cwd=str(ROOT))
                time.sleep(30)
                # Find new PID
                pids = subprocess.run(["pgrep", "-f", "train_qlora_unsloth"], capture_output=True, text=True)
                if pids.returncode == 0 and pids.stdout.strip():
                    pid = int(pids.stdout.strip().split()[-1])
                    _log(f"Restarted training at new PID {pid}")
                    restarted = True
                else:
                    _log("Could not find restarted process. Giving up.")
                    return 3
            else:
                _log("Process died and no restart command provided. Manual restart needed.")
                return 4

        if decision == "intervene":
            _log("WARNING: No CPU progress detected. Process may be stuck (waiting for IO/swap).")
            _log("Continuing watch — will flag again if persists next checkpoint.")
            # For CPU training, this can happen due to heavy swap I/O. Don't restart.


if __name__ == "__main__":
    raise SystemExit(main())
