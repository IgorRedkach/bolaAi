#!/usr/bin/env python3
"""Run tracked retraining/evaluation cycles with explicit quality gates.

This script is intentionally strict and writes a checkpoint file after each cycle
so progress is observable and resumable.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import shlex
import subprocess
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "docs"

# Fixed training model — no fallback, no downgrade allowed.
TRAINING_MODEL = "Qwen/Qwen2.5-Coder-3B-Instruct"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _run(
    cmd: list[str],
    *,
    allow_fail: bool = False,
    timeout_sec: int = 0,
    low_mem_kill_mb: int = 0,
    heartbeat_path: Path | None = None,
    stage_label: str = "",
) -> tuple[int, str, bool]:
    printable = " ".join(shlex.quote(c) for c in cmd)
    print(f"$ {printable}")
    timed_out = False
    proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    low_mem_killed = False
    stdout = ""
    stderr = ""
    waited = 0
    step = 5
    def _to_text(value: str | bytes | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value

    while True:
        try:
            out_part, err_part = proc.communicate(timeout=step)
            stdout += _to_text(out_part)
            stderr += _to_text(err_part)
            rc = proc.returncode
            break
        except subprocess.TimeoutExpired as exc:
            stdout += _to_text(exc.stdout)
            stderr += _to_text(exc.stderr)
            waited += step
            if heartbeat_path is not None:
                _write_json(
                    heartbeat_path,
                    {
                        "updated_at": _utc_now(),
                        "stage": stage_label or "running",
                        "waited_sec": waited,
                        "command": printable,
                        "mem_available_mb": _mem_available_mb(),
                    },
                )
            if low_mem_kill_mb > 0:
                mem_avail = _mem_available_mb()
                if mem_avail > 0 and mem_avail < low_mem_kill_mb:
                    low_mem_killed = True
            if low_mem_killed or (timeout_sec > 0 and waited >= timeout_sec):
                timed_out = not low_mem_killed
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                out_tail, err_tail = proc.communicate()
                stdout += _to_text(out_tail)
                stderr += _to_text(err_tail)
                rc = 137 if low_mem_killed else 124
                break
    if low_mem_killed:
        stderr += "\n[runner] terminated stage due to low-memory guard.\n"
    combined = (stdout or "") + ("\n" if stdout and stderr else "") + (stderr or "")
    if rc != 0 and not allow_fail:
        raise RuntimeError(f"Command failed ({rc}): {printable}\n{combined}")
    return rc, combined, timed_out


def _mem_available_mb() -> int:
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    kb = int(line.split()[1])
                    return kb // 1024
    except Exception:
        pass
    return -1


def _looks_like_oom(log_text: str) -> bool:
    low = (log_text or "").lower()
    markers = (
        "out of memory",
        "cuda out of memory",
        "oom",
        "memoryerror",
        "killed",
        "cannot allocate memory",
    )
    return any(m in low for m in markers)



def _latest_eval_report() -> Path | None:
    candidates = sorted((ROOT / "docs" / "eval_reports").glob("model_eval_*.json"))
    return candidates[-1] if candidates else None


def _load_eval_metrics(report_path: str) -> dict:
    """Load metrics dict from an eval report JSON file; return {} on failure."""
    try:
        if not report_path:
            return {}
        data = json.loads(Path(report_path).read_text(encoding="utf-8"))
        return data.get("metrics", {})
    except Exception:
        return {}


def _compute_regression_delta(
    prev_metrics: dict, curr_metrics: dict
) -> tuple[bool, str]:
    """Compare current cycle metrics against previous cycle.

    Returns (regression_detected, description).
    A regression is flagged when any primary metric decreases by > 0.02.
    """
    if not prev_metrics or not curr_metrics:
        return False, "no previous metrics to compare"
    regressions = []
    improvements = []
    primary = [
        "groundedness_rate",
        "tool_call_correctness_rate",
        "actionable_finding_rate",
        "severity_weighted_recall",
        "cohens_kappa",
    ]
    for key in primary:
        prev_val = prev_metrics.get(key)
        curr_val = curr_metrics.get(key)
        if prev_val is None or curr_val is None:
            continue
        delta = curr_val - prev_val
        if delta < -0.02:
            regressions.append(f"{key}: {prev_val:.4f} -> {curr_val:.4f} (Δ{delta:+.4f})")
        elif delta > 0.005:
            improvements.append(f"{key}: {prev_val:.4f} -> {curr_val:.4f} (Δ{delta:+.4f})")
    desc_parts = []
    if regressions:
        desc_parts.append("REGRESSIONS: " + "; ".join(regressions))
    if improvements:
        desc_parts.append("improvements: " + "; ".join(improvements))
    if not desc_parts:
        desc_parts.append("metrics stable (no significant change vs previous cycle)")
    return bool(regressions), " | ".join(desc_parts)


def _bool_gate(log_text: str, marker: str) -> bool:
    return marker.lower() in (log_text or "").lower()


@dataclass
class CycleResult:
    cycle_index: int
    started_at: str
    ended_at: str
    regenerate_data_ok: bool
    retrain_ok: bool
    eval_ok: bool
    e2e_ok: bool
    manual_tests_ok: bool
    self_comparison_ok: bool
    all_gates_ok: bool
    eval_report_path: str
    eval_metrics: dict
    regression_detected: bool
    regression_delta: str
    selected_base_model: str
    notes: str


def _run_cycle(
    cycle_index: int,
    base_url: str,
    track: str,
    max_steps: int,
    max_train_samples: int,
    max_train_token_chunks: int,
    max_valid_token_chunks: int,
    chunk_size_tokens: int,
    chunk_overlap_tokens: int,
    retrain_timeout_sec: int,
    e2e_timeout_sec: int,
    manual_timeout_sec: int,
    self_comparison_timeout_sec: int,
    low_mem_kill_mb: int,
    heartbeat_path: Path | None,
    prev_eval_metrics: dict | None = None,
) -> CycleResult:
    started = _utc_now()
    notes: list[str] = []

    rc, out, _ = _run(
        ["python", "src/training/generate_data.py"],
        allow_fail=True,
        low_mem_kill_mb=low_mem_kill_mb,
        heartbeat_path=heartbeat_path,
        stage_label=f"cycle_{cycle_index}:regenerate_data",
    )
    regenerate_ok = rc == 0
    if not regenerate_ok:
        notes.append("data regeneration failed")

    retrain_ok = False
    selected_model = TRAINING_MODEL
    if regenerate_ok:
        retrain_cmd = [
            "python",
            "scripts/run_training_refactor_cycle.py",
            "--track",
            track,
            "--base-model",
            TRAINING_MODEL,
            "--max-steps",
            str(max_steps),
            "--max-train-samples",
            str(max_train_samples),
            "--chunk-size-tokens",
            str(chunk_size_tokens),
            "--chunk-overlap-tokens",
            str(chunk_overlap_tokens),
        ]
        if max_train_token_chunks > 0:
            retrain_cmd.extend(["--max-train-token-chunks", str(max_train_token_chunks)])
        if max_valid_token_chunks > 0:
            retrain_cmd.extend(["--max-valid-token-chunks", str(max_valid_token_chunks)])
        rc, out, timed_out = _run(
            retrain_cmd,
            allow_fail=True,
            timeout_sec=retrain_timeout_sec,
            low_mem_kill_mb=low_mem_kill_mb,
            heartbeat_path=heartbeat_path,
            stage_label=f"cycle_{cycle_index}:retrain:{TRAINING_MODEL}",
        )
        retrain_ok = rc == 0
        if retrain_ok:
            notes.append(f"retrain succeeded: {TRAINING_MODEL}")
        else:
            reason = "timeout" if timed_out else ("oom" if _looks_like_oom(out) else "failure")
            notes.append(f"retrain {reason}: {TRAINING_MODEL}")

    eval_ok = False
    eval_report = ""
    eval_metrics: dict = {}
    regression_detected = False
    regression_delta = "no eval run"
    if retrain_ok:
        rc, out, _ = _run(
            ["python", "scripts/eval_security_agent_model.py"],
            allow_fail=True,
            low_mem_kill_mb=low_mem_kill_mb,
            heartbeat_path=heartbeat_path,
            stage_label=f"cycle_{cycle_index}:eval",
        )
        eval_ok = rc == 0
        latest = _latest_eval_report()
        eval_report = str(latest) if latest else ""
        eval_metrics = _load_eval_metrics(eval_report)
        regression_detected, regression_delta = _compute_regression_delta(
            prev_eval_metrics or {}, eval_metrics
        )
        if regression_detected:
            notes.append(f"regression detected vs previous cycle: {regression_delta}")
        if not eval_ok:
            notes.append("eval script failed")

    e2e_ok = False
    if eval_ok:
        rc, out, timed_out = _run(
            ["python", "scripts/run_agent_e2e_loop_once.py", base_url],
            allow_fail=True,
            timeout_sec=e2e_timeout_sec,
            low_mem_kill_mb=low_mem_kill_mb,
            heartbeat_path=heartbeat_path,
            stage_label=f"cycle_{cycle_index}:e2e",
        )
        e2e_ok = rc == 0 and not _bool_gate(out, "LOGICAL CORRECTNESS FAILURES")
        if not e2e_ok:
            notes.append("e2e timeout" if timed_out else "e2e logical checks failed")

    manual_ok = False
    if e2e_ok:
        rc, out, timed_out = _run(
            ["python", "scripts/run_manual_test_cases.py", "--base-url", base_url, "--max-cases", "4"],
            allow_fail=True,
            timeout_sec=manual_timeout_sec,
            low_mem_kill_mb=low_mem_kill_mb,
            heartbeat_path=heartbeat_path,
            stage_label=f"cycle_{cycle_index}:manual_tests",
        )
        manual_ok = rc == 0 and ("ALL PASS" in out or "[PASS]" in out)
        if not manual_ok:
            notes.append("manual test timeout" if timed_out else "manual fixture tests failed")

    # Self-comparison stage: agent generates own analysis and compares to tool output.
    self_comparison_ok = False
    if manual_ok:
        rc, out, timed_out = _run(
            ["python", "scripts/run_self_comparison_test.py", "--base-url", base_url],
            allow_fail=True,
            timeout_sec=self_comparison_timeout_sec,
            low_mem_kill_mb=low_mem_kill_mb,
            heartbeat_path=heartbeat_path,
            stage_label=f"cycle_{cycle_index}:self_comparison",
        )
        self_comparison_ok = rc == 0
        if not self_comparison_ok:
            notes.append("self-comparison timeout" if timed_out else "self-comparison critical discrepancies exceeded threshold")

    all_ok = regenerate_ok and retrain_ok and eval_ok and e2e_ok and manual_ok and self_comparison_ok
    ended = _utc_now()
    return CycleResult(
        cycle_index=cycle_index,
        started_at=started,
        ended_at=ended,
        regenerate_data_ok=regenerate_ok,
        retrain_ok=retrain_ok,
        eval_ok=eval_ok,
        e2e_ok=e2e_ok,
        manual_tests_ok=manual_ok,
        self_comparison_ok=self_comparison_ok,
        all_gates_ok=all_ok,
        eval_report_path=eval_report,
        eval_metrics=eval_metrics,
        regression_detected=regression_detected,
        regression_delta=regression_delta,
        selected_base_model=selected_model,
        notes="; ".join(notes) if notes else "all checks passed",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run tracked retraining loop until 3 consecutive quality passes.")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--max-cycles", type=int, default=9)
    parser.add_argument("--required-consecutive-passes", type=int, default=3)
    parser.add_argument("--track", choices=["qlora", "lora16", "both"], default="lora16")
    parser.add_argument("--retrain-timeout-sec", type=int, default=14400, help="Timeout for retrain (default 4 h for 3B model)")
    parser.add_argument("--e2e-timeout-sec", type=int, default=1800, help="Timeout for E2E stage command")
    parser.add_argument("--manual-timeout-sec", type=int, default=1200, help="Timeout for manual test stage command")
    parser.add_argument("--self-comparison-timeout-sec", type=int, default=1800, help="Timeout for self-comparison stage")
    parser.add_argument("--low-mem-kill-mb", type=int, default=2000, help="Kill stage when MemAvailable drops below threshold")
    parser.add_argument(
        "--heartbeat-json",
        default=str(OUT_DIR / "retrain_live_heartbeat.json"),
        help="Path for frequent live heartbeat updates while stages run",
    )
    parser.add_argument("--max-steps", type=int, default=200)
    parser.add_argument("--max-train-samples", type=int, default=5000)
    parser.add_argument("--max-train-token-chunks", type=int, default=0)
    parser.add_argument("--max-valid-token-chunks", type=int, default=0)
    parser.add_argument("--chunk-size-tokens", type=int, default=1024)
    parser.add_argument("--chunk-overlap-tokens", type=int, default=128)
    parser.add_argument(
        "--out-json",
        default=str(OUT_DIR / "retrain_loop_status.json"),
        help="Path for loop status JSON.",
    )
    args = parser.parse_args()

    out_path = Path(args.out_json).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    heartbeat_path = Path(args.heartbeat_json).resolve()
    _write_json(
        heartbeat_path,
        {
            "updated_at": _utc_now(),
            "stage": "starting",
            "message": "loop initialized",
            "mem_available_mb": _mem_available_mb(),
        },
    )

    streak = 0
    cycles: list[dict] = []
    prev_eval_metrics: dict = {}
    _write_json(
        out_path,
        {
            "updated_at": _utc_now(),
            "required_consecutive_passes": args.required_consecutive_passes,
            "current_consecutive_passes": 0,
            "max_cycles": args.max_cycles,
            "active_cycle": None,
            "cycles": [],
            "done": False,
        },
    )
    for i in range(1, args.max_cycles + 1):
        _write_json(
            out_path,
            {
                "updated_at": _utc_now(),
                "required_consecutive_passes": args.required_consecutive_passes,
                "current_consecutive_passes": streak,
                "max_cycles": args.max_cycles,
                "active_cycle": i,
                "cycles": cycles,
                "done": False,
            },
        )
        _write_json(
            heartbeat_path,
            {
                "updated_at": _utc_now(),
                "stage": f"cycle_{i}:starting",
                "message": "cycle starting",
                "mem_available_mb": _mem_available_mb(),
            },
        )
        result = _run_cycle(
            cycle_index=i,
            base_url=args.base_url,
            track=args.track,
            max_steps=args.max_steps,
            max_train_samples=args.max_train_samples,
            max_train_token_chunks=args.max_train_token_chunks,
            max_valid_token_chunks=args.max_valid_token_chunks,
            chunk_size_tokens=args.chunk_size_tokens,
            chunk_overlap_tokens=args.chunk_overlap_tokens,
            retrain_timeout_sec=args.retrain_timeout_sec,
            e2e_timeout_sec=args.e2e_timeout_sec,
            manual_timeout_sec=args.manual_timeout_sec,
            self_comparison_timeout_sec=args.self_comparison_timeout_sec,
            low_mem_kill_mb=args.low_mem_kill_mb,
            heartbeat_path=heartbeat_path,
            prev_eval_metrics=prev_eval_metrics,
        )
        if result.eval_metrics:
            prev_eval_metrics = result.eval_metrics
        cycles.append(asdict(result))
        streak = streak + 1 if result.all_gates_ok else 0
        payload = {
            "updated_at": _utc_now(),
            "required_consecutive_passes": args.required_consecutive_passes,
            "current_consecutive_passes": streak,
            "max_cycles": args.max_cycles,
            "active_cycle": None,
            "cycles": cycles,
            "done": streak >= args.required_consecutive_passes,
        }
        _write_json(out_path, payload)
        _write_json(
            heartbeat_path,
            {
                "updated_at": _utc_now(),
                "stage": f"cycle_{i}:completed",
                "all_gates_ok": result.all_gates_ok,
                "selected_base_model": result.selected_base_model,
                "eval_metrics": result.eval_metrics,
                "regression_detected": result.regression_detected,
                "regression_delta": result.regression_delta,
                "notes": result.notes,
                "mem_available_mb": _mem_available_mb(),
            },
        )
        print(f"Wrote progress: {out_path}")
        if streak >= args.required_consecutive_passes:
            print("Required consecutive pass streak reached.")
            return 0

    print("Reached max cycles before meeting required consecutive pass streak.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

