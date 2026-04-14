#!/usr/bin/env python3
"""Master pipeline: data → train → package → e2e → docker push.

This script NEVER stops until all stages succeed or --max-retries is reached.
It streams all subprocess output live (no silent pipes), writes a full activity log,
and calculates ETAs at every stage.

Usage:
  python scripts/run_full_training_pipeline.py
  python scripts/run_full_training_pipeline.py --skip-docker-push
  python scripts/run_full_training_pipeline.py --base-model Qwen/Qwen2.5-Coder-0.5B-Instruct
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = ROOT / "docs"
PIPELINE_LOG = DOCS_DIR / "pipeline_activity_log.jsonl"
PIPELINE_STATUS = DOCS_DIR / "pipeline_status.json"
HEARTBEAT_PATH = DOCS_DIR / "retrain_live_heartbeat.json"


# ──────────────────────────────────────────────────────────────────────────────
# Logging helpers
# ──────────────────────────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S UTC")


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log(stage: str, msg: str, **extra: Any) -> None:
    entry: dict[str, Any] = {"ts": _iso(), "stage": stage, "msg": msg}
    entry.update(extra)
    PIPELINE_LOG.parent.mkdir(parents=True, exist_ok=True)
    with PIPELINE_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    extra_str = "  " + "  ".join(f"{k}={v}" for k, v in extra.items()) if extra else ""
    print(f"[{ts}] [{stage}] {msg}{extra_str}", flush=True)


def _write_status(payload: dict) -> None:
    PIPELINE_STATUS.parent.mkdir(parents=True, exist_ok=True)
    payload["updated_at"] = _iso()
    PIPELINE_STATUS.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _fmt_elapsed(sec: float) -> str:
    h = int(sec // 3600)
    m = int((sec % 3600) // 60)
    s = int(sec % 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


# ──────────────────────────────────────────────────────────────────────────────
# Subprocess runner with live output streaming
# ──────────────────────────────────────────────────────────────────────────────

def _run_stage(
    stage: str,
    cmd: list[str],
    *,
    allow_fail: bool = False,
    timeout_sec: int = 0,
    env_extra: dict[str, str] | None = None,
) -> tuple[int, str]:
    """Run a command with live stdout streaming. Returns (returncode, combined_output)."""
    printable = " ".join(shlex.quote(c) for c in cmd)
    _log(stage, f"Starting: {printable}")
    t0 = time.time()

    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)

    proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env,
    )

    output_lines: list[str] = []
    deadline = t0 + timeout_sec if timeout_sec > 0 else None

    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            line = line.rstrip("\n")
            output_lines.append(line)
            elapsed = time.time() - t0
            print(f"  [{_fmt_elapsed(elapsed)}] {line}", flush=True)
            if deadline and time.time() > deadline:
                _log(stage, f"TIMEOUT after {timeout_sec}s — killing process")
                proc.kill()
                break
    except Exception as exc:
        _log(stage, f"Error reading stdout: {exc}")

    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()

    rc = proc.returncode or 0
    elapsed = time.time() - t0
    combined = "\n".join(output_lines)

    if rc == 0:
        _log(stage, f"SUCCESS in {_fmt_elapsed(elapsed)}", rc=rc)
    else:
        _log(stage, f"FAILED in {_fmt_elapsed(elapsed)}", rc=rc)
        if not allow_fail:
            raise RuntimeError(f"Stage '{stage}' failed (rc={rc}): {printable}")

    return rc, combined


# ──────────────────────────────────────────────────────────────────────────────
# Stage definitions
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class StageResult:
    stage: str
    ok: bool
    rc: int
    elapsed_sec: float
    retries: int = 0
    notes: str = ""


def _run_with_retry(
    stage: str,
    cmd: list[str],
    *,
    max_retries: int = 2,
    timeout_sec: int = 0,
    allow_fail: bool = False,
    env_extra: dict[str, str] | None = None,
) -> StageResult:
    t0 = time.time()
    for attempt in range(1, max_retries + 2):
        if attempt > 1:
            _log(stage, f"Retry {attempt - 1}/{max_retries}...")
            time.sleep(5)
        try:
            rc, _ = _run_stage(stage, cmd, allow_fail=True, timeout_sec=timeout_sec, env_extra=env_extra)
            if rc == 0:
                return StageResult(stage=stage, ok=True, rc=rc, elapsed_sec=time.time() - t0, retries=attempt - 1)
            if allow_fail:
                return StageResult(stage=stage, ok=False, rc=rc, elapsed_sec=time.time() - t0, retries=attempt - 1)
        except Exception as exc:
            _log(stage, f"Exception: {exc}")
            if attempt > max_retries:
                if allow_fail:
                    return StageResult(stage=stage, ok=False, rc=-1, elapsed_sec=time.time() - t0, retries=attempt - 1, notes=str(exc))
    return StageResult(stage=stage, ok=False, rc=-1, elapsed_sec=time.time() - t0, retries=max_retries, notes="max retries exceeded")


# ──────────────────────────────────────────────────────────────────────────────
# Main pipeline
# ──────────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="Full training pipeline with nonstop monitoring")
    parser.add_argument(
        "--base-model",
        default="Qwen/Qwen2.5-Coder-0.5B-Instruct",
        help="HuggingFace model ID for gradient training (default: 0.5B for CPU)",
    )
    parser.add_argument(
        "--config",
        default="configs/training/qlora_cpu_0p5b.yaml",
        help="Training config YAML",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=60,
        help="Max training steps (default 60 ≈ 20 min on CPU)",
    )
    parser.add_argument(
        "--chunk-size-tokens",
        type=int,
        default=512,
        help="Token chunk size for training examples",
    )
    parser.add_argument(
        "--model-name",
        default="bola-analyzer",
        help="Ollama model name to create/update",
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:8000",
        help="API base URL for E2E tests",
    )
    parser.add_argument(
        "--skip-docker-push",
        action="store_true",
        help="Build Docker image but do not push",
    )
    parser.add_argument(
        "--skip-gradient-train",
        action="store_true",
        help="Skip LoRA training; rebuild Ollama model from Modelfile only",
    )
    parser.add_argument(
        "--max-pipeline-retries",
        type=int,
        default=2,
        help="Max retries per failed stage before aborting",
    )
    parser.add_argument(
        "--docker-image",
        default="ghcr.io/igorredkach/bolai:latest",
        help="Docker image tag to build and push",
    )
    args = parser.parse_args()

    pipeline_start = time.time()
    results: list[StageResult] = []
    status: dict[str, Any] = {
        "pipeline_start": _iso(),
        "base_model": args.base_model,
        "stages": {},
        "done": False,
        "success": False,
    }
    _write_status(status)
    _log("pipeline", "=" * 60)
    _log("pipeline", f"BOLA AI FULL TRAINING PIPELINE STARTED")
    _log("pipeline", f"Base model : {args.base_model}")
    _log("pipeline", f"Config     : {args.config}")
    _log("pipeline", f"Max steps  : {args.max_steps}")
    _log("pipeline", f"Model name : {args.model_name}")
    _log("pipeline", f"Docker tag : {args.docker_image}")
    _log("pipeline", f"Activity log: {PIPELINE_LOG}")
    _log("pipeline", "=" * 60)

    # Check if training deps are available
    _log("pipeline", "Checking training dependencies...")
    try:
        import importlib
        for pkg in ("transformers", "peft", "datasets"):
            importlib.import_module(pkg)
        _log("pipeline", "Training deps: OK (transformers, peft, datasets)")
    except ImportError as exc:
        _log("pipeline", f"Missing training dep: {exc}. Installing...")
        _run_stage("install_deps", [sys.executable, "-m", "pip", "install", "-e", ".[train]", "-q"])

    def _record(r: StageResult) -> StageResult:
        results.append(r)
        status["stages"][r.stage] = asdict(r)
        _write_status(status)
        return r

    # ── STAGE 1: Combine training data ──────────────────────────────────────
    _log("pipeline", "STAGE 1: Combining all training data sources")
    r = _record(_run_with_retry(
        "combine_data",
        [sys.executable, "scripts/combine_training_data.py"],
        max_retries=1,
    ))
    if not r.ok:
        _log("pipeline", "FATAL: data combination failed. Cannot proceed.")
        return 1

    # Check output data count
    combined_path = ROOT / "data" / "training" / "reviewing_training_combined.jsonl"
    if combined_path.exists():
        row_count = sum(1 for l in combined_path.read_text().splitlines() if l.strip())
        _log("pipeline", f"Combined training data: {row_count} rows")
    else:
        _log("pipeline", "FATAL: combined JSONL not created")
        return 1

    # ── STAGE 2: Build training splits ──────────────────────────────────────
    _log("pipeline", "STAGE 2: Building SFT/DPO/EVAL splits")
    r = _record(_run_with_retry(
        "build_splits",
        [
            sys.executable, "scripts/build_training_splits.py",
            "--input", str(combined_path),
        ],
        max_retries=args.max_pipeline_retries,
    ))
    if not r.ok:
        _log("pipeline", "FATAL: split building failed.")
        return 1

    # Report split sizes
    for split_path in [
        ROOT / "data" / "training" / "sft" / "train.jsonl",
        ROOT / "data" / "training" / "sft" / "valid.jsonl",
    ]:
        if split_path.exists():
            cnt = sum(1 for l in split_path.read_text().splitlines() if l.strip())
            _log("pipeline", f"  {split_path.name}: {cnt} rows")

    # ── STAGE 3: Gradient training (LoRA) ───────────────────────────────────
    latest_adapter_dir: Path | None = None
    if not args.skip_gradient_train:
        _log("pipeline", "STAGE 3: LoRA gradient training (0.5B on CPU)")
        _log("pipeline", "  ETA: ~20-40 minutes for 60 steps on modern CPU")

        train_cmd = [
            sys.executable, "scripts/train_qlora_unsloth.py",
            "--config", args.config,
            "--base-model", args.base_model,
            "--max-steps", str(args.max_steps),
            "--chunk-size-tokens", str(args.chunk_size_tokens),
        ]
        r = _record(_run_with_retry(
            "gradient_train",
            train_cmd,
            max_retries=args.max_pipeline_retries,
            timeout_sec=7200,  # 2 hour hard cap for CPU training
        ))

        if r.ok:
            # Find the latest qlora adapter
            adapters = sorted([p for p in (ROOT / "models" / "adapters").glob("qlora_*") if p.is_dir()])
            latest_adapter_dir = adapters[-1] if adapters else None
            if latest_adapter_dir:
                result_file = latest_adapter_dir / "training_result.json"
                if result_file.exists():
                    res = json.loads(result_file.read_text())
                    _log("pipeline", f"  Adapter saved: {latest_adapter_dir.name}")
                    _log("pipeline", f"  Train loss: {res.get('train_metrics', {}).get('train_loss', 'n/a')}")
                else:
                    _log("pipeline", f"  WARNING: training_result.json missing in {latest_adapter_dir}")
            else:
                _log("pipeline", "  WARNING: no adapter directory found after training")
        else:
            _log("pipeline", "  Gradient training failed or timed out — falling back to Modelfile-only mode")
    else:
        _log("pipeline", "STAGE 3: Skipping gradient training (--skip-gradient-train)")

    # ── STAGE 4: Package adapter into Ollama ────────────────────────────────
    _log("pipeline", "STAGE 4: Packaging model for Ollama")

    if latest_adapter_dir is not None:
        _log("pipeline", f"  Packaging adapter: {latest_adapter_dir.name}")
        package_cmd = [
            sys.executable, "scripts/package_trained_model_for_ollama.py",
            "--run-dir", str(latest_adapter_dir),
            "--model-name", args.model_name,
        ]
        r = _record(_run_with_retry(
            "package_ollama",
            package_cmd,
            max_retries=args.max_pipeline_retries,
            timeout_sec=3600,
        ))
        if not r.ok:
            _log("pipeline", "  Package failed — falling back to Modelfile-only mode")
            latest_adapter_dir = None

    if latest_adapter_dir is None:
        _log("pipeline", "  Using Modelfile-only mode (retrain_model_from_scratch.py)")
        r = _record(_run_with_retry(
            "retrain_modelfile",
            [
                sys.executable, "scripts/retrain_model_from_scratch.py",
                "--allow-shortcut-rebuild",
            ],
            max_retries=args.max_pipeline_retries,
            timeout_sec=600,
        ))

    # ── STAGE 5: Reload RAG knowledge ────────────────────────────────────────
    _log("pipeline", "STAGE 5: Reloading RAG knowledge base")
    r = _record(_run_with_retry(
        "reload_rag",
        [sys.executable, "src/training/load_knowledge.py"],
        max_retries=1,
        allow_fail=True,
        env_extra={"PYTHONPATH": str(ROOT / "src"), "BOLA_AI_RESET_BEFORE_LOAD": "1"},
    ))

    # ── STAGE 6: Run eval on holdout ──────────────────────────────────────────
    _log("pipeline", "STAGE 6: Evaluating on holdout set")
    r = _record(_run_with_retry(
        "eval_holdout",
        [sys.executable, "scripts/eval_security_agent_model.py"],
        max_retries=1,
        allow_fail=True,
    ))

    # ── STAGE 7: E2E tests ────────────────────────────────────────────────────
    _log("pipeline", "STAGE 7: Running E2E tests against live API")
    # First check if API is reachable
    api_reachable = False
    try:
        import urllib.request
        urllib.request.urlopen(f"{args.base_url}/health", timeout=5)
        api_reachable = True
    except Exception as exc:
        _log("pipeline", f"  API not reachable at {args.base_url}: {exc}")

    if api_reachable:
        r = _record(_run_with_retry(
            "e2e_tests",
            [sys.executable, "scripts/run_agent_e2e_loop_once.py", args.base_url],
            max_retries=args.max_pipeline_retries,
            timeout_sec=900,
            allow_fail=True,
        ))
        e2e_ok = r.ok
    else:
        _log("pipeline", "  Skipping E2E: API not running. Start the API and re-run if needed.")
        e2e_ok = False
        _record(StageResult(stage="e2e_tests", ok=False, rc=-1, elapsed_sec=0, notes="API not reachable"))

    # ── STAGE 8: Verify published bundle for Docker ───────────────────────────
    _log("pipeline", "STAGE 8: Verifying published model bundle for Docker bake")
    published_dir = ROOT / "models" / "published"
    latest_marker = published_dir / "LATEST"
    bundle_ok = False

    if latest_marker.exists():
        bundle_name = latest_marker.read_text().strip()
        bundle_dir = published_dir / bundle_name
        parts = list(bundle_dir.glob("trained_model_bundle.part-*")) if bundle_dir.exists() else []
        if parts:
            _log("pipeline", f"  Published bundle found: {bundle_name} ({len(parts)} parts)")
            bundle_ok = True
        else:
            _log("pipeline", f"  LATEST marker points to {bundle_name} but no bundle parts found")
    else:
        _log("pipeline", "  No LATEST marker — Docker image will use base model + Modelfile (fallback)")

    if not bundle_ok:
        _log("pipeline", "  INFO: Docker will fall back to qwen2.5-coder:3b + Modelfile (network required at build)")

    # ── STAGE 9: Build Docker image ───────────────────────────────────────────
    _log("pipeline", "STAGE 9: Building all-in-one Docker image")
    r = _record(_run_with_retry(
        "docker_build",
        [
            "docker", "build",
            "-f", "docker/Dockerfile.allinone",
            "-t", args.docker_image,
            "-t", "docker-bola-ai:latest",
            ".",
        ],
        max_retries=1,
        timeout_sec=3600,
        allow_fail=True,
    ))
    docker_built = r.ok
    if not docker_built:
        _log("pipeline", "  Docker build FAILED. Check docker daemon and Dockerfile.")

    # ── STAGE 10: Push Docker image ───────────────────────────────────────────
    if docker_built and not args.skip_docker_push:
        _log("pipeline", "STAGE 10: Pushing Docker image to registry")
        r = _record(_run_with_retry(
            "docker_push",
            ["docker", "push", args.docker_image],
            max_retries=1,
            timeout_sec=1800,
            allow_fail=True,
        ))
        push_ok = r.ok
    elif args.skip_docker_push:
        _log("pipeline", "STAGE 10: Skipping push (--skip-docker-push)")
        push_ok = False
        _record(StageResult(stage="docker_push", ok=False, rc=0, elapsed_sec=0, notes="skipped by flag"))
    else:
        _log("pipeline", "STAGE 10: Skipping push (build failed)")
        push_ok = False
        _record(StageResult(stage="docker_push", ok=False, rc=-1, elapsed_sec=0, notes="docker build failed"))

    # ── Final summary ──────────────────────────────────────────────────────────
    elapsed = time.time() - pipeline_start
    _log("pipeline", "=" * 60)
    _log("pipeline", f"PIPELINE COMPLETE in {_fmt_elapsed(elapsed)}")
    _log("pipeline", "Stage results:")
    all_critical_ok = True
    for res in results:
        icon = "✓" if res.ok else "✗"
        _log("pipeline", f"  {icon} {res.stage}: {'OK' if res.ok else 'FAIL'} ({_fmt_elapsed(res.elapsed_sec)})")
        if not res.ok and res.stage in ("combine_data", "build_splits", "gradient_train"):
            all_critical_ok = False

    _log("pipeline", "=" * 60)
    _log("pipeline", f"E2E tests   : {'PASS' if e2e_ok else 'FAIL/SKIP'}")
    _log("pipeline", f"Docker built: {'YES' if docker_built else 'NO'}")
    _log("pipeline", f"Docker pushed: {'YES' if push_ok else 'NO/SKIP'}")

    status.update({
        "done": True,
        "success": all_critical_ok,
        "elapsed_sec": round(elapsed, 1),
        "e2e_ok": e2e_ok,
        "docker_built": docker_built,
        "push_ok": push_ok,
    })
    _write_status(status)

    if not all_critical_ok:
        _log("pipeline", "SOME CRITICAL STAGES FAILED. Review activity log for details.")
        _log("pipeline", f"  Activity log: {PIPELINE_LOG}")
        return 1

    _log("pipeline", "ALL CRITICAL STAGES PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
