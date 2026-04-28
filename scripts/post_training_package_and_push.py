#!/usr/bin/env python3
"""Post-training completion: package adapter → build Docker → push to ghcr.io.

Run this AFTER training completes (or manually to package an existing adapter).

Usage:
  python scripts/post_training_package_and_push.py           # auto-detect latest adapter
  python scripts/post_training_package_and_push.py --run-dir models/adapters/qlora_20260415T143126Z
  python scripts/post_training_package_and_push.py --skip-push
"""

from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL_NAME = "bola-har"
HAR_MODELFILE = "docker/Modelfile.bola-har"
DOCKER_IMAGE = "ghcr.io/igorredkach/bolai:latest"


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S UTC")


def _run(cmd: list[str], *, timeout: int = 0) -> int:
    printable = " ".join(shlex.quote(c) for c in cmd)
    print(f"\n[{_ts()}] $ {printable}", flush=True)
    proc = subprocess.Popen(cmd, cwd=str(ROOT), stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, bufsize=1)
    assert proc.stdout is not None
    start = time.time()
    for line in proc.stdout:
        print(line, end="", flush=True)
        if timeout > 0 and (time.time() - start) > timeout:
            proc.terminate()
            print(f"\n[{_ts()}] TIMEOUT")
            break
    return proc.wait()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", default="",
                        help="Path to adapter run dir (default: auto-detect latest qlora_* dir)")
    parser.add_argument("--skip-push", action="store_true")
    args = parser.parse_args()

    # Resolve adapter dir
    if args.run_dir:
        run_dir = Path(args.run_dir).resolve()
    else:
        adapters = sorted([p for p in (ROOT / "models" / "adapters").glob("qlora_*") if p.is_dir()])
        if not adapters:
            print(f"[{_ts()}] ERROR: No qlora_* adapter directory found")
            return 1
        run_dir = adapters[-1]

    print(f"\n[{_ts()}] POST-TRAINING PIPELINE (bola-har HAR specialist)")
    print(f"[{_ts()}] Adapter dir: {run_dir}")
    print(f"[{_ts()}] Model name : {MODEL_NAME}")
    print(f"[{_ts()}] Modelfile  : {HAR_MODELFILE}")
    print(f"[{_ts()}] Docker tag : {DOCKER_IMAGE}")

    # Verify adapter has weights
    weight_files = list(run_dir.glob("adapter_model*")) + list(run_dir.glob("*.safetensors"))
    if not weight_files:
        print(f"[{_ts()}] ERROR: No adapter weights found in {run_dir}")
        print(f"[{_ts()}] Available: {list(run_dir.iterdir())}")
        return 1
    print(f"[{_ts()}] Adapter weights: {[f.name for f in weight_files]}")

    # Stage 1: Merge adapter + package for Ollama
    print(f"\n[{_ts()}] STAGE 1: Merging adapter weights and packaging for Ollama")
    print(f"[{_ts()}] This creates models/merged/bola-har-merged/ for Docker COPY")
    rc = _run([
        sys.executable, "scripts/package_trained_model_for_ollama.py",
        "--run-dir", str(run_dir),
        "--model-name", MODEL_NAME,
    ], timeout=3600)
    if rc != 0:
        print(f"[{_ts()}] WARNING: Packaging failed — check package_trained_model_for_ollama.py")

    # Stage 2: Build Docker image
    print(f"\n[{_ts()}] STAGE 2: Building Docker image")
    rc = _run([
        "docker", "build",
        "-f", "docker/Dockerfile.allinone",
        "-t", DOCKER_IMAGE,
        "-t", "docker-bola-ai:latest",
        ".",
    ], timeout=7200)
    if rc != 0:
        print(f"[{_ts()}] FAILED: Docker build")
        return 1
    print(f"[{_ts()}] Docker build SUCCESS")

    # Stage 3: Push
    if args.skip_push:
        print(f"\n[{_ts()}] STAGE 3: SKIP push (--skip-push)")
    else:
        print(f"\n[{_ts()}] STAGE 3: Pushing to {DOCKER_IMAGE}")
        print(f"[{_ts()}] NOTE: Requires 'docker login ghcr.io' first if not already logged in")
        rc = _run(["docker", "push", DOCKER_IMAGE])
        if rc != 0:
            print(f"[{_ts()}] FAILED: Docker push")
            print(f"[{_ts()}] Run: echo TOKEN | docker login ghcr.io -u USERNAME --password-stdin")
            return 1
        print(f"[{_ts()}] Pushed: {DOCKER_IMAGE}")

    print(f"\n[{_ts()}] ✅ POST-TRAINING COMPLETE")
    print(f"[{_ts()}] Image: {DOCKER_IMAGE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
