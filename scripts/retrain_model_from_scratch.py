#!/usr/bin/env python3
"""Rebuild local Ollama model from Modelfile + RAG reload.

IMPORTANT:
- This script does NOT run gradient training.
- It only rebuilds an Ollama model and refreshes knowledge.
- For real training, run the training cycle script first and promote adapters.

This script enforces a clean rebuild flow:
1) regenerate training artifacts
2) reload RAG knowledge with reset
3) remove prior local custom model
4) recreate model from base Modelfile

It is intended to keep retraining deterministic and avoid bias accumulation from
iteratively stacking custom models.
"""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def _run(cmd: list[str], *, env: dict[str, str] | None = None, allow_fail: bool = False) -> int:
    printable = " ".join(shlex.quote(c) for c in cmd)
    print(f"$ {printable}")
    proc = subprocess.run(cmd, env=env)
    if proc.returncode != 0 and not allow_fail:
        raise RuntimeError(f"Command failed ({proc.returncode}): {printable}")
    return proc.returncode


def _assert_modelfile_from_base(modelfile: Path, model_name: str) -> None:
    if not modelfile.is_file():
        raise FileNotFoundError(f"Modelfile not found: {modelfile}")
    from_line = ""
    for raw in modelfile.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.upper().startswith("FROM "):
            from_line = line
            break
    if not from_line:
        raise RuntimeError("Modelfile has no FROM line")
    from_value = from_line.split(maxsplit=1)[1].strip()
    if from_value == model_name:
        raise RuntimeError(
            f"Modelfile FROM points to target model '{model_name}', which is not from-scratch. "
            "Set FROM to a base model (for example qwen2.5-coder:3b)."
        )
    print(f"Validated base model source: {from_value}")


def _ollama_runtime() -> tuple[list[str], str | None]:
    local = shutil.which("ollama")
    if local:
        return [local], None

    # Fallback for Docker-based stacks where ollama CLI is inside the container.
    preferred = os.environ.get("BOLA_AI_OLLAMA_CONTAINER", "bola-ollama").strip() or "bola-ollama"
    check = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
    )
    names = check.stdout.splitlines() if check.returncode == 0 else []
    for name in (preferred, "ollama", "bola-ollama"):
        if name in names:
            return ["docker", "exec", name, "ollama"], name

    raise RuntimeError(
        "Could not locate ollama CLI. Install ollama locally or set BOLA_AI_OLLAMA_CONTAINER "
        "to a running container name that has ollama binary."
    )


def _prepare_modelfile_for_ollama(modelfile: Path, container_name: str | None) -> str:
    if container_name is None:
        return str(modelfile)
    target = "/tmp/bola_modelfile"
    _run(["docker", "cp", str(modelfile), f"{container_name}:{target}"])
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description="Retrain local Ollama model from scratch.")
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Repository root path",
    )
    parser.add_argument("--model-name", default="bola-analyzer", help="Target local model name.")
    parser.add_argument(
        "--modelfile",
        default="docker/Modelfile",
        help="Path to Modelfile (relative to repo root).",
    )
    parser.add_argument(
        "--skip-generate-data",
        action="store_true",
        help="Skip training data regeneration step.",
    )
    parser.add_argument(
        "--skip-load-knowledge",
        action="store_true",
        help="Skip RAG reload step.",
    )
    parser.add_argument(
        "--tag-run",
        action="store_true",
        help="Also create timestamped model alias after base rebuild.",
    )
    parser.add_argument(
        "--allow-shortcut-rebuild",
        action="store_true",
        help="Acknowledge this is a rebuild-only path (no gradient training).",
    )
    args = parser.parse_args()

    if not args.allow_shortcut_rebuild:
        raise RuntimeError(
            "Refusing rebuild-only path without explicit acknowledgement. "
            "Use --allow-shortcut-rebuild for this script, or run real training + promotion "
            "via scripts/run_training_refactor_cycle.py."
        )

    repo_root = Path(args.repo_root).resolve()
    modelfile = (repo_root / args.modelfile).resolve()
    _assert_modelfile_from_base(modelfile, args.model_name)

    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root / "src")

    if not args.skip_generate_data:
        _run(["python", str(repo_root / "src/training/generate_data.py")], env=env)

    if not args.skip_load_knowledge:
        env_with_reset = dict(env)
        env_with_reset["BOLA_AI_RESET_BEFORE_LOAD"] = "1"
        _run(["python", str(repo_root / "src/training/load_knowledge.py")], env=env_with_reset)

    ollama_cmd, container_name = _ollama_runtime()
    ollama_modelfile = _prepare_modelfile_for_ollama(modelfile, container_name)

    # Remove old custom model so create is guaranteed fresh.
    _run(ollama_cmd + ["rm", args.model_name], allow_fail=True)
    _run(ollama_cmd + ["create", args.model_name, "-f", ollama_modelfile])

    if args.tag_run:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        alias = f"{args.model_name}-fresh-{ts}"
        _run(ollama_cmd + ["create", alias, "-f", ollama_modelfile])
        print(f"Created additional timestamped alias: {alias}")

    _run(ollama_cmd + ["show", args.model_name])
    print("From-scratch retrain completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
