#!/usr/bin/env python3
"""Merge a trained adapter and promote it to a live Ollama model.

This is a real deployment bridge:
1) load base model + trained adapter
2) merge adapter into full model weights
3) save merged model artifacts
4) build and publish Ollama model from merged weights
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import tarfile
from pathlib import Path

from training_pipeline_common import ROOT, utc_ts, write_json

MAX_GIT_PART_BYTES = 95 * 1024 * 1024


def _run(cmd: list[str], *, allow_fail: bool = False) -> int:
    printable = " ".join(shlex.quote(c) for c in cmd)
    print(f"$ {printable}")
    proc = subprocess.run(cmd)
    if proc.returncode != 0 and not allow_fail:
        raise RuntimeError(f"Command failed ({proc.returncode}): {printable}")
    return proc.returncode


def _resolve_run_dir(run_dir_arg: str) -> Path:
    run_dir = Path(run_dir_arg)
    if not run_dir.is_absolute():
        run_dir = (ROOT / run_dir).resolve()
    if not run_dir.is_dir():
        raise FileNotFoundError(f"Adapter run directory not found: {run_dir}")
    return run_dir


def _infer_base_model(run_dir: Path, explicit: str) -> str:
    if explicit.strip():
        return explicit.strip()
    tr = run_dir / "training_result.json"
    if tr.is_file():
        data = json.loads(tr.read_text(encoding="utf-8"))
        candidate = str(data.get("base_model", "")).strip()
        if candidate:
            return candidate
    raise ValueError("Base model not provided and not present in training_result.json")


def _resolve_ollama_runtime() -> tuple[list[str], str | None]:
    local = shutil.which("ollama")
    if local:
        return [local], None
    container = os.environ.get("BOLA_AI_OLLAMA_CONTAINER", "bola-ollama").strip() or "bola-ollama"
    check = subprocess.run(["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True)
    names = check.stdout.splitlines() if check.returncode == 0 else []
    for name in (container, "ollama", "bola-ollama"):
        if name in names:
            return ["docker", "exec", name, "ollama"], name
    raise RuntimeError(
        "Could not locate ollama runtime. Start ollama locally or set BOLA_AI_OLLAMA_CONTAINER "
        "to a running container name."
    )


def _rewrite_from(template_text: str, new_from: str) -> str:
    lines = template_text.splitlines()
    replaced = False
    out: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not replaced and stripped and not stripped.startswith("#") and stripped.upper().startswith("FROM "):
            out.append(f"FROM {new_from}")
            replaced = True
        else:
            out.append(line)
    if not replaced:
        out.insert(0, f"FROM {new_from}")
    return "\n".join(out).rstrip() + "\n"


def _merge_adapter(run_dir: Path, merged_dir: Path, base_model: str) -> None:
    try:
        import torch  # type: ignore
        from peft import PeftModel  # type: ignore
        from transformers import AutoModelForCausalLM, AutoTokenizer  # type: ignore
    except Exception as exc:
        raise RuntimeError(
            "Missing merge dependencies. Install with: pip install -e \".[train]\""
        ) from exc

    merged_dir.mkdir(parents=True, exist_ok=True)
    # Force float16 on CPU too — float32 doubles peak RAM (~12 GB vs ~6 GB for 3B model)
    # and causes OOM on systems with <16 GB free; PyTorch supports float16 save on CPU.
    dtype = torch.float16
    base = AutoModelForCausalLM.from_pretrained(
        base_model,
        torch_dtype=dtype,
        device_map="auto" if torch.cuda.is_available() else None,
        low_cpu_mem_usage=True,
    )
    adapted = PeftModel.from_pretrained(base, str(run_dir))
    merged = adapted.merge_and_unload()
    merged.save_pretrained(str(merged_dir))
    tok_source = run_dir if (run_dir / "tokenizer_config.json").is_file() else base_model
    tok = AutoTokenizer.from_pretrained(str(tok_source), use_fast=True)
    tok.save_pretrained(str(merged_dir))


def _write_tar_bundle(
    *,
    merged_dir: Path,
    template_text: str,
    out_dir: Path,
    model_name: str,
    ts: str,
    part_bytes: int,
) -> dict:
    """Create git-pushable split bundle with merged model + Modelfile."""
    out_dir.mkdir(parents=True, exist_ok=True)
    tar_path = out_dir / "trained_model_bundle.tar"
    bundle_modelfile = out_dir / "bundle.Modelfile"
    bundle_modelfile.write_text(
        _rewrite_from(template_text, "/app/models/published/active/merged_model"),
        encoding="utf-8",
    )

    with tarfile.open(tar_path, "w") as tf:
        tf.add(str(merged_dir), arcname="active/merged_model")
        tf.add(str(bundle_modelfile), arcname="active/Modelfile")

    parts: list[dict] = []
    idx = 0
    with tar_path.open("rb") as src:
        while True:
            chunk = src.read(part_bytes)
            if not chunk:
                break
            idx += 1
            part = out_dir / f"trained_model_bundle.part-{idx:04d}"
            part.write_bytes(chunk)
            parts.append(
                {
                    "name": part.name,
                    "bytes": len(chunk),
                    "sha256": hashlib.sha256(chunk).hexdigest(),
                }
            )

    tar_bytes = tar_path.stat().st_size
    tar_path.unlink(missing_ok=True)
    bundle_modelfile.unlink(missing_ok=True)

    restore = out_dir / "RESTORE_COMMAND.txt"
    restore.write_text(
        "cat trained_model_bundle.part-* > trained_model_bundle.tar && "
        "tar -xf trained_model_bundle.tar\n",
        encoding="utf-8",
    )

    latest_marker = out_dir.parent / "LATEST"
    latest_marker.write_text(out_dir.name + "\n", encoding="utf-8")

    return {
        "model_name": model_name,
        "created_at": ts,
        "bundle_dir": str(out_dir),
        "tar_uncompressed_bytes": tar_bytes,
        "part_size_bytes": part_bytes,
        "parts": parts,
        "latest_marker": str(latest_marker),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge adapter and publish real Ollama model")
    parser.add_argument("--run-dir", required=True, help="Adapter run directory (models/adapters/...)")
    parser.add_argument("--base-model", default="", help="Base HF model id/path (optional if in training_result.json)")
    parser.add_argument("--model-name", default="bola-analyzer", help="Target Ollama model name")
    parser.add_argument("--modelfile-template", default="docker/Modelfile", help="Template Modelfile path")
    parser.add_argument("--skip-merge", action="store_true", help="Skip merge if merged dir already exists")
    parser.add_argument("--skip-ollama-create", action="store_true", help="Skip ollama create/publish step")
    parser.add_argument(
        "--skip-git-bundle",
        action="store_true",
        help="Skip writing split model bundle under models/published",
    )
    args = parser.parse_args()

    run_dir = _resolve_run_dir(args.run_dir)
    base_model = _infer_base_model(run_dir, args.base_model)
    ts = utc_ts()
    merged_dir = (ROOT / "models" / "merged" / f"{run_dir.name}-merged-{ts}").resolve()
    packaged_dir = (ROOT / "models" / "packaged" / f"{args.model_name}-{ts}").resolve()
    packaged_dir.mkdir(parents=True, exist_ok=True)

    if not args.skip_merge:
        _merge_adapter(run_dir, merged_dir, base_model)

    template_path = Path(args.modelfile_template)
    if not template_path.is_absolute():
        template_path = (ROOT / template_path).resolve()
    template_text = template_path.read_text(encoding="utf-8")

    ollama_cmd, container_name = _resolve_ollama_runtime()

    if container_name is None:
        from_ref = str(merged_dir)
        final_modelfile = packaged_dir / "Modelfile"
        final_modelfile.write_text(_rewrite_from(template_text, from_ref), encoding="utf-8")
        create_ref = str(final_modelfile)
    else:
        remote_model_dir = f"/tmp/{merged_dir.name}"
        remote_modelfile = f"/tmp/{args.model_name}-{ts}.Modelfile"
        _run(["docker", "exec", container_name, "sh", "-lc", f"rm -rf {shlex.quote(remote_model_dir)}"])
        _run(["docker", "cp", str(merged_dir), f"{container_name}:{remote_model_dir}"])
        rewritten = _rewrite_from(template_text, remote_model_dir)
        final_modelfile = packaged_dir / "Modelfile"
        final_modelfile.write_text(rewritten, encoding="utf-8")
        _run(["docker", "cp", str(final_modelfile), f"{container_name}:{remote_modelfile}"])
        create_ref = remote_modelfile

    if not args.skip_ollama_create:
        _run(ollama_cmd + ["rm", args.model_name], allow_fail=True)
        _run(ollama_cmd + ["create", args.model_name, "-f", create_ref])
        _run(ollama_cmd + ["show", args.model_name])

    git_bundle_manifest = None
    if not args.skip_git_bundle:
        published_dir = (ROOT / "models" / "published" / f"{args.model_name}-{ts}").resolve()
        git_bundle_manifest = _write_tar_bundle(
            merged_dir=merged_dir,
            template_text=template_text,
            out_dir=published_dir,
            model_name=args.model_name,
            ts=ts,
            part_bytes=MAX_GIT_PART_BYTES,
        )

    manifest = {
        "created_at": ts,
        "run_dir": str(run_dir),
        "base_model": base_model,
        "merged_dir": str(merged_dir),
        "model_name": args.model_name,
        "modelfile": str(final_modelfile),
        "runtime": "local_ollama" if container_name is None else f"container:{container_name}",
        "ollama_created": not args.skip_ollama_create,
        "git_bundle": git_bundle_manifest,
    }
    write_json(packaged_dir / "package_manifest.json", manifest)
    print(f"Packaged model assets in: {packaged_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

