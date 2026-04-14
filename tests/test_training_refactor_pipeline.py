"""Smoke tests for refactored QLoRA/LoRA pipeline scripts."""

from __future__ import annotations

import subprocess
from pathlib import Path
from importlib.util import module_from_spec, spec_from_file_location
import sys


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=_repo_root(), check=False, text=True, capture_output=True)


def _load_script_module(rel_path: str, module_name: str):
    script = _repo_root() / rel_path
    scripts_dir = str((_repo_root() / "scripts").resolve())
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    spec = spec_from_file_location(module_name, script)
    assert spec and spec.loader
    mod = module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_training_configs_exist():
    root = _repo_root()
    assert (root / "configs/training/qlora_1b3b.yaml").is_file()
    assert (root / "configs/training/lora16_1b3b.yaml").is_file()
    assert (root / "configs/training/dpo.yaml").is_file()
    assert (root / "configs/training/eval.yaml").is_file()


def test_pipeline_scripts_help():
    scripts = [
        "scripts/build_training_splits.py",
        "scripts/build_absence_logic_dataset.py",
        "scripts/build_toolcall_schema_set.py",
        "scripts/distill_teacher_outputs.py",
        "scripts/distill_with_mentor.py",
        "scripts/train_qlora_unsloth.py",
        "scripts/train_lora16.py",
        "scripts/train_dpo.py",
        "scripts/train_rlvr_toolexec.py",
        "scripts/eval_security_agent_model.py",
        "scripts/package_trained_model_for_ollama.py",
        "scripts/run_training_refactor_cycle.py",
    ]
    for script in scripts:
        p = _run(["python", script, "--help"])
        assert p.returncode == 0, f"{script} help failed: {p.stderr}"


def test_build_training_splits_normalize_new_schema_row():
    mod = _load_script_module("scripts/build_training_splits.py", "build_training_splits")
    row = {
        "id": "ROW-1",
        "artifacts_context": "GET /api/v1/assets/{assetId}",
        "target_patterns": ["Broken Object-Level Authorization (BOLA) :: ID in path without ownership check"],
        "expected_response": "Potential BOLA on GET /api/v1/assets/{assetId}",
        "analysis_explanation": "Path-level identifier is present with missing ownership evidence.",
    }
    normalized = mod._normalize_row(row, 1)
    assert normalized["instruction"]
    assert "GET /api/v1/assets/{assetId}" in normalized["context"]
    assert "## Analysis Explanation" in normalized["target"]

