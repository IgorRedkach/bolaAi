"""Smoke tests for training pipeline scripts."""

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
    assert (root / "configs/training/qlora_cpu_3b.yaml").is_file(), "Missing qlora_cpu_3b.yaml"
    assert (root / "configs/training/qlora_har_specialist.yaml").is_file(), "Missing qlora_har_specialist.yaml"


def test_pipeline_scripts_exist():
    root = _repo_root()
    scripts = [
        "scripts/build_training_splits.py",
        "scripts/train_qlora_unsloth.py",
        "scripts/package_trained_model_for_ollama.py",
        "scripts/post_training_package_and_push.py",
        "scripts/test_checkpoint_inference.py",
        "scripts/merge_adapter_fp16.py",
    ]
    for script in scripts:
        assert (root / script).is_file(), f"Missing: {script}"


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
