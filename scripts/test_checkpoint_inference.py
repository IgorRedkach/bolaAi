#!/usr/bin/env python3
"""Grounded inference test with verify-and-correct loop.

Every specific technical value in the response (tenantIds, endpoint names,
query operation names, IDs, field names) is checked verbatim against the
raw context. If hallucinated values are found the model is asked to
correct them — up to MAX_CORRECTION_ROUNDS times.

Usage:
  python scripts/test_checkpoint_inference.py \
      --adapter models/adapters/qlora_20260415T143126Z/checkpoint-140 \
      --example-id GQL-0308-GOVERNMENT \
      --max-new-tokens 900
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRAIN_FILE = ROOT / "data" / "training" / "sft" / "train.jsonl"
MAX_CORRECTION_ROUNDS = 1  # one correction pass max — extra rounds degrade quality and spike RAM

# ── Prompt templates ──────────────────────────────────────────────────────────

# Short grounding suffix + explicit Next Steps requirement.
_GROUNDED_SUFFIX = (
    "\n\nCRITICAL RULES:"
    "\n1. Every specific technical value (tenant IDs, operation names, endpoint URLs, "
    "response field values) MUST appear VERBATIM in the Context below."
    "\n2. The HAR capture is the primary evidence — use its exact operation name, "
    "tenant IDs, and response values for reproduction steps."
    "\n3. After the finding, include a '## Next Steps for You' section with these "
    "sub-sections: Immediate Verification, Scope Assessment, Code Fix, Fix Validation, "
    "and Escalation Decision."
)

_CORRECTION_TEMPLATE = (
    "The following values do NOT appear in the Context — replace every one "
    "with the correct value found verbatim in the HAR:\n"
    "{hallucinated}\n\n"
    "Rewrite the full analysis. Keep the '## Next Steps for You' section."
)


# ── Data helpers ──────────────────────────────────────────────────────────────

def _load_example(example_id: str) -> dict:
    with TRAIN_FILE.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if row.get("id") == example_id:
                return row
    print(f"[WARN] Example {example_id!r} not found — using first example")
    with TRAIN_FILE.open() as f:
        for line in f:
            line = line.strip()
            if line:
                row = json.loads(line)
                print(f"[INFO] Using example: {row.get('id')}")
                return row
    raise ValueError("No examples in train.jsonl")


# ── Prompt builders ───────────────────────────────────────────────────────────

def _initial_prompt(row: dict) -> str:
    instruction = row["instruction"].strip() + _GROUNDED_SUFFIX
    return (
        "### Instruction\n"
        f"{instruction}\n\n"
        "### Context\n"
        f"{row['context'].strip()}\n\n"
        "### Response\n"
    )


def _correction_prompt(row: dict, hallucinated: list[str], prev_response: str) -> str:
    # Keep correction prompt compact — don't repeat the full prev response
    # so the model can still see the full context within the token window.
    correction_note = _CORRECTION_TEMPLATE.format(
        hallucinated="\n".join(f"  BAD: {v}" for v in hallucinated)
    )
    instruction = row["instruction"].strip() + _GROUNDED_SUFFIX + "\n\n" + correction_note
    return (
        "### Instruction\n"
        f"{instruction}\n\n"
        "### Context\n"
        f"{row['context'].strip()}\n\n"
        "### Response\n"
    )


# ── Claim extraction & hallucination detection ────────────────────────────────

# ── Claim extraction ─────────────────────────────────────────────────────────
# Patterns that match specific technical values requiring grounding.
_CLAIM_RES = [
    re.compile(r'tenant-[a-zA-Z0-9]+'),                # tenant-5a8f, tenant-5984, …
    re.compile(r'`([a-zA-Z][a-zA-Z0-9_]+)\s*\('),       # `listResources(`, `bulkResourceLookup(`
    re.compile(r'\bR-\d+\b'),                           # R-1030, R-2030, …
    re.compile(r'\busr_[a-zA-Z0-9_]+\b'),               # usr_abc
    re.compile(r'req-[a-zA-Z0-9]+'),                    # req-59845a8f
    re.compile(r'CONFIDENTIAL-[a-zA-Z0-9]+'),           # CONFIDENTIAL-59845a8f
    re.compile(r'other-user-[a-zA-Z0-9]+'),             # other-user-59845a8f
    re.compile(r'"kid"\s*:\s*"([^"]+)"'),               # JWT kid claim
]

# Specific structural checks that go beyond regex-extracted values.
_STRUCTURAL_CHECKS = [
    # (description, bad_pattern, context_evidence_for_correct, correct_hint)
    (
        "HTTP method in narrative",
        re.compile(r'\bGET\s+https?://'),
        "method\": \"POST\"",
        "HAR shows POST, not GET",
    ),
]

_GENERIC = {
    "/graphql", "/api", "HTTP", "JWT", "POST", "GET", "Bearer",
    "Content-Type", "Authorization", "200", "401", "403",
}

# GraphQL field/type names that appear in the schema — only these are allowed.
# Build this from context at runtime in _find_hallucinations.


def _extract_schema_names(context: str) -> set[str]:
    """Extract field/type names defined in the GraphQL schema block."""
    names: set[str] = set()
    in_schema = False
    for line in context.splitlines():
        if '```graphql' in line:
            in_schema = True
            continue
        if in_schema and line.strip().startswith('```'):
            in_schema = False
            continue
        if in_schema:
            # type/field name: word at start or after colon
            for m in re.finditer(r'\b([a-zA-Z][a-zA-Z0-9_]+)\b', line):
                names.add(m.group(1))
    return names


def _extract_claims(text: str) -> list[str]:
    claims: set[str] = set()
    for rx in _CLAIM_RES:
        for m in rx.finditer(text):
            val = (m.group(1) if m.lastindex else m.group(0)).strip('`\'" ')
            if len(val) >= 3:
                claims.add(val)
    return sorted(claims)


def _find_hallucinations(response: str, context: str) -> list[str]:
    """All claims and structural errors in the response not grounded in context."""
    issues: list[str] = []

    # 1. Value-level: regex-extracted claims not in context
    for c in _extract_claims(response):
        if c not in context and c not in _GENERIC:
            issues.append(c)

    # 2. Structural: HTTP method mismatch, fabricated op names, etc.
    for desc, bad_re, ctx_evidence, hint in _STRUCTURAL_CHECKS:
        if bad_re.search(response) and ctx_evidence in context:
            issues.append(f"[structural] {desc}: {hint}")

    # 3. GraphQL field names in response that are NOT in the schema block
    schema_names = _extract_schema_names(context)
    if schema_names:
        # Find field names cited inside query blocks in the response
        for m in re.finditer(r'\b([a-zA-Z][a-zA-Z0-9_]+)\s*\{', response):
            name = m.group(1)
            # Only check names that look like field/type refs (not bash/curl keywords)
            skip = {"bash", "json", "graphql", "curl", "data", "query", "mutation",
                    "errors", "message", "Authorization", "Content"}
            if name in skip or len(name) < 4:
                continue
            if name not in schema_names and name not in context:
                issues.append(f"[schema] field/type '{name}' not in context schema")

    return sorted(set(issues))


# ── Structural quality check ──────────────────────────────────────────────────

_REQUIRED = ["Finding", "Evidence"]
_REMEDIATION_VARIANTS = ["Remediation", "remediation", "Fix", "Mitigation", "mitigation", "Step 1"]
_REPRO_VARIANTS = [
    "Reproduction", "Steps to Reproduce", "Reproduce", "Verification",
    "PoC", "Testing Methodology",
]
_NEXT_STEPS_VARIANTS = [
    "Next Steps",
    "Immediate Verification",
    "Scope Assessment",
    "Code Fix",
    "Escalation",
]
_VULN_KEYWORDS = [
    # Core concepts — check for ANY 3 of these
    "BOLA", "bola",
    "authorization", "authoris",
    "cross-tenant", "other tenant", "another tenant",
    "tenant", "tenantId",
    "ownership",
    "JWT", "Bearer",
    "claim",
    "resolver",
    "pattern", "Pattern",
    "vulnerability", "Vulnerability",
    "findings", "Finding",
]


def _check_structure(response: str) -> tuple[bool, list[str], list[str]]:
    issues: list[str] = []
    notes: list[str] = []
    rl = response.lower()

    for sec in _REQUIRED:
        if sec.lower() in rl:
            notes.append(f"✅ Section '{sec}' present")
        else:
            issues.append(f"Missing section: '{sec}'")

    # Remediation check: accept any variant (model sometimes uses headers like "Step 1")
    if any(v in response for v in _REMEDIATION_VARIANTS):
        notes.append("✅ Remediation/fix section present")
    else:
        issues.append("Missing remediation or fix section")

    if any(v.lower() in rl for v in _REPRO_VARIANTS):
        notes.append("✅ Reproduction/Steps section present")
    else:
        issues.append("Missing reproduction or steps section")

    # Next Steps guidance: informational only — production runner appends it deterministically.
    ns_found = [v for v in _NEXT_STEPS_VARIANTS if v.lower() in rl]
    if len(ns_found) >= 2:
        notes.append(f"✅ Next-Steps guidance in model output ({ns_found[:3]})")
    else:
        notes.append(
            f"ℹ️  'Next Steps for You' not in raw model output (production runner will append it)"
        )

    kws = [k for k in _VULN_KEYWORDS if k in response]
    if len(kws) >= 3:
        notes.append(f"✅ Vulnerability keywords: {kws[:5]}")
    else:
        issues.append(f"Too few vulnerability keywords (found: {kws})")

    words = len(response.split())
    if words < 100:
        issues.append(f"Response too short ({words} words)")
    else:
        notes.append(f"✅ Length OK ({words} words)")

    if response.strip()[:30].lower().startswith("analyze"):
        issues.append("Response echoes prompt — generation problem")

    return len(issues) == 0, issues, notes


# ── Generation ────────────────────────────────────────────────────────────────

def _generate(model, tokenizer, prompt: str, max_new_tokens: int, torch) -> str:
    # 2048 input tokens — enough for the full context + instruction without truncation.
    # The 256-token training window was only for memory efficiency; Qwen3B handles
    # up to 128K tokens at inference time.
    inputs = tokenizer(
        prompt, return_tensors="pt", truncation=True, max_length=2048
    )
    t0 = time.time()
    with torch.no_grad():
        out = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=False,        # greedy — deterministic, reduces hallucination variance
            repetition_penalty=1.15,
            pad_token_id=tokenizer.eos_token_id,
        )
    elapsed = time.time() - t0
    n_gen = out.shape[1] - inputs["input_ids"].shape[1]
    response = tokenizer.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
    print(f"  [gen] {n_gen} tokens in {elapsed:.1f}s")
    return response


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--adapter",
        default="models/adapters/qlora_20260415T143126Z/checkpoint-140",
    )
    parser.add_argument("--example-id", default="GQL-0308-GOVERNMENT")
    parser.add_argument("--max-new-tokens", type=int, default=1600)
    args = parser.parse_args()

    adapter_path = Path(args.adapter)
    if not adapter_path.is_absolute():
        adapter_path = (ROOT / adapter_path).resolve()
    if not adapter_path.exists():
        print(f"[ERROR] Adapter not found: {adapter_path}")
        return 1

    print(f"[TEST] Loading example: {args.example_id}")
    example = _load_example(args.example_id)
    context = example["context"]

    print(f"\n[TEST] Loading base model + adapter: {adapter_path}")
    try:
        import torch
        from peft import PeftModel
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError as e:
        print(f"[ERROR] {e}\nInstall: pip install peft transformers torch")
        return 1

    # Cap threads: more threads means more parallel tensor ops → more RAM spikes
    torch.set_num_threads(4)
    torch.set_num_interop_threads(2)

    cfg_file = adapter_path / "adapter_config.json"
    base_model_id = "Qwen/Qwen2.5-Coder-3B-Instruct"
    if cfg_file.exists():
        base_model_id = json.loads(cfg_file.read_text()).get(
            "base_model_name_or_path", base_model_id
        )
    print(f"[TEST] Base model: {base_model_id}")

    # Memory budget report before loading
    try:
        import psutil
        avail_gb = psutil.virtual_memory().available / 1e9
        print(f"[MEM] Available RAM before load: {avail_gb:.1f} GB")
        if avail_gb < 7.0:
            print("[WARN] < 7 GB available — may OOM. Consider closing other processes.")
    except ImportError:
        pass

    t0 = time.time()
    tokenizer = AutoTokenizer.from_pretrained(str(adapter_path), use_fast=True)
    # bfloat16: 3B params × 2 bytes ≈ 6 GB vs float32 ≈ 12 GB.
    # CPU supports bfloat16 (software emulation); slower but stays within 10 GB budget.
    base = AutoModelForCausalLM.from_pretrained(
        base_model_id,
        dtype=torch.bfloat16,
        device_map=None,
        low_cpu_mem_usage=True,
    )
    model = PeftModel.from_pretrained(base, str(adapter_path))
    model.eval()

    try:
        import psutil
        used_gb = psutil.Process().memory_info().rss / 1e9
        print(f"[MEM] Process RSS after load: {used_gb:.1f} GB")
    except ImportError:
        pass

    print(f"[TEST] Model ready in {time.time()-t0:.1f}s\n")

    # ── Round 0: initial grounded generation ──────────────────────────────────
    print("=" * 70)
    print("ROUND 0 — Initial grounded generation")
    print("=" * 70)
    response = _generate(model, tokenizer, _initial_prompt(example), args.max_new_tokens, torch)
    print(response)

    # ── Verify + correct loop ─────────────────────────────────────────────────
    hallucinated: list[str] = []
    for rnd in range(1, MAX_CORRECTION_ROUNDS + 1):
        hallucinated = _find_hallucinations(response, context)
        if not hallucinated:
            print(f"\n✅ No hallucinated technical values — grounding OK after round {rnd - 1}.")
            break
        print(f"\n{'='*70}")
        print(f"ROUND {rnd} — Correction  (hallucinated: {hallucinated})")
        print("=" * 70)
        response = _generate(
            model, tokenizer,
            _correction_prompt(example, hallucinated, response),
            args.max_new_tokens, torch,
        )
        print(response)
    else:
        hallucinated = _find_hallucinations(response, context)
        if hallucinated:
            print(
                f"\n⚠️  After {MAX_CORRECTION_ROUNDS} rounds "
                f"{len(hallucinated)} hallucinated value(s) remain: {hallucinated}"
            )

    # ── Final evaluation ──────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("FINAL EVALUATION")
    print("=" * 70)

    struct_ok, struct_issues, struct_notes = _check_structure(response)
    for n in struct_notes:
        print(f"  {n}")
    for i in struct_issues:
        print(f"  ❌ {i}")

    remaining_hallucinations = _find_hallucinations(response, context)
    if remaining_hallucinations:
        print(f"  ❌ Remaining hallucinated values: {remaining_hallucinations}")
    else:
        print("  ✅ All cited technical values are grounded in the context")

    print("\n--- EXPECTED (first 600 chars) ---")
    print(example.get("target", "")[:600])
    print("---")

    passed = struct_ok and not remaining_hallucinations
    if passed:
        print("\n✅ QUALITY CHECK PASSED — response is grounded and well-structured")
        return 0
    all_issues = struct_issues + (
        [f"Hallucinated: {remaining_hallucinations}"] if remaining_hallucinations else []
    )
    print(f"\n❌ QUALITY CHECK FAILED — {len(all_issues)} issue(s)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
