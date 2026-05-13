#!/usr/bin/env python3
"""Build SFT training examples from the reviewing folder hierarchy.

Each reviewing case has three files:
  context.txt          – the document artifact
  expected_response.md – the ideal analysis output
  analysis_explanation.md – reasoning chain (optional, used for filtering)

This script:
  1. Walks all REVIEW-* / BOLA-* / INJ-* case directories
  2. Applies quality filters (minimum length, has expected_response)
  3. Detects document section types using DocTypeDetector
  4. Optionally stratifies by section type to ensure diversity
  5. Writes a combined JSONL file in the SFT training format

Usage:
    python scripts/build_sft_from_reviewing.py \\
        --input data/training/reviewing \\
        --output data/training/sft/reviewing_combined.jsonl \\
        --max 500 \\
        --stratify

Output format (per line):
    {
      "id": "<case-directory-name>",
      "instruction": "Analyze the artifact context and provide a grounded security response.",
      "context": "<contents of context.txt>",
      "target": "<contents of expected_response.md>"
    }
"""

import argparse
import json
import os
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Optional

# Allow importing from src/
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from bola_ai.rag.doc_fact_extractor import DocTypeDetector, DocSection

INSTRUCTION = (
    "Analyze the artifact context and provide a grounded security response."
)

# Minimum character lengths for quality filtering
MIN_CONTEXT_CHARS = 500
MIN_TARGET_CHARS = 300

# Maximum context chars we include (trim very long docs to avoid token blow-out)
MAX_CONTEXT_CHARS = 16_000
MAX_TARGET_CHARS = 8_000

# Section types we actively want more of (rare in current data)
PRIORITY_SECTIONS = {
    DocSection.SQL_SCHEMA,
    DocSection.SOURCE_CODE,
    DocSection.OPENAPI_YAML,
    DocSection.LOG_TRACE,
}


def load_case(case_dir: Path) -> Optional[dict]:
    """Load one training case. Returns None if the case fails quality checks."""
    ctx_path = case_dir / "context.txt"
    resp_path = case_dir / "expected_response.md"

    if not ctx_path.exists() or not resp_path.exists():
        return None

    context = ctx_path.read_text(errors="replace").strip()
    target = resp_path.read_text(errors="replace").strip()

    if len(context) < MIN_CONTEXT_CHARS or len(target) < MIN_TARGET_CHARS:
        return None

    # Trim to token-budget limits
    if len(context) > MAX_CONTEXT_CHARS:
        context = context[:MAX_CONTEXT_CHARS] + "\n...[truncated]"
    if len(target) > MAX_TARGET_CHARS:
        target = target[:MAX_TARGET_CHARS] + "\n...[truncated]"

    return {
        "id": case_dir.name,
        "instruction": INSTRUCTION,
        "context": context,
        "target": target,
    }


def walk_cases(root: Path) -> list[Path]:
    """Return all case directories under root (any depth)."""
    cases: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        if "context.txt" in filenames and "expected_response.md" in filenames:
            cases.append(Path(dirpath))
    return cases


def stratify(
    cases: list[Path],
    max_total: int,
    seed: int = 42,
) -> list[Path]:
    """Select a diverse, stratified subset of cases by section type.

    Priority sections (SQL, code, OpenAPI, logs) are included first.
    The remainder is filled with random sampling from the largest groups.
    """
    rng = random.Random(seed)
    buckets: dict[str, list[Path]] = defaultdict(list)

    for case_dir in cases:
        ctx_path = case_dir / "context.txt"
        try:
            text = ctx_path.read_text(errors="replace")[:3000]
        except OSError:
            continue
        sections = DocTypeDetector.detect(text)
        # Use the most-specific (least common) section as the bucket key
        bucket_key = sections[0].value if sections else "unknown"
        # Prioritize rare sections
        for s in sections:
            if s in PRIORITY_SECTIONS:
                bucket_key = s.value
                break
        buckets[bucket_key].append(case_dir)

    selected: list[Path] = []

    # Fill priority buckets first
    for section in PRIORITY_SECTIONS:
        bucket = buckets.get(section.value, [])
        rng.shuffle(bucket)
        selected.extend(bucket)  # take all rare cases

    selected_set = set(selected)

    # Fill remaining slots from non-priority buckets proportionally
    remaining_slots = max_total - len(selected)
    non_priority = [
        c for c in cases if c not in selected_set
    ]
    rng.shuffle(non_priority)
    selected.extend(non_priority[:max(0, remaining_slots)])

    # Final shuffle so output isn't sorted by section type
    rng.shuffle(selected)
    return selected[:max_total]


def build_output(
    root: Path,
    output: Path,
    max_cases: int,
    stratify_flag: bool,
    seed: int,
    verbose: bool,
) -> None:
    print(f"Scanning for cases under {root} …")
    all_cases = walk_cases(root)
    print(f"Found {len(all_cases)} case directories")

    if stratify_flag:
        selected = stratify(all_cases, max_cases, seed=seed)
        print(f"Stratified selection: {len(selected)} cases")
    else:
        rng = random.Random(seed)
        rng.shuffle(all_cases)
        selected = all_cases[:max_cases]

    records: list[dict] = []
    skipped = 0
    section_stats: dict[str, int] = defaultdict(int)

    for case_dir in selected:
        record = load_case(case_dir)
        if record is None:
            skipped += 1
            continue

        # Track section type stats
        text = (case_dir / "context.txt").read_text(errors="replace")[:3000]
        for s in DocTypeDetector.detect(text):
            section_stats[s.value] += 1

        records.append(record)
        if verbose:
            print(f"  + {case_dir.name}")

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"\nWrote {len(records)} records to {output}  (skipped {skipped})")
    print("\nSection type coverage:")
    for k, v in sorted(section_stats.items(), key=lambda x: -x[1]):
        print(f"  {k}: {v} ({100*v//len(records) if records else 0}%)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        default="data/training/reviewing",
        help="Root reviewing directory (default: data/training/reviewing)",
    )
    parser.add_argument(
        "--output",
        default="data/training/sft/reviewing_combined.jsonl",
        help="Output JSONL file (default: data/training/sft/reviewing_combined.jsonl)",
    )
    parser.add_argument(
        "--max",
        type=int,
        default=500,
        help="Maximum number of training examples to emit (default: 500)",
    )
    parser.add_argument(
        "--stratify",
        action="store_true",
        help="Stratify by document section type to ensure diversity",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print each accepted case name",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).parent.parent
    build_output(
        root=repo_root / args.input,
        output=repo_root / args.output,
        max_cases=args.max,
        stratify_flag=args.stratify,
        seed=args.seed,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
