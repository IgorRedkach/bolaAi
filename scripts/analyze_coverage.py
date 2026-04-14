#!/usr/bin/env python3
"""Analyse all reviewing examples and build vulnerability coverage statistics.

For each leaf folder, reads expected_response.md and analysis_explanation.md
to extract which vulnerability patterns are covered, then builds:
  docs/coverage_statistics.json   — machine-readable pattern→count map
  docs/COVERAGE_REPORT.md         — human-readable summary with gaps highlighted

Memory-efficient: loads one folder at a time and immediately discards the text.

Usage:
    python scripts/analyze_coverage.py
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from training.reviewing_iter import iter_leaf_folders

REPO_ROOT = Path(__file__).resolve().parents[1]
REVIEWING_ROOT = REPO_ROOT / "data" / "training" / "reviewing"
OUT_JSON  = REPO_ROOT / "docs" / "coverage_statistics.json"
OUT_MD    = REPO_ROOT / "docs" / "COVERAGE_REPORT.md"

# All known pattern IDs from bola_patterns.md
ALL_PATTERNS = [
    "1.1","1.2","1.3","1.4","1.5","1.6","1.7","1.8","1.9","1.10","1.11","1.12","1.13",
    "2.1","2.2","2.3","2.4","2.5",
    "3.1","3.2","3.3","3.4","3.5",
    "4.1","4.2","4.3","4.4","4.5",
    "5.1","5.2","5.3","5.4",
    "6.1","6.2","6.3","6.4","6.5",
    "7.1","7.2","7.3","7.4",
    "8.1","8.2","8.3","8.4","8.5",
    "9.1","9.2","9.4","9.5",
    "10.1","10.2","10.3","10.4","10.5","10.6",
]

PATTERN_RE = re.compile(r"[Pp]attern\s+(\d+\.\d+)|\((\d+\.\d+)\)|P(\d+\.\d+)-|GQL-\d+-|BOLA-\d+-P(\d+\d+)")


def _extract_patterns_from_text(text: str) -> list[str]:
    """Extract all pattern IDs mentioned in text."""
    found = set()
    # Standard "Pattern X.Y" or "(X.Y)"
    for m in re.finditer(r"[Pp]attern\s+(\d+\.\d+)|\((\d+\.\d+)\)", text):
        pid = m.group(1) or m.group(2)
        if pid and pid in ALL_PATTERNS:
            found.add(pid)
    # Folder name like BOLA-0001-P11-... → Pattern 1.1
    # This is a fallback but we don't do it on text
    return list(found)


def _extract_patterns_from_folder(leaf: Path) -> list[str]:
    """Extract pattern IDs from an example folder (one folder at a time)."""
    found = set()
    for fname in ("expected_response.md", "analysis_explanation.md", "context.txt"):
        fpath = leaf / fname
        if fpath.exists():
            try:
                text = fpath.read_text(encoding="utf-8", errors="ignore")
                found.update(_extract_patterns_from_text(text))
            except Exception:
                pass
    # Also try to infer from folder name (BOLA-0001-P11 -> 1.1)
    name = leaf.name
    m = re.search(r"-P(\d+)(\d+)-", name)
    if m:
        pid = f"{m.group(1)}.{m.group(2)}"
        if pid in ALL_PATTERNS:
            found.add(pid)
    # GQL/SF/INJ patterns often reference multiple patterns - also check the name
    if name.startswith("GQL-"):
        # GraphQL examples mostly cover 1.1, 1.3, 1.5, 1.9, 5.2, 6.1, 9.1
        pass  # already extracted from file content
    return list(found)


def main() -> None:
    print(f"Scanning: {REVIEWING_ROOT}")
    coverage: dict[str, int] = defaultdict(int)
    folder_count = 0
    zero_match = 0

    for leaf in iter_leaf_folders(REVIEWING_ROOT):
        folder_count += 1
        patterns = _extract_patterns_from_folder(leaf)
        if not patterns:
            zero_match += 1
        for pid in patterns:
            coverage[pid] += 1
        # Release memory immediately
        del patterns

    # Build stats
    stats = {pid: coverage.get(pid, 0) for pid in ALL_PATTERNS}
    under_50 = {pid: cnt for pid, cnt in stats.items() if cnt < 50}
    under_10 = {pid: cnt for pid, cnt in stats.items() if cnt < 10}
    zero = {pid: cnt for pid, cnt in stats.items() if cnt == 0}

    # Write JSON
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(stats, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Written: {OUT_JSON}")

    # Write Markdown report
    lines = [
        "# Vulnerability Coverage Report",
        "",
        f"**Total example folders scanned:** {folder_count}",
        f"**Folders with no pattern detected:** {zero_match}",
        f"**Patterns with <50 examples:** {len(under_50)}",
        f"**Patterns with <10 examples:** {len(under_10)}",
        f"**Patterns with 0 examples:** {len(zero)}",
        "",
        "## Coverage Table",
        "",
        "| Pattern ID | Count | Status |",
        "|-----------|-------|--------|",
    ]
    for pid in ALL_PATTERNS:
        cnt = stats.get(pid, 0)
        if cnt == 0:
            status = "❌ NONE"
        elif cnt < 10:
            status = "⚠️  CRITICAL GAP"
        elif cnt < 50:
            status = "🔶 LOW"
        elif cnt < 100:
            status = "🔷 MODERATE"
        else:
            status = "✅ GOOD"
        lines.append(f"| {pid} | {cnt} | {status} |")

    lines += [
        "",
        "## Under-Represented Patterns (<50 examples)",
        "",
    ]
    for pid, cnt in sorted(under_50.items(), key=lambda x: x[1]):
        lines.append(f"- **Pattern {pid}**: {cnt} examples")

    lines += [
        "",
        "## Gap-Filling Priority",
        "",
        "The following patterns should be prioritised in Step 9 (2000 gap-filling examples):",
        "",
    ]
    priority = sorted(under_50.items(), key=lambda x: x[1])[:20]
    for pid, cnt in priority:
        needed = max(0, 50 - cnt)
        lines.append(f"- Pattern {pid}: needs **{needed}** more examples (currently {cnt})")

    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Written: {OUT_MD}")

    # Print summary
    print(f"\nCoverage summary:")
    print(f"  Total folders: {folder_count}")
    print(f"  Patterns under 50: {len(under_50)}")
    print(f"  Patterns at zero: {len(zero)}")
    if zero:
        print(f"  Zero-coverage patterns: {sorted(zero.keys())}")


if __name__ == "__main__":
    main()
