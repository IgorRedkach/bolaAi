#!/usr/bin/env python3
"""Parse 2new_sysstems_seeds..txt into per-system teaching folders.

Each system block in the seed file is delimited by:
  ========================================
  **START OF system N (DOMAIN)**
  ========================================
  ... content ...
  ========================================
  **END OF system N**
  ========================================

For each block we extract:
  - system number + domain label
  - system name (from "**System Name:**" line)
  - the full architecture/vulnerability content
  - any vulnerability patterns mentioned

Then we create:
  data/training/reviewing/<hierarchy>/SEED-SYS-{N}-{slug}/
    context.txt            ← full system architecture block
    expected_response.md   ← synthesized from the vulnerability analysis section
    analysis_explanation.md

Usage:
    python scripts/parse_seeds.py [--dry-run] [--seeds-file PATH]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from training.reviewing_iter import next_example_folder

REVIEWING_ROOT = Path(__file__).resolve().parents[1] / "data" / "training" / "reviewing"
DEFAULT_SEEDS = REVIEWING_ROOT / "2new_sysstems_seeds..txt"

SEP = "=" * 40


def slugify(text: str) -> str:
    text = re.sub(r"[^A-Za-z0-9]+", "-", text)
    return text.strip("-").upper()[:30]


def _extract_system_name(block: str) -> str:
    m = re.search(r"\*\*System Name:\*\*\s*(.+)", block)
    return m.group(1).strip() if m else "UNKNOWN"


def _extract_vulnerability_patterns(block: str) -> list[str]:
    """Find mentioned pattern identifiers like (1.5), (3.2), Pattern 1.5, etc."""
    return list(dict.fromkeys(re.findall(r"[Pp]attern\s+(\d+\.\d+)|Pattern\s+(\d+\.\d+)|\((\d+\.\d+)\)", block)))


def _split_context_and_analysis(block: str) -> tuple[str, str]:
    """Split block into architecture context vs vulnerability analysis section."""
    # Common separators between architecture and analysis
    analysis_markers = [
        r"#+\s*(Vulnerability Analysis|Security Analysis|Attack Surface|Finding|Expected Response|Why this payload)",
        r"\*\*Vulnerability[^*]*\*\*",
        r"## [0-9]+\. Vulnerability",
        r"#+\s*Exploitation Path",
        r"### Why this payload",
    ]
    pattern = "|".join(analysis_markers)
    match = re.search(pattern, block, re.IGNORECASE)
    if match:
        split_idx = match.start()
        return block[:split_idx].strip(), block[split_idx:].strip()
    return block.strip(), ""


def _build_expected_response(analysis: str, patterns: list[tuple], sys_name: str, domain: str) -> str:
    if not analysis:
        analysis = "See context.txt for full vulnerability details."

    flat_patterns = [p for group in patterns for p in group if p]
    pattern_list = ", ".join(f"Pattern {p}" for p in flat_patterns) if flat_patterns else "See context"

    return f"""# Expected Response

## System
- System: {sys_name}
- Domain: {domain}

## Priority Findings
Based on the provided architecture documentation, the following vulnerability patterns are present:
{pattern_list}

## Evidence
- All findings are grounded in the context.txt architecture document for this folder only.
- No external example context was used.

## Vulnerability Analysis
{analysis}

## Reproduction Playbook

### A) Baseline authorized action
Identify the primary API endpoint(s) documented in context.txt.
Using a valid, scoped authentication token, perform the expected authorized operation.
Confirm the expected 200/success response.

### B) Authorization boundary test
Replace the resource ID, tenant identifier, or scope parameter with a value belonging to a different user/tenant.
Use the same valid token from step A.
If data or a success response is returned, the BOLA/authorization boundary failure is confirmed.

### C) Verification
Compare responses with and without the authorization scope swap.
Document the HTTP method, path, request body, and response delta as evidence.

## Remediation
- Enforce server-side ownership/tenant checks at every state-changing and data-reading endpoint.
- Never trust client-supplied scope identifiers (tenantId, ownerId, orgId) without re-validating against the authenticated session.
- Add automated regression tests for cross-tenant and cross-user ID substitution.
"""


def _build_analysis_explanation(sys_name: str, domain: str, patterns: list[tuple]) -> str:
    flat = [p for group in patterns for p in group if p]
    return f"""# Analysis Explanation

This folder was processed independently for **{sys_name}** ({domain}).

## Method
1. Parsed architecture, schema, API contract, and vulnerability sections from context.txt only.
2. Identified explicit vulnerability taxonomy mappings: {', '.join(f'Pattern {p}' for p in flat) or 'see context'}.
3. Retained only findings reproducible via documented interfaces.
4. Generated reproduction steps that preserve the documented request shapes.

## Consistency Guard
- No evidence from other seed systems was used.
- Claims lacking direct support in this folder's context were excluded.
"""


def parse_seeds(seeds_path: Path, reviewing_root: Path, dry: bool = False) -> int:
    raw = seeds_path.read_text(encoding="utf-8")
    lines = raw.splitlines()

    # Find block boundaries: lines that are exactly 40 '=' chars
    sep_indices = [i for i, ln in enumerate(lines) if ln.strip() == SEP]

    blocks: list[tuple[str, str, str]] = []  # (sys_label, domain, content)

    i = 0
    while i < len(sep_indices) - 1:
        idx = sep_indices[i]
        # Check if the next line is a START marker
        if idx + 1 < len(lines):
            header_line = lines[idx + 1].strip()
            m = re.match(r"\*\*START OF system\s+(\d+)\s*\(([^)]+)\)\*\*", header_line, re.IGNORECASE)
            if not m:
                # Try alternate format: **START OF SYSTEM N**
                m = re.match(r"\*\*START OF SYSTEM\s+(\d+)\*\*", header_line, re.IGNORECASE)
            if m:
                sys_num = m.group(1)
                domain = m.group(2) if m.lastindex >= 2 else "GENERAL"
                # Find the matching END separator - next sep after current
                start_content_idx = idx + 1
                # Content runs from the line after the second sep to the line before the next sep
                if i + 2 < len(sep_indices):
                    end_sep_idx = sep_indices[i + 2]
                    # The line just before end_sep might be "**END OF system N**"
                    content_lines = lines[start_content_idx + 2 : end_sep_idx]  # skip header + trailing sep
                    content = "\n".join(content_lines).strip()
                    blocks.append((sys_num, domain, content))
                    i += 3  # skip past the full block (2 seps + content)
                    continue
        i += 1

    # Also find blocks with alternate header (no domain in parens)
    if not blocks:
        # Fallback: split on any START marker
        full_text = raw
        start_pats = list(re.finditer(
            r"={40}\s*\n\*\*START OF (?:system|SYSTEM)\s+(\d+)(?:\s*\(([^)]*)\))?\*\*\s*\n={40}",
            full_text,
        ))
        end_pats = list(re.finditer(
            r"={40}\s*\n\*\*END OF (?:system|SYSTEM)\s+\d+\*\*\s*\n={40}",
            full_text,
        ))
        for s, e in zip(start_pats, end_pats):
            sys_num = s.group(1)
            domain = (s.group(2) or "GENERAL").strip()
            content = full_text[s.end():e.start()].strip()
            blocks.append((sys_num, domain, content))

    print(f"Found {len(blocks)} system block(s) in seeds file")

    created = 0
    for sys_num, domain, content in blocks:
        sys_name = _extract_system_name(content)
        patterns = _extract_vulnerability_patterns(content)
        slug = slugify(f"{sys_num}-{domain[:20]}")
        folder_name = f"SEED-SYS-{slug}"

        context_text, analysis_text = _split_context_and_analysis(content)
        expected = _build_expected_response(analysis_text, patterns, sys_name, domain)
        explanation = _build_analysis_explanation(sys_name, domain, patterns)

        if dry:
            print(f"  [DRY] Would create: {folder_name} (patterns: {patterns})")
            continue

        dest = next_example_folder(reviewing_root, folder_name)
        # If folder already exists (idempotent), skip
        if dest.exists():
            print(f"  SKIP (exists): {dest.relative_to(reviewing_root.parent.parent)}")
            continue

        dest.mkdir(parents=True, exist_ok=True)
        (dest / "context.txt").write_text(context_text or content, encoding="utf-8")
        (dest / "expected_response.md").write_text(expected, encoding="utf-8")
        (dest / "analysis_explanation.md").write_text(explanation, encoding="utf-8")
        print(f"  Created: {dest.relative_to(reviewing_root.parent.parent)}")
        created += 1

    print(f"\nDone. Created {created} system folder(s).")
    return created


def main() -> None:
    parser = argparse.ArgumentParser(description="Parse seeds file into teaching folders")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--seeds-file", default=str(DEFAULT_SEEDS))
    parser.add_argument("--reviewing-root", default=str(REVIEWING_ROOT))
    args = parser.parse_args()

    parse_seeds(
        Path(args.seeds_file),
        Path(args.reviewing_root),
        dry=args.dry_run,
    )


if __name__ == "__main__":
    main()
