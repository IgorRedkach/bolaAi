#!/usr/bin/env python3
"""Reorganize /data/training/reviewing into a stable hierarchical structure.

New layout:
  reviewing/
    folder-with-hundreds-folders-N/     (up to 10 ten-folder groups = 1000 examples)
      folder-with-ten-folders-N/        (up to 10 files-to-train groups = 100 examples)
        folder-with-files-to-train-N/   (up to 10 individual example folders)
          EXAMPLE-XXXX/
            context.txt
            expected_response.md
            analysis_explanation.md

Seed .txt files at the reviewing root are left in place.

Usage:
    python scripts/reorganize_reviewing.py [--dry-run]
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

REVIEWING_ROOT = Path(__file__).resolve().parents[1] / "data" / "training" / "reviewing"

FILES_PER_TRAIN_FOLDER = 10      # example folders per files-to-train group
TRAIN_PER_TEN_FOLDER = 10        # files-to-train groups per ten-folder group
TEN_PER_HUNDRED_FOLDER = 10      # ten-folder groups per hundreds-folder group


def is_example_folder(p: Path) -> bool:
    """Return True if p looks like a leaf example folder (has context.txt or expected_response.md)."""
    if not p.is_dir():
        return False
    children = {c.name for c in p.iterdir()}
    return bool(children & {"context.txt", "expected_response.md", "analysis_explanation.md"})


def collect_existing_leaf_folders(root: Path) -> list[Path]:
    """Collect all current leaf example folders in BFS order, skipping the new hierarchy roots."""
    leaves: list[Path] = []
    for candidate in sorted(root.iterdir()):
        if not candidate.is_dir():
            continue
        # Skip already-reorganized hierarchy folders
        name = candidate.name
        if name.startswith("folder-with-"):
            # Recurse inside to collect any leaves that may already be there
            for sub in sorted(candidate.rglob("*")):
                if is_example_folder(sub):
                    leaves.append(sub)
            continue
        if is_example_folder(candidate):
            leaves.append(candidate)
    return leaves


def destination_path(leaf_index: int, root: Path) -> Path:
    """Compute the canonical destination path for the Nth leaf (0-based)."""
    # Which files-to-train group (0-based)?
    train_group_idx = leaf_index // FILES_PER_TRAIN_FOLDER          # 0..
    ten_group_idx   = train_group_idx // TRAIN_PER_TEN_FOLDER        # 0..
    hundred_group_idx = ten_group_idx // TEN_PER_HUNDRED_FOLDER      # 0..

    train_local  = (train_group_idx % TRAIN_PER_TEN_FOLDER) + 1      # 1-based within parent
    ten_local    = (ten_group_idx   % TEN_PER_HUNDRED_FOLDER) + 1
    hundred_num  = hundred_group_idx + 1

    hundreds_name = f"folder-with-hundreds-folders-{hundred_num}"
    tens_name     = f"folder-with-ten-folders-{ten_local}"
    train_name    = f"folder-with-files-to-train-{train_local}"

    return root / hundreds_name / tens_name / train_name


def main() -> None:
    parser = argparse.ArgumentParser(description="Reorganize reviewing folder")
    parser.add_argument("--dry-run", action="store_true", help="Print moves without executing")
    parser.add_argument("--root", default=str(REVIEWING_ROOT), help="Path to reviewing root")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    dry = args.dry_run

    leaves = collect_existing_leaf_folders(root)
    print(f"Found {len(leaves)} leaf example folder(s)")

    moved = 0
    skipped = 0
    for idx, leaf in enumerate(leaves):
        dest_parent = destination_path(idx, root)
        dest = dest_parent / leaf.name

        # Already in correct location?
        if leaf.parent == dest_parent:
            skipped += 1
            continue

        if dry:
            print(f"[DRY] mv {leaf.relative_to(root)} -> {dest.relative_to(root)}")
        else:
            dest_parent.mkdir(parents=True, exist_ok=True)
            if dest.exists():
                # Avoid clobbering; append suffix
                dest = dest_parent / (leaf.name + f"_dup{idx}")
            shutil.move(str(leaf), str(dest))
            print(f"mv  {leaf.relative_to(root)} -> {dest.relative_to(root)}")
            moved += 1

    if dry:
        print(f"\n[DRY RUN] Would move {len(leaves) - skipped} folder(s), {skipped} already in place.")
    else:
        print(f"\nMoved {moved}, skipped {skipped} (already in place).")

    # Remove now-empty old top-level directories
    if not dry:
        for candidate in sorted(root.iterdir()):
            if not candidate.is_dir():
                continue
            name = candidate.name
            if name.startswith("folder-with-"):
                continue
            # It's an old-style directory at root level - should now be empty
            try:
                candidate.rmdir()
                print(f"rmdir {candidate.name}")
            except OSError:
                pass  # Not empty, leave it


if __name__ == "__main__":
    main()
