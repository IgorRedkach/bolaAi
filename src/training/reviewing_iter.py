"""Utilities for walking the hierarchical reviewing folder structure.

The reviewing folder uses a 3-level hierarchy:
  reviewing/
    folder-with-hundreds-folders-N/
      folder-with-ten-folders-N/
        folder-with-files-to-train-N/
          <EXAMPLE-FOLDER>/
            context.txt
            expected_response.md
            analysis_explanation.md

Public API
----------
iter_leaf_folders(reviewing_root) -> Iterator[Path]
    Yields every leaf example folder (containing the three teaching files)
    regardless of nesting depth.  Also handles legacy flat folders still at root.

next_example_folder(reviewing_root, prefix="EX") -> Path
    Returns the Path where the next new example should be placed (does NOT
    create the directory).  Respects the 10-per-group limit at every level.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator


EXAMPLE_FILES = {"context.txt", "expected_response.md", "analysis_explanation.md"}

FILES_PER_TRAIN = 10      # max example folders per files-to-train group
TRAINS_PER_TEN  = 10      # max files-to-train groups per ten-folder group
TENS_PER_HUNDRED = 10     # max ten-folder groups per hundreds-folder group


def _is_leaf(p: Path) -> bool:
    """True if p is an example leaf folder (has at least one of the teaching files)."""
    if not p.is_dir():
        return False
    names = {c.name for c in p.iterdir()}
    return bool(names & EXAMPLE_FILES)


def iter_leaf_folders(reviewing_root: Path) -> Iterator[Path]:
    """Yield every leaf example folder under reviewing_root, sorted by path."""
    root = Path(reviewing_root)
    for candidate in sorted(root.rglob("*")):
        if _is_leaf(candidate):
            # Skip if it is a parent that also happens to have files (unlikely but safe)
            # by checking none of its children are also leaves
            yield candidate


def _count_leaves(directory: Path) -> int:
    """Count direct children that are leaf example folders."""
    return sum(1 for c in directory.iterdir() if c.is_dir() and _is_leaf(c))


def _next_train_folder(hundreds: Path, tens: Path) -> Path:
    """Return or create the files-to-train sub-folder that still has room."""
    existing = sorted(
        (c for c in tens.iterdir() if c.is_dir() and c.name.startswith("folder-with-files-to-train-")),
        key=lambda p: int(p.name.rsplit("-", 1)[-1]),
    )
    for train in existing:
        if _count_leaves(train) < FILES_PER_TRAIN:
            return train
    # Need a new one
    next_num = (int(existing[-1].name.rsplit("-", 1)[-1]) + 1) if existing else 1
    return tens / f"folder-with-files-to-train-{next_num}"


def _next_ten_folder(hundreds: Path) -> Path:
    """Return or create the ten-folder that still has room for a files-to-train group."""
    existing = sorted(
        (c for c in hundreds.iterdir() if c.is_dir() and c.name.startswith("folder-with-ten-folders-")),
        key=lambda p: int(p.name.rsplit("-", 1)[-1]),
    )
    for tens in existing:
        # Check if there's room for at least one more files-to-train group
        train_groups = [c for c in tens.iterdir() if c.is_dir() and c.name.startswith("folder-with-files-to-train-")]
        if len(train_groups) < TRAINS_PER_TEN:
            return tens
        # Check if existing train groups still have room
        for tg in train_groups:
            if _count_leaves(tg) < FILES_PER_TRAIN:
                return tens
    next_num = (int(existing[-1].name.rsplit("-", 1)[-1]) + 1) if existing else 1
    return hundreds / f"folder-with-ten-folders-{next_num}"


def _next_hundreds_folder(root: Path) -> Path:
    """Return or create the hundreds-folder that has room."""
    existing = sorted(
        (c for c in root.iterdir() if c.is_dir() and c.name.startswith("folder-with-hundreds-folders-")),
        key=lambda p: int(p.name.rsplit("-", 1)[-1]),
    )
    for hundreds in existing:
        # Check capacity: TENS_PER_HUNDRED × TRAINS_PER_TEN × FILES_PER_TRAIN
        capacity = TENS_PER_HUNDRED * TRAINS_PER_TEN * FILES_PER_TRAIN
        current = sum(1 for _ in iter_leaf_folders(hundreds))
        if current < capacity:
            return hundreds
    next_num = (int(existing[-1].name.rsplit("-", 1)[-1]) + 1) if existing else 1
    return root / f"folder-with-hundreds-folders-{next_num}"


def next_example_folder(reviewing_root: Path, name: str) -> Path:
    """Return the full path where the next example folder named `name` should be placed.

    Creates intermediate hierarchy directories as needed.
    Does NOT create the leaf folder itself.
    """
    root = Path(reviewing_root)
    hundreds = _next_hundreds_folder(root)
    hundreds.mkdir(parents=True, exist_ok=True)

    tens = _next_ten_folder(hundreds)
    tens.mkdir(parents=True, exist_ok=True)

    train = _next_train_folder(hundreds, tens)
    train.mkdir(parents=True, exist_ok=True)

    return train / name
