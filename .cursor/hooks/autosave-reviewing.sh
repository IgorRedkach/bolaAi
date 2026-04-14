#!/bin/bash
# Auto-commit training reviewing edits after each file write.
# Triggered by afterFileEdit for paths matching data/training/reviewing.

input=$(cat)
file=$(echo "$input" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('path',''))" 2>/dev/null)

if [[ -z "$file" ]]; then
  exit 0
fi

cd "$(git -C "$(dirname "$file")" rev-parse --show-toplevel 2>/dev/null)" 2>/dev/null || exit 0

git add "$file" docs/REVIEW_FIX_PLAN.md 2>/dev/null

basename=$(basename "$file")
folder=$(basename "$(dirname "$file")")

if git diff --cached --quiet; then
  exit 0
fi

git commit -m "review: fix $folder/$basename" --no-gpg-sign 2>/dev/null

exit 0
