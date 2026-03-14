#!/bin/sh
# Reassemble chunked tar and load into Docker (for offline deployment).
# Usage: sh scripts/import_image_chunks.sh [DIR_WITH_PARTS]
# DIR_WITH_PARTS should contain bola-ai-image.tar.part-* (from export_image_chunks.sh).
# Creates bola-ai-image.tar in that dir, runs docker load, then removes the reassembled tar.

set -e
DIR="${1:-.}"
PARTS="$DIR/bola-ai-image.tar.part-*"
TAR="$DIR/bola-ai-image.tar"

if ! ls $PARTS 1>/dev/null 2>&1; then
  echo "No parts found: $PARTS"
  exit 1
fi
echo "Reassembling $TAR from chunks ..."
cat $PARTS > "$TAR"
echo "Loading image into Docker ..."
docker load -i "$TAR"
echo "Done. Remove reassembled tar if desired: rm $TAR"
