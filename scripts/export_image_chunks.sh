#!/bin/sh
# Export the BOLA AI Docker image to a tar and split into chunked files for transfer to an offline machine.
# Usage: from repo root, run:
#   sh scripts/export_image_chunks.sh [OUTPUT_DIR] [CHUNK_SIZE_MB]
# Example: sh scripts/export_image_chunks.sh ./export 100
# Creates OUTPUT_DIR/bola-ai-image.tar.part-* (default: ./export, 100MB chunks).
# Requires: docker (image docker-bola-ai:latest must exist; build with docker compose -f docker/docker-compose.yml build bola-ai).

set -e
OUT_DIR="${1:-./export}"
CHUNK_MB="${2:-100}"
IMAGE_NAME="${BOLA_AI_IMAGE_NAME:-docker-bola-ai:latest}"
mkdir -p "$OUT_DIR"
TAR="$OUT_DIR/bola-ai-image.tar"

echo "Saving image $IMAGE_NAME to $TAR ..."
docker save "$IMAGE_NAME" -o "$TAR"
echo "Splitting into ${CHUNK_MB}MB chunks ..."
split -b "${CHUNK_MB}M" "$TAR" "$TAR.part-"
echo "Done. Chunks: $TAR.part-*"
echo "Transfer these files to the target machine, then run: sh scripts/import_image_chunks.sh <dir>"
