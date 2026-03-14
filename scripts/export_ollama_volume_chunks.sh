#!/bin/sh
# Export the Ollama model volume to a tar and split into chunks (for offline transfer).
# Run after one-time online setup (OLLAMA_ONLINE_SETUP=1) so the volume contains bola-analyzer.
# Usage: sh scripts/export_ollama_volume_chunks.sh [VOLUME_NAME] [OUTPUT_DIR] [CHUNK_SIZE_MB]
# Default volume: docker_ollama_data (from compose project name "docker"). Output: ./export, 100MB chunks.

set -e
VOLUME="${1:-docker_ollama_data}"
OUT_DIR="${2:-./export}"
CHUNK_MB="${3:-100}"
mkdir -p "$OUT_DIR"
TAR="$OUT_DIR/bola-ollama-data.tar"

echo "Exporting volume $VOLUME to $TAR ..."
docker run --rm -v "$VOLUME":/data -v "$(pwd)/$OUT_DIR":/out alpine tar cf /out/bola-ollama-data.tar -C /data .
echo "Splitting into ${CHUNK_MB}MB chunks ..."
split -b "${CHUNK_MB}M" "$OUT_DIR/bola-ollama-data.tar" "$OUT_DIR/bola-ollama-data.tar.part-"
echo "Done. Chunks: $OUT_DIR/bola-ollama-data.tar.part-*"
echo "On target machine: cat .../bola-ollama-data.tar.part-* > bola-ollama-data.tar"
echo "  docker volume create $VOLUME"
echo "  docker run --rm -v $VOLUME:/data -v \$(pwd):/in alpine sh -c 'tar xf /in/bola-ollama-data.tar -C /data'"
