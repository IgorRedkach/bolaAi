# Offline Deployment (No Internet)

The tool is designed to **run without any requests to the open internet**. You can deploy it on an air-gapped machine by transferring the built image and (optionally) the Ollama model data in **chunks**, then reassembling and running locally.

## Principles

- **At runtime:** No outbound requests. Ollama and the app talk only to each other; no model pull or update checks.
- **Deployment:** The built image and model volume can be exported, split into chunked files, moved (e.g. USB, internal transfer), reassembled, and loaded on the target machine.

## Default Docker behavior (offline)

- `docker compose -f docker/docker-compose.yml up -d` runs in **offline mode**: Ollama starts and serves only; it does **not** pull any model from the internet.
- The **bola-analyzer** model must already be present in the `ollama_data` volume (e.g. from a previous online setup or from an imported chunked bundle).

## Option A: One-time online setup, then offline

On a machine **with** internet:

1. Build and start with online setup (pull model once):
   ```bash
   OLLAMA_ONLINE_SETUP=1 docker compose -f docker/docker-compose.yml up -d
   ```
2. Wait until the ollama service is healthy (model created).
3. Stop the stack: `docker compose -f docker/docker-compose.yml down` (do **not** use `-v` so the volume is kept).
4. Export the image and the ollama volume as chunked files (see “Export by chunks” below).
5. Transfer the chunked files to the target (air-gapped) machine.
6. On the target machine: import from chunks and run (see “Import and run” below). From then on, run with normal `docker compose up -d` (no internet).

## Option B: Import a pre-built bundle (fully offline)

If someone else has already built the image and exported the model volume:

1. Get the chunked files (e.g. `bola-ai-image.tar.part-*`, `bola-ollama-data.tar.part-*`).
2. On the target machine: reassemble and load (see “Import and run” below).
3. Run: `docker compose -f docker/docker-compose.yml up -d`. No internet required.

## Export by chunks

From the repo root, on a machine where the image (and optionally the ollama volume) exists:

```bash
# Export app image to a tar and split into 100MB chunks
docker save docker-bola-ai:latest -o /tmp/bola-ai-image.tar
split -b 100M /tmp/bola-ai-image.tar bola-ai-image.tar.part-

# Optional: export Ollama model volume (after online setup) so the target has the model
docker run --rm -v docker_ollama_data:/data -v /tmp:/out alpine tar cf /out/bola-ollama-data.tar -C /data .
split -b 100M /tmp/bola-ollama-data.tar bola-ollama-data.tar.part-
```

Transfer the `bola-ai-image.tar.part-*` (and if used, `bola-ollama-data.tar.part-*`) files to the target machine (e.g. USB or internal transfer). The exact volume name may be `docker_ollama_data` or `<project>_ollama_data` depending on the compose project name.

## Import and run (target / air-gapped machine)

On the target machine (no internet):

```bash
# Reassemble app image and load
cat bola-ai-image.tar.part-* > bola-ai-image.tar
docker load -i bola-ai-image.tar

# Optional: create and fill Ollama volume from chunks
cat bola-ollama-data.tar.part-* > bola-ollama-data.tar
docker volume create docker_ollama_data
docker run --rm -v docker_ollama_data:/data -v "$(pwd)":/in alpine sh -c "tar xf /in/bola-ollama-data.tar -C /data"

# Run the stack (offline)
cd /path/to/bolaAi
docker compose -f docker/docker-compose.yml up -d
```

Use the same volume name as in your compose file (check with `docker volume ls` after a first run if needed).

## Scripts

- **scripts/export_image_chunks.sh** — Exports the built image to a tar and splits it into chunks (e.g. for USB transfer).
- **scripts/import_image_chunks.sh** — Reassembles chunked tar and runs `docker load` on the target machine.
- **scripts/export_ollama_volume_chunks.sh** — Exports the Ollama model volume to a chunked tar (run after one-time online setup).

See script headers for usage and required env/paths.

## Embedder and RAG (app container)

- The **embedding model** (sentence-transformers) can try to reach the internet on first load if not cached. For strict offline, either:
  - Use **BOLA_AI_FAKE_EMBEDDER=1** (no external model), or
  - Pre-cache the embedder on a connected machine so the offline host has the cache in the image or a mounted path.
- RAG preload uses data baked into the image or in `/app/data`; no network required when preload runs inside the container.
