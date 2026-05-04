# BOLA AI

Portable, local-only AI agent that finds security vulnerabilities by analyzing API documentation, HAR captures, OpenAPI specs, and log traces. Covers BOLA/IDOR, broken access control, insecure design, integrity failures, injection, misconfiguration, and logging gaps.

Runs entirely offline inside a single Docker container — no cloud, no API keys, no internet at runtime.

---

## Quickest start

1. Drop your files (HAR captures, API docs, OpenAPI specs) into a local folder first:

```bash
mkdir -p ~/Downloads/shared
cp your-api-capture.har ~/Downloads/shared/
```

2. Start the container:

```bash
docker run -p 8000:8000 -v ~/Downloads/shared:/shared-docs ghcr.io/igorredkach/bolai:latest
```

3. Open **http://localhost:8000/chat** in your browser.

The container auto-ingests every file in the shared folder on startup and runs a security analysis pass automatically — findings appear in the chat without you having to type anything.

The tool makes no outbound network calls during analysis — everything runs locally inside the container.

---

## What it does

1. **Ingest** — paste or upload your artifact (HAR file, OpenAPI YAML, architecture doc, log trace).
2. **Analyze** — the agent finds authorization gaps, enumeration opportunities, logic flaws, and more.
3. **Report** — receives structured findings with evidence quotes, threat hypotheses, and copy-pasteable `curl` verification commands.

Two analysis modes run automatically:

- **PRISM-HAR pipeline** — activated when the input is a HAR file. Deterministically extracts structured facts, sends them to the fine-tuned `bola-har` specialist model under grammar constraints, validates each finding against extracted facts, and renders deterministic curl PoC commands. No hallucinated endpoints.
- **General pipeline** — for all other inputs (docs, specs, logs). Uses RAG retrieval against a pre-loaded security knowledge base + the `bola-analyzer` model.

---

## Web UI

Visit `http://localhost:8000/chat` after `docker run`. The chat interface lets you:

- Upload files via the UI or reference files already in `/shared-docs`
- Type `ingest <filename>` to ingest a file from the shared volume
- Type `analyze` or ask a question to trigger analysis
- Read findings with markdown rendering directly in the browser

---

## REST API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Web chat UI |
| `GET` | `/health` | Health check: Ollama status, chunk count, auto-ingest state |
| `POST` | `/ingest` | Upload a file or paste text (`multipart/form-data`: `file` or `content` + `source`) |
| `POST` | `/ingest_shared` | Ingest a file by name from the `/shared-docs` volume |
| `POST` | `/analyze` | Run analysis. Optional JSON body: `{"query": "..."}` |
| `GET` | `/api/auto_analysis` | Retrieve the cached result of the startup auto-analysis |
| `POST` | `/reset` | Wipe user-ingested documents (keeps the pre-loaded knowledge base) |

Example with `curl`:

```bash
# Ingest a HAR file
curl -X POST http://localhost:8000/ingest \
  -F "file=@/path/to/capture.har" -F "source=capture.har"

# Run analysis
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"query": "Check for IDOR in user endpoints"}' \
  -m 360
```

---

## CLI

With the container (or local API) running on port 8000:

```bash
pip install -e .

bola-ai health --wait
bola-ai ingest --file docs/openapi.yaml --source openapi
bola-ai analyze
bola-ai analyze --query "Check for privilege escalation in admin routes"
```

Override API URL: `bola-ai --api http://localhost:8000 health`

---

## docker compose

The `docker-compose.yml` in the repo root wraps the same all-in-one image with named volumes for easier lifecycle management:

```bash
# Copy your files to shared_docs/ first (auto-ingested on startup)
cp your-capture.har shared_docs/

docker compose up -d
# Open http://localhost:8000/chat

docker compose logs -f bola-ai
docker compose down            # keep volumes (data persists)
docker compose down -v         # wipe all data (clean slate)
```

---

## Configuration

Key environment variables (all optional):

| Variable | Default | Description |
|----------|---------|-------------|
| `BOLA_AI_SHARED_DOCS_DIR` | `/shared-docs` | Path scanned for auto-ingest on startup |
| `BOLA_AI_LLM_CHAT_TIMEOUT` | `900` | Max seconds for one LLM reply |
| `BOLA_AI_N_CONTEXT` | `12` | RAG chunks for interactive `/analyze` |
| `BOLA_AI_OLLAMA_NUM_CTX` | `8192` | Context window (tokens) |
| `BOLA_AI_LOG_MEMORY` | `` | Set to `1` to log process RSS at each step |
| `BOLA_AI_LOG_LEVEL` | `INFO` | Logging verbosity |

Full reference: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#configuration-reference-environment-variables)

---

## Local dev setup (without Docker)

```bash
git clone https://github.com/IgorRedkach/bolaAi
cd bolaAi
pip install -e ".[dev]"

ollama serve
ollama pull qwen2.5-coder:3b

export PYTHONPATH=src
uvicorn bola_ai.api.app:create_app --host 0.0.0.0 --port 8000 --factory --reload
```

Or use the local dev compose (builds from source, live-reloads `src/`):

```bash
docker compose -f docker/docker-compose.yml build bola-ai
docker compose -f docker/docker-compose.yml up -d
```

---

## Tests

Unit tests (no live stack required):

```bash
pip install -e ".[dev]"
BOLA_AI_SKIP_LIVE_E2E=1 BOLA_AI_FAKE_EMBEDDER=1 PYTHONPATH=src pytest tests/ -v
```

Live E2E tests (requires running API + Ollama):

```bash
PYTHONPATH=src pytest tests/ -v
```

---

## Training the HAR specialist model

The `bola-har` model baked into the image was fine-tuned with QLoRA on `data/training/sft/bola_har_specialist_train.jsonl`. To retrain:

```bash
pip install -e ".[train]"
# Fine-tune
python scripts/train_qlora_unsloth.py --config configs/training/qlora_har_specialist.yaml
# Merge adapter → GGUF → upload as GitHub Release asset
python scripts/post_training_package_and_push.py --run-dir models/adapters/<run_id>
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full training and build pipeline.

---

## Architecture and goals

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — components, pipeline details, Docker build strategy, env vars
- [docs/GOALS.md](docs/GOALS.md) — mission, vulnerability taxonomy, design principles
- [docs/MEMORY.md](docs/MEMORY.md) — RAM profile and low-memory guidance
- [docs/OFFLINE_DEPLOY.md](docs/OFFLINE_DEPLOY.md) — air-gapped deployment (chunk export/import)

---

## Data and disposability

- Default data dir: `./data` (ChromaDB). Configure via `BOLA_AI_DATA`.
- For a disposable run: delete the Docker volume after use — no sensitive content persists.
- `docker compose down -v` wipes all volumes.

---

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
