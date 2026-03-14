# BOLA AI

**Local-only AI agent to find BOLA (Broken Object-Level Authorization) vulnerabilities.**  
Free, disposable, no network at runtime. For goals and architecture see [docs/GOALS.md](docs/GOALS.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). **Low-memory:** [docs/MEMORY.md](docs/MEMORY.md).

## Quick start

### 1. Install (Python 3.10+)

```bash
pip install -e .
# Optional: pip install -e ".[dev]"  # for pytest
```

### 2. Run API (local)

**Option A — with Ollama (full analysis)**  
Start Ollama and pull a model:

```bash
ollama serve   # if not already running
ollama pull qwen2.5-coder:1.5b
```

Then start the API:

```bash
export PYTHONPATH=src
uvicorn bola_ai.api.app:create_app --host 0.0.0.0 --port 8000 --factory
# Or: python run_api.py
```

**Option B — without Ollama (ingest + UI only)**  
Ingest and UI work; `/analyze` will fail until Ollama is available. Use fake embedder to save memory:

```bash
export BOLA_AI_FAKE_EMBEDDER=1
export PYTHONPATH=src
uvicorn bola_ai.api.app:create_app --host 0.0.0.0 --port 8000 --factory
# Or from repo root: sh scripts/run_api_lowmem.sh
```

Open: http://localhost:8000

### 3. Use the CLI

With the API running on port 8000:

```bash
export PYTHONPATH=src
python -m bola_ai.cli health
python -m bola_ai.cli ingest --file docs/GOALS.md --source goals
python -m bola_ai.cli analyze
python -m bola_ai.cli analyze --query "Check for IDOR in user endpoints"
```

Override API URL: `python -m bola_ai.cli --api http://localhost:8000 health`

### 4. Docker — ready-to-go container (offline by default)

Image includes **RAG preloaded** with BOLA patterns. The stack runs **without any requests to the open internet** at runtime (see [docs/GOALS.md](docs/GOALS.md) and [docs/OFFLINE_DEPLOY.md](docs/OFFLINE_DEPLOY.md)).

**Offline (default):** Model must already be in the Ollama volume (e.g. from a previous one-time setup or from an imported chunked bundle). No pull at runtime.

```bash
docker compose -f docker/docker-compose.yml build bola-ai
docker compose -f docker/docker-compose.yml up -d
```

**One-time online setup** (to fill the model volume, then run offline later):

```bash
OLLAMA_ONLINE_SETUP=1 docker compose -f docker/docker-compose.yml up -d
# After model is ready, stop (without -v): docker compose -f docker/docker-compose.yml down
# Then on this or an air-gapped machine: docker compose -f docker/docker-compose.yml up -d
```

**Deploy by chunks (air-gapped):** Export image and optional Ollama volume as chunked files, transfer, reassemble, and run locally. See [docs/OFFLINE_DEPLOY.md](docs/OFFLINE_DEPLOY.md) and `scripts/export_image_chunks.sh`, `scripts/import_image_chunks.sh`, `scripts/export_ollama_volume_chunks.sh`.

To wipe data when done: `docker compose -f docker/docker-compose.yml down -v`

**Logs:** `docker logs bola-ai` shows app and entrypoint logs. The compose file mounts `../src` into the container so code changes apply without rebuilding.

### 5. Fake system info → BOLA suggestions

To communicate with the model using sample/fake system info and get suggestions: ingest the text (or file), then call analyze. Example:

```bash
# With API running (e.g. docker compose up -d):
sh scripts/demo_fake_system_info.sh
# Or: curl -X POST http://localhost:8000/ingest -F "content=YOUR_DOCS" -F "source=my_system"
#     curl -X POST http://localhost:8000/analyze
```

### 6. Training data and RAG knowledge

Generate BOLA examples (JSONL + RAG chunks):

```bash
PYTHONPATH=src python src/training/generate_data.py
# Writes data/training/bola_training.jsonl and data/training/bola_rag_chunks.txt
```

Load knowledge into the RAG store (requires real embedder; run with API deps installed):

```bash
PYTHONPATH=src python src/training/load_knowledge.py
# Reads data/knowledge/*.md and data/training/bola_rag_chunks.txt
```

**Training data for retraining:** The tool uses a RAG knowledge base (not full LLM weight fine-tuning). To add your own examples and optionally retrain or fine-tune elsewhere:

- **RAG:** Add markdown under `data/knowledge/` and/or append to the output of `generate_data.py`; run `load_knowledge.py` to reload. No weights: all chunks are used for retrieval.
- **JSONL for external fine-tuning:** `data/training/bola_training.jsonl` holds BOLA examples. You can add rows (with optional weights in your own pipeline) and use them with Ollama or other tools for fine-tuning. See [docs/GOALS.md](docs/GOALS.md) Success criteria.

## API

| Method | Path      | Description                    |
|--------|-----------|--------------------------------|
| GET    | /         | Simple HTML UI                 |
| GET    | /health   | Health + Ollama + chunk count |
| POST   | /ingest   | Body: form `content` or `file` |
| POST   | /analyze  | Body: optional `{"query": "..."}` |

## Tests (low memory)

Tests use a fake embedder so they don’t load sentence-transformers/torch:

```bash
BOLA_AI_FAKE_EMBEDDER=1 PYTHONPATH=src pytest tests/ -v
# Or: sh scripts/run_tests.sh
```

**Live API QA:** `docker compose up -d` then `sh scripts/qa_api_live.sh http://localhost:8000`. Or `pytest tests/test_api_live.py -v` with API running.

**E2E (real LLM):** Tests that **talk to the LLM** and assert on report **content**. See [docs/E2E_TESTING.md](docs/E2E_TESTING.md). Run: `BOLA_AI_LIVE_URL=http://localhost:8000 PYTHONPATH=src pytest tests/test_e2e_llm.py tests/test_issues_resolved.py -v -s`. Open issues and their autotests: [docs/ISSUES.md](docs/ISSUES.md).

Monitor memory: run `sh scripts/check_memory.sh 2` in another terminal; if Python exceeds ~10 GB, kill it. See [docs/MEMORY.md](docs/MEMORY.md).

## Data and disposal

- Default data dir: `./data` (ChromaDB + configurable path via `BOLA_AI_DATA`).
- For a disposable run: use a temp dir or Docker volume and delete it after use so no sensitive docs or artifacts remain.

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).

---

**When all goals are reached:** accept/keep the changes when Cursor prompts you, so the project is saved.
