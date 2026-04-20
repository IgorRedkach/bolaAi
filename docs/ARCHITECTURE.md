# BOLA AI — Architecture

## Overview

BOLA AI is a local-only security analysis agent that runs in a single Docker container. It ingests API documentation, HAR captures, OpenAPI specs, and other artifacts and produces auditor-ready vulnerability reports — grounded in the actual evidence, with copy-pasteable verification steps. No outbound traffic is required at runtime; the model, knowledge base, and embedding model are all baked into the image at build time.

Primary vulnerability taxonomy (checked in priority order): field-level authorization injection, write escalation, object enumeration, cross-principal isolation, logic/integrity failures, injection, misconfiguration, and logging gaps — with explicit support for Salesforce Aura/Experience Cloud, GraphQL, REST, and HAR-based API traces.

---

## High-Level Components

```
┌────────────────────────────────────────────────────────────────────────┐
│                  Docker host  (optional: --network=none)               │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  Container: ghcr.io/igorredkach/bolai:latest (all-in-one)        │  │
│  │                                                                  │  │
│  │  ┌──────────────┐   ┌───────────────┐   ┌─────────────────────┐ │  │
│  │  │    Ollama    │   │   ChromaDB    │   │   FastAPI + UI      │ │  │
│  │  │  v0.20.5     │   │  (pre-baked   │   │                     │ │  │
│  │  │  bola-       │   │   knowledge   │   │  GET  /chat         │ │  │
│  │  │  analyzer    │   │   + user docs │   │  POST /api/chat     │ │  │
│  │  │  (qwen2.5-   │   │   at runtime) │   │  POST /ingest       │ │  │
│  │  │  coder:3b    │   │               │   │  POST /ingest_shared│ │  │
│  │  │  + Modelfile │   │               │   │  POST /analyze      │ │  │
│  │  │  few-shots)  │   │               │   │  GET  /health       │ │  │
│  │  └──────┬───────┘   └──────┬────────┘   │  GET  /api/auto_..  │ │  │
│  │         │                  │            │  GET  /api/shared.. │ │  │
│  │         └──────────────────┴────────────┤  POST /reset        │ │  │
│  │                  RAG + Agent            └─────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                        │
│  /shared-docs  ←  mount -v ~/my-docs:/shared-docs                      │
│  /data/chroma  ←  ephemeral (wiped per session for clean state)        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Components

### 1. LLM — Ollama + `bola-analyzer` model

- **Base model:** `qwen2.5-coder:3b` quantized to `Q4_K_M` (~1.8 GiB).
- **Custom model:** `bola-analyzer` — created from `docker/Modelfile` on top of the base model. The Modelfile adds:
  - A `SYSTEM` instruction with a four-priority verification strategy (field injection → write escalation → ID swap → cross-principal) and strict grounding rules.
  - `MESSAGE` few-shot pairs: Salesforce Aura field injection (single-user), Salesforce Aura write escalation (single-user), GraphQL cross-tenant isolation (two-user). These teach output format, reasoning style, and verification strategy alignment at inference time.
  - Sampling parameters: `temperature 0.7`, `top_p 0.9`, `top_k 40`, `repeat_penalty 1.1`.
- **Build-time baking:** The Dockerfile starts Ollama, runs `ollama pull qwen2.5-coder:3b` and `ollama create bola-analyzer -f /app/Modelfile` during `docker build`. Model weights live in `/root/.ollama/models` inside the image layer — no internet access needed at runtime.
- **Fallback:** If the pre-baked model is missing at startup, the entrypoint re-pulls from `ollama.com` (controlled by `BOLA_AI_ALLOW_MODEL_PULL=1`, default on).
- **Ollama version:** Pinned to `v0.20.5` (`ARG OLLAMA_VERSION=0.20.5`) to keep `llama_sampler` stable on CPU.
- **Internal endpoint:** `http://127.0.0.1:11434/api/chat` (container-local only).

### 2. Vector DB — ChromaDB

- **Role:** Stores embeddings for both the pre-loaded security knowledge base and user-ingested documents. Supports similarity search for RAG context retrieval.
- **Pre-loaded knowledge (baked at build time):**
  - `data/knowledge/bola_patterns.md` — 279 lines of vulnerability patterns.
  - `data/knowledge/ai_teacher_bola_quality_patterns.md` — authorization quality patterns and verification gold examples.
  - `data/knowledge/phase1_small_model_guidelines.md` — small-model-specific guidelines and verification strategy matrix.
  - `data/training/bola_rag_chunks.txt` — chunked training examples loaded as RAG context.
  - Total pre-baked chunks: ~517 at image build time.
- **Runtime docs:** User-ingested files (via `/ingest`, `/ingest_shared`, or auto-ingest from `/shared-docs`) are added on top; typical post-ingest count is ~608 chunks for a large HAR file.
- **Embeddings:** `sentence-transformers/all-MiniLM-L6-v2` (~90 MB, CPU-only, downloaded and cached at build time).
- **Persistence path:** `/data/chroma` (mount an ephemeral volume and wipe between sessions for clean state).

### 3. Application — FastAPI

- **Role:** Orchestrate ingestion, RAG retrieval, LLM calls, and output normalization. Serve the chat UI and REST API.
- **Factory pattern:** `uvicorn bola_ai.api.app:create_app --factory` — the app is created by `create_app()` so the lifespan startup hook (auto-ingest + auto-analyze) runs correctly.

#### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/chat` | Interactive browser-based chat UI |
| `GET` | `/` | Alias for `/chat` |
| `POST` | `/api/chat` | Smart chat router: ingest commands (`ingest <filename>`), help, general queries, analysis |
| `POST` | `/ingest` | Ingest raw text/file content, chunk and embed into ChromaDB |
| `POST` | `/ingest_shared` | Ingest a file by relative path from the `/shared-docs` volume |
| `POST` | `/analyze` | Full RAG + LLM analysis: returns structured Markdown findings |
| `GET` | `/health` | Status: Ollama liveness, chunk counts, user doc sources, auto-ingest/analysis state |
| `GET` | `/api/auto_analysis` | Returns the cached result of the startup auto-analysis |
| `GET` | `/api/shared_docs` | List files available in the `/shared-docs` volume |
| `POST` | `/reset` | Wipe user-ingested documents from ChromaDB (keeps pre-loaded knowledge) |

#### Startup Automation

On container start, a background thread (`_auto_ingest_and_analyze`) runs automatically:
1. Scans `/shared-docs` for files and ingests them (`auto_ingest_status: done`).
2. Runs a security analysis pass over the ingested user documents (`auto_analysis_status: analyzing → done`).
3. Caches the result for `GET /api/auto_analysis`.

Auto-analysis uses a focused query (`_AUTO_ANALYZE_QUERY`) that checks in priority order: field injection, write escalation, ID enumeration, cross-principal isolation.

#### Analysis Serialization

A threading lock (`_analysis_lock`) ensures only one LLM call runs at a time — prevents CPU contention timeouts when interactive `/analyze` and the background startup analysis could otherwise race.

### 4. Agent / RAG Pipeline (`src/bola_ai/agent/`)

#### Ingestion (`src/bola_ai/rag/`)
- **`chunking.py`:** Splits documents into ~512-char chunks with 64-char overlap. HAR files are preprocessed by `_preprocess_har()`: filters static assets (JS/CSS/fonts/images by extension and MIME type), keeps only API-like requests (`/api/`, `/graphql`, `/aura`, `application/json`, form-encoded, write methods), and compresses each entry to a compact summary. Reduces a 6.9 MB HAR to ~33 KB before embedding.
- **`store.py`:** `DocStore` wraps ChromaDB. Supports `add_document`, `search` (with optional source filter), `reset`, `count`.
- **`embeddings.py`:** Wraps `sentence-transformers` with lazy load. `fake_embedder.py` provides deterministic zero-vectors for tests.

#### Analysis (`src/bola_ai/agent/runner.py`)
`run_analysis()` orchestrates a two-phase RAG + LLM pipeline:

1. **Pattern retrieval** — semantic search against canonical knowledge docs only (`bola_patterns.md`, `ai_teacher_bola_quality_patterns.md`, `phase1_small_model_guidelines.md`) using `_SECURITY_RAG_QUERY` (intent-based; not keyword matching). Returns `n_context // 2` chunks.
2. **Evidence retrieval** — semantic search against user-ingested documents using the analysis query. Returns up to `n_context` chunks (default 12 for `/analyze`, 6 for startup auto-analysis).
3. **Context assembly** — evidence and patterns combined into a structured `[EVIDENCE SOURCE]` / `[SECURITY LOGIC PATTERNS]` block, capped at `MAX_CONTEXT_CHARS` (default 12 000 chars).
4. **Prompt construction** — `BOLA_SYSTEM_PROMPT` (from `prompts.py`) + `build_analysis_prompt()` user message.
5. **LLM call** — `chat()` → `POST /api/chat` to Ollama. Supports per-call `num_predict` override (startup auto-analysis uses 512 tokens; interactive uses 768).
6. **Normalization** — `_normalize_report()` post-processes the output:
   - Strips RAG pattern bleed-through.
   - Aligns curl block paths to the heading endpoint via `_fix_curl_path_mismatch()`.
   - Grounds unknown paths to closest extracted allowed path.
   - Removes placeholder marker variants.
   - Corrects `403 → Vulnerable` labelling errors.
   - Appends comparative verification block when user explicitly requests two-token comparison.

#### System Prompt (`src/bola_ai/agent/prompts.py`)
`BOLA_SYSTEM_PROMPT` enforces:
- **Endpoint strictness / payload freedom:** Only use paths/hosts/IDs from artifacts; synthesize attack payloads freely.
- **Wide-spectrum priority order** (same 6 priorities as Modelfile).
- **Output format** with mandatory fields: Type, Target, Observation, Threat Hypothesis, Verification Strategy, Analyst Steps, PoC, Expected Outcomes.
- **Response quality guards:** verification strategy must match finding class; Salesforce/Aura-native request shapes must be preserved.

### 5. CLI (`src/bola_ai/cli.py`)

```
bola-ai health [--wait]          # poll until Ollama and app are ready
bola-ai ingest --file <path>     # ingest a file
bola-ai ingest-shared <relpath>  # ingest from /shared-docs
bola-ai analyze [--query <str>]  # run security analysis
```

### 6. Training Infrastructure (development only — not in the runtime image)

The training pipeline lives in `src/training/` and `scripts/`. It is not installed in the Docker image.

| Component | Purpose |
|-----------|---------|
| `src/training/generate_data.py` | Generates JSONL training examples and RAG chunks from vulnerability scenario seeds |
| `src/training/ai_teacher_prompts.py` | Prompt templates for AI-assisted synthetic training data generation |
| `src/training/load_knowledge.py` | Loads `data/knowledge/*.md` and `data/training/bola_rag_chunks.txt` into ChromaDB — used both at Docker build time and by developers |
| `src/training/reviewing_iter.py` | Iterates over training examples requiring human review |
| `scripts/train_qlora_unsloth.py` | QLoRA fine-tuning via Unsloth + HuggingFace PEFT/TRL |
| `scripts/train_lora16.py` | Full LoRA-16 rank fine-tuning |
| `scripts/train_dpo.py` | DPO (Direct Preference Optimization) training |
| `scripts/eval_security_agent_model.py` | Evaluation harness (generates eval reports in `docs/eval_reports/`) |
| `scripts/run_ai_teaching_cycle.py` | End-to-end AI teaching cycle: generate tasks → distill → retrain → eval |
| `scripts/package_trained_model_for_ollama.py` | Packages adapter + base → Ollama-compatible bundle |
| `configs/training/` | YAML configs for qlora/lora/dpo runs at different sizes (0.5B, 1B, 3B) |
| `models/adapters/` | Local LoRA/QLoRA checkpoint outputs (33 training runs, latest: `qlora_20260415T143126Z`) |
| `models/packaged/` | Modelfile-only packages for tested checkpoints |
| `data/training/` | JSONL splits (`train.jsonl`, `valid.jsonl`), RAG chunks, AI task/cycle outputs |

> **Note on model bundles:** Trained weight bundles (`trained_model_bundle.part-*`) were previously stored in `models/published/` via Git LFS. These have been removed from the repository history (git filter-repo) because the current Docker image no longer uses them — the image pulls `qwen2.5-coder:3b` from Ollama at build time and applies the Modelfile directly.

---

## Docker Strategy

### Build Pipeline
```
docker build -f docker/Dockerfile.allinone -t bolai .
```
Two baking stages run inside the build:

1. **Model bake:** Ollama starts, pulls `qwen2.5-coder:3b`, runs `ollama create bola-analyzer -f /app/Modelfile`, then shuts down. Model weights are captured in the `/root/.ollama/models` layer.
2. **RAG bake:** `src/training/load_knowledge.py` loads the knowledge base into ChromaDB at `/data/chroma` and downloads + caches the `all-MiniLM-L6-v2` embedding model. Both are captured in the `/data` layer.

### Published Image
```
docker pull ghcr.io/igorredkach/bolai:latest
```
Published automatically by GitHub Actions on every push to `main` that touches `src/`, `data/`, `docker/`, `pyproject.toml`, or `.github/workflows/`. Uses `ubuntu-latest` with freed disk space (removes dotnet/android/ghc toolchains) and CPU-only PyTorch to fit the runner.

### Running

```bash
# Standard — auto-ingests and analyzes any files in ~/my-docs on startup
docker run -p 8000:8000 -v ~/my-docs:/shared-docs ghcr.io/igorredkach/bolai:latest

# Strict isolation — no outbound traffic
docker run --network=none -p 8000:8000 -v ~/my-docs:/shared-docs ghcr.io/igorredkach/bolai:latest
```
Open `http://localhost:8000/chat`.

---

## Configuration Reference (Environment Variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_MODEL` | `bola-analyzer` | Model name to use for inference |
| `BOLA_AI_OLLAMA_NUM_CTX` | `8192` | KV cache / context window (tokens) |
| `BOLA_AI_OLLAMA_NUM_PREDICT` | `768` | Max output tokens for interactive `/analyze` |
| `BOLA_AI_LLM_CHAT_TIMEOUT` | `900` | Max seconds to wait for one LLM completion (15 min) |
| `BOLA_AI_ANALYZE_CLIENT_TIMEOUT` | `960` | HTTP client timeout for `/analyze` endpoint |
| `BOLA_AI_AUTO_ANALYZE_TIMEOUT` | `900` | Timeout for startup auto-analysis LLM call |
| `BOLA_AI_AUTO_ANALYZE_N_CONTEXT` | `6` | RAG chunks retrieved for startup auto-analysis |
| `BOLA_AI_AUTO_ANALYZE_NUM_PREDICT` | `512` | Output token cap for startup auto-analysis (faster) |
| `BOLA_AI_AUTO_ANALYZE_MAX_SOURCES` | `2` | Max user docs to include in startup auto-analysis |
| `BOLA_AI_N_CONTEXT` | `12` | RAG chunks for interactive `/analyze` |
| `BOLA_AI_MAX_CONTEXT_CHARS` | `12000` | Max total RAG context characters sent to LLM |
| `BOLA_AI_SHARED_DOCS_DIR` | `/shared-docs` | Path scanned for auto-ingest on startup |
| `BOLA_AI_DATA` | `data` | Root path for ChromaDB and training data |
| `BOLA_AI_ALLOW_MODEL_PULL` | `1` | Pull model from internet if pre-baked model missing |
| `BOLA_AI_FAKE_EMBEDDER` | `` | Set to `1` to skip sentence-transformers (tests only) |
| `BOLA_AI_LOG_MEMORY` | `` | Set to `1` to log process RSS at each pipeline step |
| `BOLA_AI_LOG_LEVEL` | `INFO` | Logging verbosity |
| `BOLA_AI_NUM_THREAD` | auto (2–8) | CPU thread count passed to Ollama |

---

## Memory Profile (CPU-only)

| Component | Approximate footprint |
|-----------|----------------------|
| Ollama + `bola-analyzer` (Q4_K_M, 3B) | ~2.1 GiB (1.8 GiB weights + 288 MiB KV cache) |
| ChromaDB + embeddings in memory | ~200–400 MB |
| FastAPI app (Python) | ~150–250 MB |
| **Total at inference time** | **~2.5–3.0 GiB** |

Inference speed: ~5–8 tokens/second on a modern 8-core CPU, 6–10 minutes per full analysis pass. See [MEMORY.md](MEMORY.md) for detailed tuning guidance.

---

## Security and Disposability

- **No telemetry or outbound calls** from the application or LLM at runtime (use `--network=none` for strict enforcement).
- **No persistence of user inputs** beyond the container/volume lifecycle — wipe the ChromaDB volume between sessions.
- **No API keys or cloud credentials required** — fully offline after `docker pull`.
- **No model fine-tuning artifacts** shipped in the image — the Docker image contains only the base `qwen2.5-coder:3b` weights and the Modelfile.

---

## File Layout

```
bolaAi/
├── src/
│   ├── bola_ai/
│   │   ├── api/
│   │   │   └── app.py              # FastAPI app, all routes, startup automation
│   │   ├── agent/
│   │   │   ├── prompts.py          # BOLA_SYSTEM_PROMPT, build_analysis_prompt
│   │   │   ├── runner.py           # run_analysis, normalize_report, path grounding
│   │   │   └── llm.py              # Ollama httpx client, chat(), is_available()
│   │   ├── rag/
│   │   │   ├── store.py            # DocStore (ChromaDB wrapper)
│   │   │   ├── chunking.py         # chunk_text, HAR preprocessor
│   │   │   ├── embeddings.py       # sentence-transformers wrapper
│   │   │   └── fake_embedder.py    # deterministic zero embedder for tests
│   │   ├── config.py               # All env-var config with defaults
│   │   ├── memory.py               # RSS memory measurement helper
│   │   ├── logging_config.py       # Structured logging setup
│   │   └── cli.py                  # bola-ai CLI (health/ingest/analyze)
│   └── training/
│       ├── load_knowledge.py       # Loads knowledge + RAG chunks into ChromaDB
│       ├── generate_data.py        # Generates JSONL + RAG chunks from seeds
│       ├── ai_teacher_prompts.py   # AI-assisted training data prompts
│       └── reviewing_iter.py       # Review iteration helper
├── docker/
│   ├── Dockerfile.allinone         # Production image (model + RAG baked in)
│   ├── Modelfile                   # bola-analyzer: system prompt + few-shot examples
│   └── entrypoint-allinone.sh      # Container startup script
├── data/
│   ├── knowledge/
│   │   ├── bola_patterns.md            # Core vulnerability patterns (RAG)
│   │   ├── ai_teacher_bola_quality_patterns.md  # Authorization quality patterns
│   │   └── phase1_small_model_guidelines.md     # Verification strategy guidelines
│   └── training/
│       ├── bola_rag_chunks.txt         # Pre-chunked training examples for RAG
│       ├── bola_training.jsonl         # JSONL training set
│       └── sft/                        # Supervised fine-tuning splits (train/valid)
├── configs/training/                   # YAML configs for qlora/lora/dpo runs
├── scripts/                            # Training, eval, packaging, E2E scripts
├── models/
│   ├── adapters/                       # Local LoRA/QLoRA checkpoints (dev only)
│   └── packaged/                       # Modelfile packages for tested checkpoints
├── tests/                              # Pytest: unit, integration, E2E, live API
│   └── fixtures/                       # Test document corpus (30+ scenarios)
├── docs/
│   ├── ARCHITECTURE.md                 # This file
│   ├── GOALS.md
│   ├── MEMORY.md
│   └── eval_reports/                   # Model evaluation reports
├── shared_docs/                        # Developer test documents (not in image)
├── .github/workflows/
│   └── publish-image.yml               # CI: build + push to ghcr.io on src/data/docker changes
├── pyproject.toml                      # Package metadata + optional train/dev deps
├── QUICKSTART.md
└── README.md
```

---

This architecture supports the goals in [GOALS.md](GOALS.md): local-only, broad vulnerability taxonomy with field-level authorization prioritized, auditor-friendly output, fully disposable, and suitable for sensitive enterprise artifact analysis.
