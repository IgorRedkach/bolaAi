# BOLA AI — Architecture

## Overview

BOLA AI is a local-only security analysis agent that runs in a single Docker container. It ingests API documentation, HAR captures, OpenAPI specs, and other artifacts and produces auditor-ready vulnerability reports — grounded in the actual evidence, with copy-pasteable verification steps. No outbound traffic is required at runtime; the models, knowledge base, and embedding model are all baked into the image at build time.

Primary vulnerability taxonomy (checked in priority order): field-level authorization injection, write escalation, object enumeration, cross-principal isolation, logic/integrity failures, injection, misconfiguration, and logging gaps — with explicit support for GraphQL, REST, HAR-based API traces, DB schemas, etc.

**Unified pipeline** (current): A single pipeline that handles HAR and general inputs together, with the HAR path producing richer output by default. When HAR input is detected, a purpose-built two-pass HAR analysis runs (PRISM-HAR): deterministic extraction → `bola-har` specialist LLM under GBNF grammar constraints → mechanical validation. After validation, two new steps run for both paths:

1. **DocEnricher** (`agent/doc_enricher.py`): Searches any additional (non-HAR) documents ingested in the same session — OpenAPI specs, schemas, code docs — and cross-validates each finding. Corroborating evidence upgrades confidence; contradicting evidence adds a verification note.
2. **ExampleGenerator** (`agent/example_generator.py`): Produces typed, copy-pasteable verification examples for each finding: GraphQL queries, REST curl pairs, or SOQL statements, depending on detected API type. Uses isolated prompts (`agent/prompts_examples.py`) so this step can be separately fine-tuned.

The general RAG+LLM flow is fully preserved for non-HAR inputs and also used by DocEnricher for context retrieval.

---

## High-Level Components

```
┌────────────────────────────────────────────────────────────────────────┐
│                            Docker host                                 │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  Container: ghcr.io/igorredkach/bolai:latest (all-in-one)        │  │
│  │                                                                  │  │
│  │  ┌─────────────────────────┐  ┌───────────────┐  ┌───────────┐  │  │
│  │  │         Ollama          │  │   ChromaDB    │  │  FastAPI  │  │  │
│  │  │  bola-analyzer          │  │  (pre-baked   │  │  + UI     │  │  │
│  │  │  (qwen2.5-coder:3b +    │  │   knowledge   │  │           │  │  │
│  │  │   Modelfile, general)   │  │   + user docs │  │  /chat    │  │  │
│  │  │                         │  │   at runtime) │  │  /ingest  │  │  │
│  │  │  bola-har               │  │               │  │  /analyze │  │  │
│  │  │  (qwen2.5-coder:3b +    │  │               │  │  /health  │  │  │
│  │  │   QLoRA adapter +       │  │               │  │  /reset   │  │  │
│  │  │   Modelfile.bola-har,   │  │               │  │  ...      │  │  │
│  │  │   HAR specialist)       │  │               │  │           │  │  │
│  │  └───────────┬─────────────┘  └──────┬────────┘  └─────┬─────┘  │  │
│  │              │                       │                  │        │  │
│  │  ┌───────────▼───────────────────────▼──────────────────▼──────┐ │  │
│  │  │                   Agent / RAG Pipeline (Unified)              │ │  │
│  │  │                                                              │ │  │
│  │  │   HAR input?  ─yes─▶  Phase 1: PRISM-HAR                    │ │  │
│  │  │        │               HarExtractor → FactIndex              │ │  │
│  │  │        │               → HarAnalyzer (bola-har + GBNF)       │ │  │
│  │  │        │               → FindingValidator                    │ │  │
│  │  │        │                        │                            │ │  │
│  │  │        └─no──▶  General Pipeline│                            │ │  │
│  │  │                  RAG retrieval → bola-analyzer → normalize   │ │  │
│  │  │                                 │                            │ │  │
│  │  │   ┌─────────────────────────────▼──────────────────────────┐ │ │  │
│  │  │   │  Phase 2: DocEnricher                                  │ │ │  │
│  │  │   │  RAG search non-HAR docs → corroborate/contradict      │ │ │  │
│  │  │   │  → EnrichedFinding (adjusted confidence + doc notes)   │ │ │  │
│  │  │   └─────────────────────────────┬──────────────────────────┘ │ │  │
│  │  │                                 │                            │ │  │
│  │  │   ┌─────────────────────────────▼──────────────────────────┐ │ │  │
│  │  │   │  Phase 3: ExampleGenerator                             │ │ │  │
│  │  │   │  Detect API type → GraphQL/REST/SOQL examples          │ │ │  │
│  │  │   │  → VerificationExample[] per finding                   │ │ │  │
│  │  │   └─────────────────────────────┬──────────────────────────┘ │ │  │
│  │  │                                 │                            │ │  │
│  │  │                          ReportRenderer                      │ │  │
│  │  └──────────────────────────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                        │
│  /shared-docs  ←  mount -v ~/my-docs:/shared-docs                      │
│  /data/chroma  ←  ephemeral (wiped per session for clean state)        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Components

### 1. LLM — Ollama + Two Specialized Models

#### `bola-analyzer` (general-purpose)

- **Base model:** `qwen2.5-coder:3b` quantized to `Q4_K_M` (~1.8 GiB).
- **Custom model:** `bola-analyzer` — created from `docker/Modelfile` on top of the base model. The Modelfile adds:
  - A `SYSTEM` instruction with a four-priority verification strategy (field injection → write escalation → ID swap → cross-principal) and strict grounding rules.
  - Sampling parameters: `temperature 0.7`, `top_p 0.9`, `top_k 40`, `repeat_penalty 1.1`.
- **Used for:** non-HAR inputs through the general RAG+LLM pipeline.

#### `bola-har` (HAR specialist)

- **Base model:** `qwen2.5-coder:3b` with a merged QLoRA adapter trained on `bola_har_specialist_train.jsonl`.
- **Training config:** `configs/training/qlora_har_specialist.yaml` — LoRA rank 32, alpha 64, bfloat16, paged_adamw_8bit, 3 epochs, max sequence 2048.
- **Custom model:** `bola-har` — created from `docker/Modelfile.bola-har`. Sampling: `temperature 0.3`, `top_p 0.85`, `repeat_penalty 1.2`. System prompt enforces verbatim evidence quoting and JSON-only output.
- **GBNF grammar constraint:** Every inference call from `HarAnalyzer` passes the `FINDING_GRAMMAR` constant to Ollama's `/api/chat` as `options.grammar`. This prevents structurally invalid JSON at the token level — not just post-hoc.
- **Used for:** HAR inputs routed through the PRISM-HAR pipeline exclusively.
- **Build-time baking:** The merged adapter is stored as a Q4_K_M GGUF file (`bola-har-q4km.gguf`, ~1.8 GiB) and published as a GitHub Release asset. During `docker build`, the Dockerfile downloads the GGUF using a build secret (`gh_token`) and runs `ollama create bola-har -f Modelfile.bola-har` to bake it into a separate image layer. The `scripts/merge_adapter_fp16.py` script produces the merged safetensors; `llama.cpp` tools then quantize to GGUF.

**Ollama version:** Pinned to `v0.20.5` (`ARG OLLAMA_VERSION=0.20.5`) to keep `llama_sampler` stable on CPU.  
**Internal endpoint:** `http://127.0.0.1:11434/api/chat` (container-local only).

---

### 2. Vector DB — ChromaDB

- **Role:** Stores embeddings for both the pre-loaded security knowledge base and user-ingested documents. Supports similarity search for RAG context retrieval.
- **Pre-loaded knowledge (baked at build time) — canonical knowledge files only:**
  - `data/knowledge/bola_patterns.md` — vulnerability patterns.
  - `data/knowledge/ai_teacher_bola_quality_patterns.md` — authorization quality patterns and verification gold examples.
  - `data/knowledge/phase1_small_model_guidelines.md` — small-model-specific guidelines and verification strategy matrix.
- **Training data is intentionally excluded from RAG.** Files under `data/training/` (`bola_rag_chunks.txt`, `*.jsonl`) are used exclusively by the training pipeline. Mixing them into the inference RAG store creates training-inference overlap where the model pattern-matches memorised examples instead of reasoning from retrieved evidence.
- **Runtime docs:** User-ingested files (via `/ingest`, `/ingest_shared`, or auto-ingest from `/shared-docs`) are added on top; typical post-ingest count is ~608 chunks for a large HAR file. HAR files are tagged with `metadata={"artifact_type": "har"}` at ingest time, enabling fast HAR source detection by `runner.py`.
- **RAG isolation:** `src/bola_ai/rag/rag_isolation.py` defines a whitelist of canonical knowledge sources (`KNOWLEDGE_SOURCES`) and a blocklist of contaminating fixture documents (`CONTAMINATING_DOCS`). Every analysis call uses `build_session_source_filter()` to restrict ChromaDB retrieval to only canonical knowledge plus the current session's user-uploaded files, excluding fixture/adversarial docs even if they were mistakenly ingested.
- **Embeddings:** `sentence-transformers/all-MiniLM-L6-v2` (~90 MB, CPU-only, downloaded and cached at build time).
- **Persistence path:** `/data/chroma` (mount an ephemeral volume and wipe between sessions for clean state).

---

### 3. Application — FastAPI

- **Role:** Orchestrate ingestion, pipeline routing, LLM calls, and output normalization. Serve the chat UI and REST API.
- **Factory pattern:** `uvicorn bola_ai.api.app:create_app --factory` — the app is created by `create_app()` so the lifespan startup hook (auto-ingest + auto-analyze) runs correctly.

#### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/chat` | Interactive browser-based chat UI |
| `GET` | `/` | Alias for `/chat` |
| `POST` | `/api/chat` | Smart chat router: ingest commands (`ingest <filename>`), help, general queries, analysis |
| `POST` | `/ingest` | Ingest raw text/file content, chunk and embed into ChromaDB. HAR JSON detected and tagged with `artifact_type: har` metadata. |
| `POST` | `/ingest_shared` | Ingest a file by relative path from the `/shared-docs` volume. HAR detection applied. |
| `POST` | `/analyze` | Full analysis: routes to PRISM-HAR pipeline for HAR inputs, general RAG+LLM pipeline otherwise. Returns structured Markdown findings. |
| `GET` | `/health` | Status: Ollama liveness, chunk counts, user doc sources, auto-ingest/analysis state |
| `GET` | `/api/auto_analysis` | Returns the cached result of the startup auto-analysis |
| `GET` | `/api/shared_docs` | List files available in the `/shared-docs` volume |
| `POST` | `/reset` | Wipe user-ingested documents from ChromaDB (keeps pre-loaded knowledge) |

#### Startup Automation

On container start, a background thread (`_auto_ingest_and_analyze`) runs automatically:
1. Scans `/shared-docs` for files and ingests them (`auto_ingest_status: done`). HAR files are tagged at ingest.
2. Runs a security analysis pass over the ingested user documents — routes to PRISM-HAR pipeline if the ingested content is a HAR file (`auto_analysis_status: analyzing → done`).
3. Caches the result for `GET /api/auto_analysis`.

#### Analysis Serialization

A threading lock (`_analysis_lock`) ensures only one LLM call runs at a time — prevents CPU contention timeouts when interactive `/analyze` and the background startup analysis could otherwise race.

---

### 4. Agent / RAG Pipeline (`src/bola_ai/agent/`)

#### Ingestion (`src/bola_ai/rag/`)

- **`chunking.py`:** Splits documents into ~512-char chunks with 64-char overlap. HAR files are preprocessed by `_preprocess_har()`: filters static assets (JS/CSS/fonts/images by extension and MIME type), keeps only API-like requests (`/api/`, `/graphql`, `/aura`, `application/json`, form-encoded, write methods), and compresses each entry to a compact summary.
- **`store.py`:** `DocStore` wraps ChromaDB. Supports `add_document`, `search` (with optional source filter), `reset`, `count`.
- **`embeddings.py`:** Wraps `sentence-transformers` with lazy load. `fake_embedder.py` provides deterministic zero-vectors for tests.
- **`har_extractor.py`:** Deterministic HAR JSON parser — no LLM involvement. `HarExtractor.extract()` parses raw HAR text into a `StructuredArtifact` containing `HarEntry` objects with security-relevant fields: method, URL, host, path, parsed query/body, auth-relevant headers, response status, response body excerpt, and derived signals (path ID segments, `is_auth_flow`, `is_analytics`, `is_static_resource`, `is_internal_endpoint`). `StructuredArtifact` also carries aggregate signals: `has_sequential_int_ids`, `has_tenant_params`, `has_batch_endpoints`, and `security_relevant_entry_ids` (entries where all noise flags are false). `HarExtractor.is_har()` is the HAR detection gate used in `runner.py`.
- **`fact_index.py`:** `FactIndex.build()` indexes a `StructuredArtifact` into O(1) lookup tables: `entry_by_id`, `all_hosts`, `all_paths`, `all_path_id_segments`, and `entry_raw_texts`. Used by `FindingValidator` to verify that model-generated findings reference real content.
- **`rag_isolation.py`:** Defines `KNOWLEDGE_SOURCES` (canonical knowledge whitelist) and `CONTAMINATING_DOCS` (fixture/adversarial doc blocklist). `build_session_source_filter()` constructs the ChromaDB source filter for each analysis call. `get_contaminating_docs_in_store()` scans the collection at startup to warn about contamination.

#### PRISM-HAR Pipeline (`src/bola_ai/agent/`)

Activated by `runner.py` when `HarExtractor.is_har(query)` is true or when the ChromaDB collection contains a HAR-tagged source. Falls back to the general pipeline on any unhandled exception. After validation, control flows into DocEnricher and ExampleGenerator (phases 2 and 3 below).

- **`har_analyzer.py`:** `HarAnalyzer.analyze()` takes a `StructuredArtifact`, calls `artifact.to_entries_list_text()` to produce the ENTRIES LIST, and sends it to the `bola-har` Ollama model with `FINDING_GRAMMAR` (GBNF) enforced. Returns a `list[RawFinding]` — each finding carries `entry_id`, `pattern_id`, `pattern_name`, `evidence_quote`, `attack_delta`, `poc_entry_id`, `confidence`, and `note`. Parse errors return an empty list.
- **`validator.py`:** `FindingValidator.validate_all()` checks each `RawFinding` against the `FactIndex`. Validation rules: (1) `entry_id` must exist — otherwise rejected; (2) `poc_entry_id` must exist; (3) `evidence_quote` must appear verbatim in the raw text of the referenced entry. All rejections are logged for auditability.
- **`report_renderer.py`:** `ReportRenderer.render()` converts `list[ValidatedFinding]` + `StructuredArtifact` into a Markdown report. curl commands are built deterministically from `HarEntry` fields — the LLM never generates a curl. Accepts optional `enriched` and `examples` keyword arguments to include DocEnricher and ExampleGenerator output per finding.

#### DocEnricher (`src/bola_ai/agent/doc_enricher.py`) — Phase 2

Runs after HAR validation when additional (non-HAR) documents are ingested in the same session. No LLM call in the mechanical path; an optional LLM classification is available for ambiguous cases.

- **`DocEnricher.enrich_all(findings)`:** For each `ValidatedFinding`, builds a targeted RAG query from `pattern_id` + `attack_delta` + `evidence_quote`. Searches `DocStore` restricted to non-HAR sources. Classifies each retrieved chunk as `corroborates`, `contradicts`, or `context` using keyword heuristics.
- **`EnrichedFinding`:** Extends `ValidatedFinding` with `doc_evidences: list[DocEvidence]`, `enriched_confidence` (may upgrade or downgrade from the raw finding), and `enrichment_note`.
- **Confidence adjustment:** Corroborated findings (no contradicting evidence) may be upgraded one level (low→medium, medium→high). Contradicted findings (existing control documented) may be downgraded with a runtime-verification note.
- **Graceful skip:** If no non-HAR sources are present, enrichment returns `EnrichedFinding(validated=vf)` with empty evidence list — report content is unchanged.

#### ExampleGenerator (`src/bola_ai/agent/example_generator.py`) — Phase 3

A separate knowledge step that produces typed, copy-pasteable verification examples. Intentionally isolated from the core analysis so it can be trained or fine-tuned independently.

- **`ExampleGenerator.generate(enriched)`:** Detects the API type from the artifact (`graphql`, `soql`, `rest`, `mixed`) using signals in `prompts_examples.detect_api_type()`. For each `EnrichedFinding`, calls `bola-analyzer` (or a future `bola-examples` specialist, set via `BOLA_AI_EXAMPLES_MODEL`) with an API-type-specific prompt.
- **`VerificationExample`:** Carries `pattern_id`, `api_type`, `endpoint`, `method`, `examples: list[str]` (extracted fenced code blocks), and `generation_note`.
- **`prompts_examples.py`:** Isolated prompt module with `EXAMPLES_SYSTEM_PROMPT`, per-type prompt builders (`build_rest_example_prompt`, `build_graphql_example_prompt`, `build_soql_example_prompt`, `build_mixed_example_prompt`), and `select_prompt()` dispatcher. This file is the only surface that needs to change when improving example quality or adding training data.
- **Graceful skip:** If the LLM returns `NO_EXAMPLE: <reason>` or an empty response, the finding is skipped and counted in `skipped_count`. The report renders without an examples section for that finding.

#### General Pipeline (`src/bola_ai/agent/runner.py`)

Used for all non-HAR inputs. `run_analysis()` orchestrates:

1. **HAR detection gate** — `HarExtractor.is_har(query)` or `_context_contains_har(store, source_filter)`. If true, dispatches `_run_har_pipeline()` which sequences HarExtractor → FactIndex → HarAnalyzer → FindingValidator → ReportRenderer.
2. **Pattern retrieval** — semantic search against canonical knowledge docs only using `_SECURITY_RAG_QUERY`. Returns `n_context // 2` chunks.
3. **Evidence retrieval** — semantic search against user-ingested documents using the analysis query via session-scoped source filter from `rag_isolation.build_session_source_filter()`. Returns up to `n_context` chunks (default 12 for `/analyze`, 6 for startup auto-analysis).
4. **Context assembly** — evidence and patterns combined into a structured `[EVIDENCE SOURCE]` / `[SECURITY LOGIC PATTERNS]` block, capped at `MAX_CONTEXT_CHARS` (default 12 000 chars).
5. **Prompt construction** — `BOLA_SYSTEM_PROMPT` (from `prompts.py`) + `build_analysis_prompt()` user message.
6. **LLM call** — `chat()` → `POST /api/chat` to Ollama (`bola-analyzer`). Supports per-call `num_predict` override.
7. **Normalization** — `_normalize_report()` post-processes the output: strips RAG pattern bleed-through, aligns curl block paths to the heading endpoint via `_fix_curl_path_mismatch()`, grounds unknown paths to closest extracted allowed path, removes placeholder marker variants, appends comparative verification block when user explicitly requests two-token comparison.

#### LLM Client (`src/bola_ai/agent/llm.py`)

`chat()` sends requests to Ollama's `/api/chat` endpoint. Accepts an optional `grammar: Optional[str]` parameter — when provided, passes it as `options.grammar` in the request body for GBNF-constrained generation (used by `HarAnalyzer`). `is_available()` checks Ollama liveness.

#### System Prompt (`src/bola_ai/agent/prompts.py`)

`BOLA_SYSTEM_PROMPT` enforces:
- **Endpoint strictness / payload freedom:** Only use paths/hosts/IDs from artifacts; synthesize attack payloads freely.
- **Wide-spectrum priority order** (same 6 priorities as Modelfile).
- **Output format** with mandatory fields: Type, Target, Observation, Threat Hypothesis, Verification Strategy, Analyst Steps, PoC, Expected Outcomes.
- **Response quality guards:** verification strategy must match finding class; Salesforce/Aura-native request shapes must be preserved.

---

### 5. CLI (`src/bola_ai/cli.py`)

```
bola-ai health [--wait]          # poll until Ollama and app are ready
bola-ai ingest --file <path>     # ingest a file
bola-ai ingest-shared <relpath>  # ingest from /shared-docs
bola-ai analyze [--query <str>]  # run security analysis
```

---

### 6. Training Infrastructure (development only — not in the runtime image)

The training pipeline lives in `src/training/` and `scripts/`. It is not installed in the Docker image.

| Component | Purpose |
|-----------|---------|
| `src/training/generate_data.py` | Generates JSONL training examples and RAG chunks from vulnerability scenario seeds |
| `src/training/ai_teacher_prompts.py` | Prompt templates for AI-assisted synthetic training data generation |
| `src/training/load_knowledge.py` | Loads `data/knowledge/*.md` into ChromaDB — used both at Docker build time and by developers |
| `src/training/reviewing_iter.py` | Iterates over training examples requiring human review |
| `scripts/train_qlora_unsloth.py` | QLoRA fine-tuning via Unsloth + HuggingFace PEFT/TRL |
| `scripts/post_training_package_and_push.py` | Merges QLoRA adapter into base model weights, packages for Ollama, pushes to registry |
| `scripts/test_checkpoint_inference.py` | Smoke-tests a checkpoint with a real HAR input before packaging |
| `configs/training/qlora_har_specialist.yaml` | QLoRA config for `bola-har`: rank 32, bfloat16, 3 epochs, HAR specialist splits |
| `configs/training/` | Additional YAML configs for qlora/lora/dpo runs at different sizes (0.5B, 1B, 3B) |
| `models/adapters/` | Local LoRA/QLoRA checkpoint outputs (dev only) |
| `models/merged/` | Merged adapter + base model weights, ready for `ollama create` |
| `models/packaged/` | Modelfile-only packages for tested checkpoints |
| `data/training/sft/` | JSONL splits: `bola_har_specialist_train.jsonl`, `bola_har_specialist_eval.jsonl`, general `train.jsonl` / `valid.jsonl` |

---

## Docker Strategy

### Build Pipeline

```
docker build -f docker/Dockerfile.allinone -t bolai .
```

Three baking stages run inside the build:

1. **`bola-analyzer` model bake:** Ollama starts, pulls `qwen2.5-coder:3b`, runs `ollama create bola-analyzer -f /app/Modelfile`, then shuts down. General-purpose model weights are captured in the `/root/.ollama/models` layer.
2. **`bola-har` model bake:** The Dockerfile downloads `bola-har-q4km.gguf` (~1.8 GiB Q4_K_M) from a GitHub Release asset using a Docker build secret (`--secret id=gh_token`). Ollama starts, runs `ollama create bola-har -f /app/Modelfile.bola-har`, then shuts down. HAR specialist model weights are captured in a second layer. Pass the secret at build time: `docker build --secret id=gh_token,env=GITHUB_TOKEN -f docker/Dockerfile.allinone .`
3. **RAG bake:** `src/training/load_knowledge.py` loads the canonical knowledge base into ChromaDB at `/data/chroma` and downloads + caches the `all-MiniLM-L6-v2` embedding model. Both are captured in the `/data` layer.

### Published Image

```
docker pull ghcr.io/igorredkach/bolai:latest
```

Published automatically by GitHub Actions on every push to `main` that touches `src/`, `data/`, `docker/`, `pyproject.toml`, or `.github/workflows/`. Uses `ubuntu-latest` with freed disk space (removes dotnet/android/ghc toolchains) and CPU-only PyTorch to fit the runner.

### Running

```bash
# Drop your files into a shared folder, then start the container
cp capture.har ~/my-docs/
docker run -p 8000:8000 -v ~/my-docs:/shared-docs ghcr.io/igorredkach/bolai:latest
```

Open `http://localhost:8000/chat`. Files in the shared folder are auto-ingested and analyzed on startup — no internet required.

---

## Configuration Reference (Environment Variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_MODEL` | `bola-analyzer` | Model name used for non-HAR general pipeline |
| `BOLA_AI_HAR_MODEL` | `bola-har` | Model name used for PRISM-HAR pipeline |
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
| `BOLA_AI_FAKE_EMBEDDER` | `` | Set to `1` to skip sentence-transformers (tests only) |
| `BOLA_AI_LOG_MEMORY` | `` | Set to `1` to log process RSS at each pipeline step |
| `BOLA_AI_LOG_LEVEL` | `INFO` | Logging verbosity |
| `BOLA_AI_NUM_THREAD` | auto (2–8) | CPU thread count passed to Ollama |
| `BOLA_AI_EXAMPLES_MODEL` | `` | Model for ExampleGenerator (defaults to `bola-analyzer`; set to `bola-examples` when a specialist model is available) |
| `BOLA_HAR_MODEL` | `bola-har` | Model used by HarAnalyzer |
| `BOLA_HAR_NUM_PREDICT` | `2048` | Max output tokens for HAR specialist LLM pass |
| `BOLA_HAR_NUM_CTX` | `8192` | Context window for HAR specialist LLM pass |

---

## Memory Profile (CPU-only)

| Component | Approximate footprint |
|-----------|----------------------|
| Ollama + `bola-analyzer` (Q4_K_M, 3B) | ~2.1 GiB (1.8 GiB weights + 288 MiB KV cache) |
| Ollama + `bola-har` (Q4_K_M, 3B + merged adapter) | ~2.1 GiB (same base; Ollama loads only the active model) |
| ChromaDB + embeddings in memory | ~200–400 MB |
| FastAPI app (Python) | ~150–250 MB |
| **Total at inference time (one model active)** | **~2.5–3.0 GiB** |

Only one model is resident in memory at a time; Ollama unloads and reloads as needed when the active pipeline changes. Inference speed: ~5–8 tokens/second on a modern 8-core CPU. PRISM-HAR analysis is typically faster than general analysis because the ENTRIES LIST is more compact than raw chunked HAR text and grammar constraints eliminate retry overhead.

---

## Security and Disposability

- **No telemetry or outbound calls** from the application or LLM at runtime — all inference is local.
- **No persistence of user inputs** beyond the container/volume lifecycle — wipe the ChromaDB volume between sessions.
- **No API keys or cloud credentials required** — fully offline after `docker pull`.
- **RAG contamination prevention** — `rag_isolation.py` enforces source-level filtering per analysis session; fixture and adversarial docs are blocklisted and never surface in retrieval even if mistakenly ingested.
- **Grammar-constrained inference** — `bola-har` model output is structurally valid JSON at the token level; malformed output cannot reach the validator.
- **Deterministic PoC generation** — curl commands are built from parsed `HarEntry` fields, never from LLM text, preventing hallucinated endpoints in reports.

---

## File Layout

```
bolaAi/
├── src/
│   ├── bola_ai/
│   │   ├── api/
│   │   │   └── app.py                  # FastAPI app, all routes, startup automation, HAR metadata at ingest
│   │   ├── agent/
│   │   │   ├── prompts.py              # BOLA_SYSTEM_PROMPT, build_analysis_prompt (general pipeline)
│   │   │   ├── prompts_examples.py     # Isolated prompts for ExampleGenerator (REST/GraphQL/SOQL)
│   │   │   ├── runner.py               # Unified pipeline: HAR gate → enrichment → examples → report
│   │   │   ├── llm.py                  # Ollama httpx client, chat() with grammar param, is_available()
│   │   │   ├── har_analyzer.py         # HarAnalyzer: ENTRIES LIST → bola-har + GBNF → list[RawFinding]
│   │   │   ├── validator.py            # FindingValidator: RawFinding + FactIndex → list[ValidatedFinding]
│   │   │   ├── doc_enricher.py         # DocEnricher: ValidatedFinding + DocStore → list[EnrichedFinding]
│   │   │   ├── example_generator.py    # ExampleGenerator: EnrichedFinding → VerificationExample[]
│   │   │   └── report_renderer.py      # ReportRenderer: ValidatedFinding + enriched + examples → Markdown
│   │   ├── rag/
│   │   │   ├── store.py                # DocStore (ChromaDB wrapper)
│   │   │   ├── chunking.py             # chunk_text, HAR preprocessor
│   │   │   ├── embeddings.py           # sentence-transformers wrapper
│   │   │   ├── fake_embedder.py        # deterministic zero embedder for tests
│   │   │   ├── har_extractor.py        # HarExtractor: raw HAR text → StructuredArtifact (no LLM)
│   │   │   ├── fact_index.py           # FactIndex.build(): StructuredArtifact → O(1) fact lookups
│   │   │   └── rag_isolation.py        # KNOWLEDGE_SOURCES, CONTAMINATING_DOCS, build_session_source_filter
│   │   ├── config.py                   # All env-var config with defaults
│   │   ├── memory.py                   # RSS memory measurement helper
│   │   ├── logging_config.py           # Structured logging setup
│   │   └── cli.py                      # bola-ai CLI (health/ingest/analyze)
│   └── training/
│       ├── load_knowledge.py           # Loads knowledge into ChromaDB (build time + dev)
│       ├── generate_data.py            # Generates JSONL + RAG chunks from seeds
│       └── ai_teacher_prompts.py       # AI-assisted training data prompts
├── docker/
│   ├── Dockerfile.allinone             # Production image (both models + RAG baked in)
│   ├── Modelfile                       # bola-analyzer: system prompt + sampling params
│   ├── Modelfile.bola-har              # bola-har: HAR specialist system prompt + sampling params
│   └── entrypoint-allinone.sh          # Container startup script
├── data/
│   ├── knowledge/
│   │   ├── bola_patterns.md                         # Core vulnerability patterns (RAG)
│   │   ├── ai_teacher_bola_quality_patterns.md      # Authorization quality patterns
│   │   └── phase1_small_model_guidelines.md         # Verification strategy guidelines
│   └── training/
│       ├── sft/
│       │   ├── bola_har_specialist_train.jsonl      # HAR specialist training split
│       │   ├── bola_har_specialist_eval.jsonl       # HAR specialist eval split
│       │   ├── train.jsonl                          # General training split
│       │   └── valid.jsonl                          # General validation split
│       └── bola_rag_chunks.txt                      # Pre-chunked training examples (training pipeline only)
├── configs/training/
│   ├── qlora_har_specialist.yaml       # bola-har QLoRA training config
│   └── ...                            # Other qlora/lora/dpo configs
├── scripts/
│   ├── train_qlora_unsloth.py          # QLoRA fine-tuning via Unsloth
│   ├── post_training_package_and_push.py  # Merge adapter + package for Ollama + push
│   ├── test_checkpoint_inference.py    # Checkpoint smoke-test with real HAR input
│   └── ...                            # Eval, E2E, monitoring scripts
├── models/
│   ├── adapters/                       # Local LoRA/QLoRA checkpoint outputs (dev only)
│   ├── merged/                         # Merged adapter + base weights (input to docker build)
│   └── packaged/                       # Modelfile packages for tested checkpoints
├── tests/
│   ├── test_har_extractor.py           # HarExtractor unit tests (real HAR fixtures)
│   ├── test_fact_index.py              # FactIndex lookup tests
│   ├── test_har_analyzer.py            # HarAnalyzer tests with mocked LLM output
│   ├── test_validator.py               # FindingValidator pass/warn/reject logic
│   ├── test_report_renderer.py         # ReportRenderer curl generation per pattern type
│   ├── test_rag_isolation.py           # Source filter construction tests
│   └── fixtures/                       # Test document corpus (30+ scenarios)
├── docs/
│   ├── ARCHITECTURE.md                 # This file
│   ├── GOALS.md                        # Mission, vulnerability taxonomy, design principles
│   ├── MEMORY.md                       # RAM profile and low-memory guidance
│   ├── OFFLINE_DEPLOY.md               # Air-gapped deployment (chunk export/import)
│   └── proposals/                      # Design proposals and data generation standards
├── shared_docs/                        # Developer test documents (not in image; volume-mounted at runtime)
├── .github/workflows/
│   └── publish-image.yml               # CI: build + push to ghcr.io on src/data/docker changes
├── pyproject.toml                      # Package metadata + optional train/dev deps
└── README.md
```

---

This architecture supports the goals: local-only, broad vulnerability taxonomy with field-level authorization prioritized, auditor-friendly output with deterministic PoC generation, fully disposable, grammar-constrained HAR specialist inference, RAG contamination-isolated, and suitable for sensitive enterprise artifact analysis.
