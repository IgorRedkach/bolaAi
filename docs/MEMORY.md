# Memory Management

Use these when the host has limited RAM or the system stops the process.

## Target: under 10 GB

The tool is designed to stay **under ~10 GB** total RAM when running the full stack (Ollama + embedder + app). Rough breakdown:

| Component        | Typical RAM |
|-----------------|-------------|
| Ollama (1.5B)    | ~2–4 GB     |
| Embedder (MiniLM)| ~1–2 GB     |
| Chroma + app     | ~0.5 GB     |
| **Total**        | **~4–8 GB** |

To stay under 10 GB: use `BOLA_AI_N_CONTEXT=5` or `6`, and optionally a smaller Ollama model (e.g. `qwen2.5-coder:0.5b`). For minimal footprint (e.g. &lt;2 GB), use `BOLA_AI_FAKE_EMBEDDER=1` and run only ingest/UI, or run Ollama in a separate host.

## Reduce footprint

| Env var | Effect |
|--------|--------|
| `BOLA_AI_FAKE_EMBEDDER=1` | Do not load sentence-transformers/torch. Use for tests or ingest-only; RAG uses deterministic vectors. |
| `BOLA_AI_N_CONTEXT=5` | Fewer chunks sent to the LLM (default 10). Lowers prompt size and memory. |
| `BOLA_AI_MAX_CONTEXT_CHARS=8192` | Cap total RAG context length (chars). Omit for no cap. Reduces peak memory for large docs. |
| `OLLAMA_MODEL=qwen2.5-coder:0.5b` | Smaller Ollama model (if you run Ollama separately). |

## Logging

Set `BOLA_AI_LOG_LEVEL=DEBUG` for verbose logs (e.g. in docker-compose or when running the API). Default is `INFO`. Logs go to stderr and appear in `docker logs bola-ai`.

## Monitor memory from terminal (prevent runaway)

**Check consumption regularly** so Python does not exceed the tool limit (~10 GB). If you see a Python process above 10 GB, kill it to avoid OOM.

```bash
# One-off check (from repo root)
sh scripts/check_memory.sh

# Watch every 2 seconds while running tests or API
sh scripts/check_memory.sh 2
```

Targets: **tool (BOLA AI / uvicorn / pytest) ≤ 10 GB**; **agent/IDE ≤ 6 GB**. On a 32 GB system both can run if kept under these limits.

## Workflow

1. **If the system or IDE is killed (OOM):** Use `BOLA_AI_FAKE_EMBEDDER=1` for all local work (tests, API). Do not run `load_knowledge.py` or a full Docker build with embedder in the same session. Run tests with fake embedder only; run Docker/preload on a machine with more RAM or in a separate session.
2. **Tests:** Always use `BOLA_AI_FAKE_EMBEDDER=1` so pytest never loads torch.
3. **Dev without analysis:** Run API with `BOLA_AI_FAKE_EMBEDDER=1`; ingest and UI work; `/analyze` will fail until Ollama is available.
4. **Training data:** Run `generate_data.py` only (writes files, no model). Run `load_knowledge.py` in a separate, one-off process so the server is not holding the embedding model at the same time.
5. **Docker:** Use a smaller Ollama model tag in `OLLAMA_MODEL` and consider running Ollama in a separate container with a memory limit.
