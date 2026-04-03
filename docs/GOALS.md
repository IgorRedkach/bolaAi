# BOLA AI — Goals & Mission

## Mission

Build a **world-class, portable, local-only AI security tool** for government and regulated organizations (e.g., healthcare, finance, government agencies) in the United States. The tool helps keep **critical systems safe** (national interests) by reducing security and compliance risk: it analyzes documentation, schemas, and APIs to predict **Broken Object-Level Authorization (BOLA)** and related issues, then either tests automatically or gives auditors clear, actionable verification steps. **Quality is non-negotiable:** no shortcuts, no cutting content or relaxing criteria to make steps “pass”; problems (timeouts, failures, poor output) must be **analyzed and fixed at the root**, not worked around.

## Primary Risk Focus: BOLA (Broken Object-Level Authorization)

**BOLA** is #1 in the OWASP API Security Top 10. It occurs when APIs do not verify that the authenticated user is allowed to access or modify the specific object (by ID, key, or path). Attackers exploit this by changing IDs, query parameters, or resource paths to access data or actions they should not have.

This tool prioritizes BOLA because:

- It is **easy to miss** in reviews and generic test plans.
- It is **high impact**: one flaw can expose large volumes of sensitive data.
- It is **common** in real systems (linked tables, shared IDs, missing checks).
- Regulated sectors (healthcare, finance, government) hold data where BOLA leads to compliance breaches (HIPAA, PCI-DSS, FedRAMP, etc.).

## Design Principles

1. **Autonomous, no internet at runtime** — The tool must run **without any requests to the open internet**. No outbound calls to external APIs, model registries, or update servers. Suitable for air-gapped and restricted environments. All required assets (model, RAG data) are either baked into the image or supplied via a pre-loaded volume.
2. **Local only** — No data leaves the machine; no network required when running the tool.
3. **Disposable** — Run in a container with ephemeral storage; when analysis is done, wipe the volume and delete the container so no sensitive artifacts remain.
4. **Free and open** — No usage fees or vendor lock-in; usable by any team with basic infrastructure.
5. **Auditor-friendly** — Outputs concrete steps, example queries, and test cases so humans can verify findings.
6. **Documentation-first** — Works from existing docs: system info, schemas, API specs, and runbooks rather than requiring live access.
7. **Offline deployable** — The built image (and optional model volume) can be **downloaded or transferred by chunks** (e.g. split archives) to a target machine and run locally without internet.

## Target Users

- **Internal security and compliance teams** in government and regulated companies.
- **Auditors and assessors** who need to check APIs and data access for BOLA.
- **Developers and architects** doing security-by-design reviews of new APIs or integrations.

## Real-World BOLA Examples (From Practice)

These illustrate the kinds of issues the tool is meant to help find and verify.

### 1. Salesforce — Unrestricted Related Table

- **Context:** A “restricted” case object was correctly scoped, but it was linked to a **team members** table that was **not** restricted.
- **Risk:** A user who should not see US persons data could reach it via the team members relationship.

### 2. APIs Without Permission Checks

- **Context:** APIs did not verify that the caller was allowed to access the requested patient.
- **Risk:** Any logged-in user could query and potentially retrieve **all patients’ personal data**, including diagnosis.

### 3. Logs and Queue Visibility

- **Context:** Logs contained full request details; when queue processing retried or failed, this information was visible to the operations team (including teams outside the country).
- **Risk:** Complaints, resolutions, and personal customer data under **GDPR** were exposed to people who should not have access.
- **Outcome:** Reputational and compliance risk; highlights that BOLA and data exposure can occur via logs and operational tooling, not only via APIs.

### 4. Third-Party Image Storage

- **Context:** Image storage was outsourced to a third party. API calls could be edited by any user.
- **Risk:** Users could obtain **full images and designs** of unreleased samples, enabling insider leakage and reputational harm.
- **Outcome:** Demonstrates BOLA in a multi-party, cross-border setup where object-level checks were missing.

## What the Tool Delivers

- **Analysis** of provided documentation (system info, schemas, API specs, runbooks).
- **Predictions** of likely BOLA and related authorization weaknesses, with brief rationale.
- **Verification support:**
  - Suggested queries (e.g., HTTP requests, parameter changes).
  - Step-by-step instructions for auditors to confirm or rule out the finding.
- **Optional automated checks** where the tool can run tests (e.g., ID enumeration, cross-tenant access) in a controlled way.
- **No persistence of sensitive data** — container and volume can be destroyed after use.

## Success Criteria

- **No requests to the open internet** — At runtime the tool does not send any requests to the internet. Ollama and the app talk only to each other (and the CLI to the app) on localhost/internal network. Model and RAG data are pre-loaded; no pull or download at run time.
- **Trained LLM and training data:** RAG is preloaded from `data/knowledge/` and `data/training/bola_rag_chunks.txt`; the Ollama model uses a BOLA system prompt (Modelfile). For adding examples and retraining: add markdown to `data/knowledge/`, extend `generate_data.py` output, and use `data/training/bola_training.jsonl` with your own weights/pipeline for fine-tuning (e.g. externally).
- Runs **autonomously and fully offline** in a Docker container (LLM, vector DB, UI).
- Produces **actionable**, BOLA-focused findings with clear verification steps.
- Produces **logically valid** verification guidance: do not confirm BOLA from auth failures (`401`, invalid token) or missing-object outcomes (`404`) alone; require two valid-user token comparison on an existing object ID.
- Passes **adversarial manual verification mode**: robust against ambiguous docs (legacy endpoint mentions, mixed scopes/roles, cross-tenant ambiguity) while staying grounded to active documented endpoints.
- **GraphQL and SOQL support**: When docs describe GraphQL (queries, mutations, nested resolvers) or SOQL/Salesforce (record-level sharing, WITH SECURITY_ENFORCED, cross-object queries), the tool identifies BOLA risks in those paradigms and provides verification steps using the appropriate syntax.
- Can be **trained or adapted** on BOLA patterns and organizational docs via local data and optional fine-tuning.
- **Easy to tear down**: one workflow to wipe volumes and remove the container when the analysis is complete.
- **Deployable by chunks:** There is a documented and scripted way to export the built image (and model data) as chunked files, transfer them to another machine (e.g. without internet), reassemble, and run the stack locally.
- **Shared-volume document intake:** Users can place documentation in the Docker-shared docs path and ingest by relative filename (no manual paste required), including agent E2E loops.
- **Self-verification before answer:** The tool **verifies its own results** before returning an answer to the customer, from a **critical perspective**, to reduce hallucinations. For example: check that every endpoint or resource mentioned in the report appears in the ingested documentation; flag or correct invented paths, wrong verification logic (e.g. 401/404 used to “confirm” BOLA), or off-topic findings; **REST-only docs:** strip invented **GraphQL** code fences in `runner._normalize_report` when context states no GraphQL / REST-only. This may be implemented as post-processing (e.g. normalization, path grounding, validation rules) and/or prompt instructions so that outputs are critically checked against the provided context before being shown to the user.

All agents and LLMs used in the project should align with these goals: no internet at runtime, BOLA-focused, auditor-friendly, disposable, and **no quality tricks** (no shortening prompts, cutting scope, or relaxing bar to avoid failures—fix root causes instead).

---

## Goal governance (do not delete user goals)

- Existing goals in this file are **append-only** unless the user explicitly asks to delete a goal.
- Agents may **edit wording** for clarity, split one goal into multiple goals, or mark a goal as superseded/deprecated, but they must keep the original intent traceable in this file.
- If a goal is replaced, keep an explicit note like: `Supersedes: <old goal text/ID>` instead of deleting history.
- If an agent thinks a goal is obsolete and the user did not request deletion, move it to a short **Deprecated goals** subsection instead of removing it.

---

## Goals checklist (implementation)

- [x] **E2E always live:** `pytest tests/` **requires** a running API + Ollama when live E2E files are collected (see docs/E2E_TESTING.md); no silent skip. Unit-only runs exclude those files. In-process tests use fake embedder where applicable (docs/MEMORY.md).
- [x] **No internet at runtime** — Tool does not send any requests to the open internet; runs autonomously offline.
- [x] Free, local-only tool
- [x] BOLA-focused analysis with verification steps
- [x] Verification logic quality guardrails (no false BOLA confirmation from 401/404-only outcomes; endpoint grounding to provided documentation)
- [x] Adversarial manual verification cycle with generated tricky docs passes
- [x] **GraphQL support**: identifies BOLA in operations/arguments (user(id), deleteDocument(id), nested resolvers); verification uses GraphQL syntax and two valid user tokens; heading bleed and auth-only verification post-corrected
- [x] **SOQL/Salesforce support**: identifies record-level BOLA (missing WITH SECURITY_ENFORCED, cross-object subqueries, sharing model gaps) with SOQL-aware verification steps
- [x] Docker: LLM (Ollama) + Vector DB (Chroma) + UI (FastAPI); default startup uses pre-loaded model (no pull at runtime).
- [x] Ephemeral volume; wipe before/after use
- [x] Strategy that tool consumes less than 10 GB
- [x] Train/adapt via RAG knowledge base + generated training data (generate_data.py, load_knowledge.py)
- [x] API + CLI for terminal and scripted use (run every time via `python -m bola_ai.cli` or `bola-ai`)
- [x] Automation tests (pytest with fake embedder). Do not wipe and delete container for test purposes on every test run only when specifically wiping is tested.
- [x] **Trained, ready-to-go container:** RAG preloaded with BOLA knowledge; Ollama model `bola-analyzer` from Modelfile. For offline: use pre-loaded Ollama volume or optional online setup profile to pull model once, then run offline.
- [x] Communicate with the model to give fake system info and get suggestions.
- [x] **Download built image by chunks:** Scripts and docs to export image (and optional model volume) as chunked files, transfer to air-gapped machine, reassemble, and run locally (see docs/OFFLINE_DEPLOY.md and scripts/).
- [x] **Self-verification before answer:** Tool verifies its own results before answering the customer (path grounding, redaction of unknown endpoints, correction of 401/404 BOLA logic, two-token verification phrasing) to reduce hallucinations. Implemented in `runner.py` via `_normalize_report`; can be extended with additional validation (e.g. explicit checklist before return).
- [x] **No quality shortcuts:** Agent and development process require analyzing and fixing root causes for failures (timeouts, bad output); no shortening queries, cutting content, or relaxing criteria to make steps “pass.” Documented in GOALS and agent prompt.
- [x] **Timeouts split (Issue 17):** Longer waits for **ingest**, **stack startup**, and **training load**; **LLM inference** timeout (`BOLA_AI_LLM_CHAT_TIMEOUT`) not increased to mask slow replies — improve model/prompt/hardware instead.
- [x] **Agent E2E loop:** Each quality loop uses **new** generated docs, **new** person-style questions, and **expectations tied only to that run’s data** (see AGENT_PROMPT_FULL_CYCLE.md E). E2E-loop failures are **`[E2E-LOOP]`** issues with tests in **`tests/test_e2e_loop_failures.py`**, run **separately** from `test_issues_resolved.py`.
- [x] **Failures/interruptions → OPEN issues:** Failed or interrupted loops create **OPEN** tasks in ISSUES.md; the next loop continues until those (and goals) are satisfied — see AGENT_PROMPT hard requirement 3b.
- [x] **Progress writes OK, stopping is not:** Agents may document what’s done mid-loop but must **continue** until OPEN issues, goals, and improvements are cleared — see AGENT_PROMPT (“Progress notes vs stopping”).
- [x] **Weak-place registry:** Gaps are tracked in **`docs/AGENT_WEAK_PLACES.md`**; **OPEN** rows block “done”; agents **chain fix → re-verify loops** in-session per **`docs/AGENT_PROMPT_FULL_CYCLE.md`** and **`docs/ANALYSIS_AGENT_LOOP_STOP_GAP.md`**.
- [x] **Goal immutability by default:** Agents must not delete user-defined goals from `docs/GOALS.md` unless the user explicitly requests deletion; goals are edited/superseded with traceability.
- [x] **Shared Docker volume ingestion workflow:** Users can provide docs by copying files into shared docs volume/path (`shared_docs` ↔ `/shared-docs`), then ingest via API/CLI (`POST /ingest_shared`, `bola-ai ingest-shared`). Agent E2E uses this path by default.
- [x] **AI-assisted teaching pipeline scaffolding:** Prompt templates + task-pack generator exist to create high-quality synthetic docs/schemas/network logs and grounded expected responses for continuous model teaching (`src/training/ai_teacher_prompts.py`, `scripts/generate_ai_training_tasks.py`, `docs/AI_MODEL_TEACHING_PLAN.md`).
- [x] **AI-agent teaching at scale:** Recurring teacher/reviewer gate cycle implemented with acceptance artifacts and trend tracking (`scripts/run_ai_teaching_cycle.py`, `data/training/ai_cycles/teaching_cycle_summary_*.json`), with accepted-only output packs.
- [x] **Diverse test-data generation is mandatory:** Agent E2E fixture rotation enforces cross-type diversity across loops (`rest_doc`, `graphql`, `salesforce_soql`, `har_like`) via `scripts/run_agent_e2e_loop_once.py` + `docs/e2e_fixture_rotation_state.json`.
- [x] **Assume documentation is incomplete by default:** Runtime prompt now explicitly requires uncertainty marking when ownership controls are not documented (`src/bola_ai/agent/prompts.py`), and phase-1 teaching prompts enforce an `## Uncertainty` section.
- [x] **Trained model must be baked into shipped image:** Production image must include the prepared model (not a fresh runtime pull). Startup should fail fast when the baked model is missing unless explicit fallback is opted in.
- [x] **Model-size policy decision (user-mandated):** Standard runtime baseline is a smaller local model class (3B/3.5B-class). Do not use larger-model defaults or targets for this project line; quality must be achieved via better teaching data, prompts, and evaluation loops on the smaller model.
- [x] **Small-model teaching phase 1 (mandatory):** Implemented and executed: strict phase-1 prompts/contracts, curated cross-domain task profile, and gate execution with cycle summary artifacts (`docs/SMALL_MODEL_PHASE1_PLAN.md`, `scripts/generate_ai_training_tasks.py --phase small-model-phase1`, `scripts/run_ai_teaching_cycle.py`).

---

## Interactive Web Chat Interface

- [x] **Web chat UI:** Interactive chat page at `/chat` (same port 8000) where users can converse with the BOLA agent in natural language. Messages and responses displayed in a chat bubble layout with markdown rendering. Works fully offline (no CDN dependencies).
- [x] **Smart message routing:** Backend `/api/chat` endpoint that intelligently routes user messages: ingest commands trigger document ingestion from shared volume; help/usage questions return guidance; analysis questions go to the LLM; status/reset commands are handled directly.
- [x] **Shared docs awareness:** Users can say "I copied files to the volume" or "list files" and the tool responds with available documents and offers to ingest them. `GET /api/shared_docs` endpoint lists files in the shared docs directory.
- [x] **Usage guidance:** When asked "how do I use this tool?" or "help", the tool returns clear, structured guidance covering all features (ingest, analyze, shared docs, reset, chat commands). This makes the tool self-documenting for new users.
- [x] **Manual web E2E verification:** Agent prompt E2E includes a step to open `http://localhost:8000/chat` in a browser and verify the chat interface works (send a message, see response, test ingest command). Documented in `docs/E2E_TESTING.md`.
- [x] **Startup loading indicator:** When Ollama is not yet ready (model downloading, container booting), the chat UI shows a clear loading/startup state instead of appearing broken. The health dot turns red/amber, a banner explains the system is starting up, and chat input is disabled until the backend is healthy. Prevents user confusion during first-run model download.

---

## User Document Awareness & Analysis Integrity

- [x] **Auto-ingest on startup:** When the container starts and files exist in the shared docs folder (`/shared-docs`), auto-ingest them so the user doesn't have to manually say "ingest". The chat UI shows what was auto-ingested. Health endpoint reports `user_documents` count and `user_doc_sources`.
- [x] **Analysis requires user documents:** The tool must NEVER run BOLA analysis if only preloaded RAG knowledge exists (no user documents ingested). Instead, it returns clear instructions: list available files, suggest ingesting them. Prevents hallucinated findings from generic training data.
- [x] **Broader ingest vocabulary:** The tool understands a wide range of natural language phrases for ingesting files: "get my files", "investigate my documents", "take a look", "scan the folder", "check my docs", "analyze my files", "read the documents", "look at my files", "process the docs", etc. All trigger bulk ingest from the shared folder.
- [x] **Chat history persistence:** Chat conversation is preserved across page reloads via localStorage. A "Clear" button lets users wipe history.

---

## Startup Reliability & Testing Process

- [x] **Non-blocking auto-ingest:** Auto-ingest runs in a background thread so the server starts accepting connections immediately. Health endpoint reports `auto_ingest_status` for UI progress display.
- [x] **All-in-one image smoke test in E2E:** Cold-start image smoke verified on freshly pulled `ghcr.io/igorredkach/bolai:latest` with a new shared-doc fixture and manual `/chat` command checks (`help`, `list files`, `ingest <file>`, analysis question, `status`) after startup wait.
- [x] **Release verification cycle is mandatory after runtime bugs:** Completed full publish/pull/verify cycle in-session: pushed code to `main`, removed local BOLA containers/images, pulled newer `latest` digest, ran from scratch with new shared docs, waited startup window, and revalidated health/chat/analyze behavior.

---

## Hands-free Analysis (run, wait, read)

- [x] **Auto-analyze on startup:** When the container starts with files in shared_docs/, after auto-ingest completes and Ollama is ready, automatically run BOLA analysis and store the result. The chat UI fetches and displays it on load. Users can: `docker run -p 8000:8000 -v ~/shared:/shared-docs ghcr.io/igorredkach/bolai:latest`, wait ~15 minutes, open `/chat`, and see the full analysis without typing anything.
- [x] **Ollama context window fix:** Set `num_ctx: 8192` in Ollama API options to prevent prompt truncation when RAG context + system prompt exceeds the default 4096 token limit.
