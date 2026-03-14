# BOLA AI — Goals & Mission

## Mission

Build a **free, local-only AI security tool** for government and regulated organizations (e.g., healthcare, finance, government agencies) in the United States. The tool helps reduce security and compliance risk by analyzing documentation, schemas, and APIs to predict **Broken Object-Level Authorization (BOLA)** and related issues, then either tests automatically or gives auditors clear, actionable verification steps.

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

All agents and LLMs used in the project should align with these goals: no internet at runtime, BOLA-focused, auditor-friendly, and disposable.

---

## Goals checklist (implementation)

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
- [x] Low-memory option (BOLA_AI_FAKE_EMBEDDER, docs/MEMORY.md)
- [x] Automation tests (pytest with fake embedder). Do not wipe and delete container for test purposes on every test run only when specifically wiping is tested.
- [x] **Trained, ready-to-go container:** RAG preloaded with BOLA knowledge; Ollama model `bola-analyzer` from Modelfile. For offline: use pre-loaded Ollama volume or optional online setup profile to pull model once, then run offline.
- [x] Communicate with the model to give fake system info and get suggestions.
- [x] **Download built image by chunks:** Scripts and docs to export image (and optional model volume) as chunked files, transfer to air-gapped machine, reassemble, and run locally (see docs/OFFLINE_DEPLOY.md and scripts/).
