# BOLA AI — Goals & Mission

## Mission

Build a **portable AI agent** that finds system vulnerabilities by investigating documentation and/or log traces. The tool serves government and regulated organizations (healthcare, finance, defense, critical infrastructure) in keeping **critical systems safe**. It runs **entirely offline**, produces **auditor-actionable findings** grounded in provided artifacts, and treats **quality as non-negotiable**: problems are analyzed and fixed at the root, never worked around.

Mission interpretation guardrails:
- The vulnerability taxonomy is **non-exhaustive** and continuously extensible.
- Quality is measured by **evidence, correctness, and actionability**, not by forcing a fixed number of findings.
- Goals should avoid overfitting to one fixture family, one platform, or one phrasing style.

## Vulnerability Taxonomy

The agent investigates a broad and evolving set of vulnerability classes. BOLA is the historical namesake and remains a primary focus, but the tool is not limited to a single weakness family. It detects and explains any vulnerability class that can be evidenced from documentation, schemas, API specs, HAR captures, or log/network traces.

### 2.1 Broken Object-Level Authorization (BOLA)

The Logic: failure in the **ownership invariant**. The system validates identity (authentication) but fails to verify the relationship between that identity and the requested resource instance.

- **Instance-to-user scoping failure:** object fetched by primary key but query omits caller user/tenant constraint.
- **Hierarchical/nested dependency gap:** parent access is checked, child-to-parent ownership is not re-verified for the current user.
- **Predictable traversal opportunity:** enumerable/patterned identifiers (sequential integers, timestamps, known carrier formats) enable object address guessing without discovery.
- **Cross-service identity propagation drift:** the caller's identity or tenant context is lost or weakened as a request crosses internal service boundaries.
- **Cache-key authorization mismatch:** cached responses keyed by object ID alone (no user/tenant dimension) serve data across users.
- **Mass assignment via object fields:** write endpoints accept fields that override ownership, role, or status attributes the caller should not control.

### 2.2 Broken Access Control (BAC)

The Logic: failure in the **enforcement boundary**. Users are not restricted to their functional mandate or administrative silo.

- **Functional pivot (vertical/horizontal):** access to endpoints or metadata outside the assigned role boundary (user calling /admin/ or /internal/ paths).
- **Metadata/attribute side-channel:** restricted object existence leaked via search, typeahead, recent-items, or analytics APIs.
- **State/session permeability:** external/portal sessions reach internal/standard views or setup menus.
- **Privilege escalation via parameter tampering:** role, group, or permission identifiers accepted from client input without server-side re-validation.

### 2.3 Insecure Design

The Logic: **systemic architectural flaw** where security is bypassed by the nature of the application's design.

- **Client-assumed authority:** backend trusts client-supplied security-sensitive state (price, role, status, discount) instead of re-calculating server-side.
- **Workflow decoupling:** multi-step flows (verification → processing → finalization) where the final state can be reached out-of-order without prerequisite re-checks.
- **Semantic ambiguity:** over-broad endpoints (upsert-style) blur distinct authorization checks for create vs update vs delete.
- **Implicit trust in third-party callbacks:** accepting state-changing webhooks or callbacks without cryptographic signature validation.

### 2.4 Software or Data Integrity Failures

The Logic: failure in **delegated trust**. A trusted process is manipulated into unauthorized actions.

- **Confused deputy/brokerage failures:** privileged internal services (PDF generators, email notifiers, cloud exporters) abused as proxies using internal system credentials to access private data.
- **Persistence poisoning via lifecycle actions:** clone/restore/sync/merge creates new objects inheriting data or permissions from a source the user was never authorized to see.
- **Integrity downgrade via versioning:** legacy API versions or protocols (v1.0, SOAP) bypass modern security filters while still touching production data.
- **Supply-chain injection:** untrusted dependencies, plugins, or serialized payloads injecting code or data into the trusted execution context.

### 2.5 Injection (Logic and Protocol)

The Logic: failure to **distinguish instruction from data**.

- **Authorization-bypass injection:** injected operators (OR 1=1, Lucene wildcards) nullify owner/tenant constraints in search filters or queries.
- **Resolver/graph traversal injection:** exploiting GraphQL, SOQL, or similar query languages to navigate from an authorized public node to an unauthorized private node via nested fields or aliases.
- **Server-Side Request Forgery (SSRF) via user-controlled URLs:** endpoints accepting URLs or file paths that the backend fetches, enabling access to internal resources.
- **Template/expression injection:** user input interpreted as template syntax (SSTI, EL injection) granting access to internal state or objects.

### 2.6 Security Misconfiguration

The Logic: **hardening failure** where code may be sound but environment settings expose the system.

- **Schema/relationship over-exposure:** introspection, WSDLs, Swagger/OpenAPI docs, or tooling APIs left enabled, revealing internal data model and field relationships.
- **Verbose error feedback:** detailed 500/403 responses leaking resource owner names, internal database keys, stack traces, or confirmation of high-value target existence.
- **Default credentials and unnecessary services:** shipped default accounts, debug endpoints, or unnecessary protocols still active in production.
- **Permissive CORS/CSP policies:** allowing unauthorized origins to make authenticated cross-origin requests or load untrusted scripts.

### 2.7 Security Logging and Alerting Failures

The Logic: **visibility failure**. Malicious object-boundary movement is not observable or investigable.

- **Operational PII/PHI leakage:** sensitive payloads (tokens, IDs, PII) over-logged into broadly accessible plaintext logs.
- **Anti-forensic capabilities:** actors can alter or delete audit trails tracking their own resource access.
- **Insufficient logging of authorization decisions:** object-level access grants/denials not logged, making breach reconstruction impossible.
- **Alert suppression via volume:** high-rate normal activity masking low-rate malicious access in alerting systems.

### 2.8 Mishandling of Exceptional Conditions

The Logic: **resilience failure**. Error conditions fail open (granting access) instead of fail closed.

- **Concurrency/race condition gaps:** temporary ownership-state windows during high-latency syncs where the owner association has not yet been committed.
- **Fail-open on timeout/exception:** authorization middleware that grants access when the authorization service is unavailable or returns an error.
- **Partial rollback exposure:** multi-step transactions where a failure rollback leaves intermediate state (files, records, permissions) accessible.
- **Resource exhaustion leading to bypass:** denial-of-service conditions that degrade authorization checks before availability checks.

### 2.9 Broken Authentication Boundaries

The Logic: **identity boundary failure** where authentication mechanisms can be subverted to assume another identity context.

- **Token scope leakage:** tokens issued for one service or audience accepted by a different service without audience validation.
- **Session fixation/confusion:** ability to force or predict session identifiers, binding a victim's authentication to an attacker-controlled session.
- **OAuth/OIDC misconfiguration:** redirect URI validation gaps, implicit flow token leakage, or insecure token storage patterns.

### 2.10 Cryptographic Failures Affecting Authorization

The Logic: **cryptographic weakness** enabling unauthorized data access or identity impersonation.

- **Weak or missing encryption of sensitive data at rest:** object-level data (PII, PHI, credentials) stored unencrypted or with weak algorithms.
- **Signature bypass on tokens or assertions:** JWTs with `alg:none`, SAML response manipulation, or HMAC/RSA confusion attacks.
- **Insufficient transport security:** internal service-to-service communication lacking TLS, enabling credential or token interception.

### Additional Related Classes (non-exhaustive)

This taxonomy is deliberately not closed. Any vulnerability class evidenced in provided artifacts is in scope, including but not limited to: object state machine abuse, webhook callback trust failures, API gateway routing bypasses, GraphQL depth/complexity attacks, deserialization vulnerabilities, business logic bypasses, and time-of-check-to-time-of-use (TOCTOU) flaws.

## Why BOLA is Prioritized

BOLA remains the primary investigation focus because:

- It is **easy to miss** in reviews and generic test plans.
- It is **high impact**: one flaw can expose large volumes of sensitive data.
- It is **common** in real systems (linked tables, shared IDs, missing checks).
- Regulated sectors hold data where BOLA leads to compliance breaches (HIPAA, PCI-DSS, FedRAMP).
- The other vulnerability classes in the taxonomy frequently **compound with BOLA** — BAC enables the pivot, insecure design enables the workflow skip, injection enables the constraint bypass.

## Design Principles

1. **Autonomous, no internet at runtime** — No outbound calls to external APIs, model registries, or update servers. Suitable for air-gapped and restricted environments. All required assets (model, RAG data) are baked into the image.
2. **Local only** — No data leaves the machine; no network required when running.
3. **Disposable** — Run in a container with ephemeral storage; wipe volume and delete container when done.
4. **Free and open** — No usage fees or vendor lock-in.
5. **Auditor-friendly** — Outputs concrete steps, example queries, and test cases so humans can verify findings.
6. **Artifact-driven** — Works from existing documentation, schemas, API specs, HAR captures, and log/network traces rather than requiring live system access.
7. **Offline deployable** — The built image can be downloaded or transferred by chunks to a target machine and run locally.

## Target Users

- **Internal security and compliance teams** in government and regulated organizations.
- **Auditors and assessors** checking APIs and systems for authorization, design, and integrity failures.
- **Developers and architects** doing security-by-design reviews of new APIs or integrations.
- **Incident responders** analyzing log/network traces for evidence of exploitation patterns.

## What the Tool Delivers

- **Analysis** of provided artifacts (documentation, schemas, API specs, HAR captures, log traces).
- **Findings** across the vulnerability taxonomy, grounded in evidence from provided artifacts, with clear rationale and confidence boundaries.
- **Verification support:**
  - Suggested queries (HTTP requests, GraphQL operations, SOQL, parameter changes).
  - Step-by-step instructions for auditors to confirm or rule out each finding.
- **No persistence of sensitive data** — container and volume can be destroyed after use.

## Success Criteria

- **No requests to the open internet** at runtime. Model and RAG data pre-loaded.
- **Trained LLM and knowledge base:** RAG preloaded from `data/knowledge/` and training data; Ollama model uses system prompt with few-shot examples (Modelfile). Extensible via `generate_data.py` and knowledge markdown.
- Runs **autonomously and fully offline** in Docker (LLM, vector DB, UI).
- Produces **actionable**, evidence-grounded findings with clear verification steps.
- Produces **logically valid** verification guidance: does not confirm vulnerabilities from auth failures (401), missing-object outcomes (404), or single-user tests alone; requires valid comparative checks grounded in artifact semantics.
- **No fixed finding-count requirement:** when artifacts contain limited evidence, the tool should return fewer high-confidence findings with explicit uncertainty; when artifacts contain broader evidence, it should surface all supported risks.
- **Broad vulnerability coverage:** identifies findings across the full taxonomy (2.1–2.10+) when evidenced in provided artifacts, not limited to a single class.
- **GraphQL, SOQL, and platform-specific support:** when docs describe GraphQL, SOQL/Salesforce, Aura/LWC, or other platform-specific patterns, findings use the appropriate syntax and verification approach.
- Can be **trained or adapted** via local data and the teaching pipeline.
- **Easy to tear down**: one workflow to wipe volumes and remove the container.
- **Deployable by chunks:** documented workflow to export, transfer, reassemble, and run on air-gapped machines.
- **Shared-volume document intake:** users place files in shared docs path and the tool auto-ingests.
- **Self-verification before answer:** the tool verifies its own results before returning (path grounding, redaction of unknown endpoints, correction of invalid confirmation logic, verification step validity). Implemented as post-processing normalization and prompt instructions.

All agents and LLMs used in the project should align with these goals: no internet at runtime, evidence-grounded investigation across the vulnerability taxonomy, auditor-friendly output, disposable operation, and **no quality shortcuts**.

---

## Goal governance (do not delete user goals)

- Existing goals in this file are **append-only** unless the user explicitly asks to delete a goal.
- Agents may **edit wording** for clarity, split one goal into multiple goals, or mark a goal as superseded/deprecated, but they must keep the original intent traceable in this file.
- If a goal is replaced, keep an explicit note like: `Supersedes: <old goal text/ID>` instead of deleting history.
- If an agent thinks a goal is obsolete and the user did not request deletion, move it to a short **Deprecated goals** subsection instead of removing it.

---

## Goals checklist (implementation, non-exhaustive)

This checklist tracks implementation progress and can include concrete mechanisms used at a point in time. It is **not** a fixed scoring rubric for model quality, and should not be interpreted as a requirement to find a specific number of risks or to mirror one example style.

- [x] **E2E always live:** `pytest tests/` requires a running API + Ollama when live E2E files are collected; no silent skip.
- [x] **No internet at runtime** — Tool runs autonomously offline.
- [x] Free, local-only tool.
- [x] Evidence-grounded vulnerability investigation from documentation and log/network traces across the full taxonomy.
- [x] Verification logic quality guardrails (no false confirmation from 401/404-only outcomes; endpoint grounding to provided documentation).
- [x] Adversarial manual verification cycle with generated tricky docs passes.
- [x] **GraphQL support**: identifies vulnerabilities in operations/arguments and nested resolvers; verification uses GraphQL syntax and two valid user tokens.
- [x] **SOQL/Salesforce support**: identifies record-level risks (sharing model gaps, cross-object subqueries) with appropriate verification steps.
- [x] Docker: LLM (Ollama) + Vector DB (Chroma) + UI (FastAPI); default startup uses pre-loaded model (no pull at runtime).
- [x] Ephemeral volume; wipe before/after use.
- [x] Portable memory profile with documented guardrails and low-memory test modes.
- [x] Train/adapt via RAG knowledge base + generated training data.
- [x] API + CLI for terminal and scripted use.
- [x] Automation tests (pytest with fake embedder).
- [x] **Trained, ready-to-go container:** model and RAG knowledge baked into image; no internet needed at startup.
- [x] Communicate with the model to give system info and get suggestions.
- [x] **Download built image by chunks:** scripts and docs for air-gapped deployment.
- [x] **Self-verification before answer:** path grounding, redaction, verification logic correction.
- [x] **No quality shortcuts:** root-cause analysis and fixes, not workarounds.
- [x] **Timeouts split:** longer waits for ingest/startup/training; LLM inference timeout not raised to mask slow replies.
- [x] **Agent E2E loop:** each quality loop uses new generated docs and expectations tied only to that run's data.
- [x] **Failures/interruptions → OPEN issues:** unfinished work tracked for next loop.
- [x] **Weak-place registry:** gaps tracked and verified before completion.
- [x] **Goal immutability by default.**
- [x] **Shared Docker volume ingestion workflow.**
- [x] **AI-assisted teaching pipeline scaffolding.**
- [x] **AI-agent teaching at scale:** recurring teacher/reviewer gate cycle.
- [x] **Diverse test-data generation is mandatory:** cross-type diversity across loops.
- [x] **Assume documentation is incomplete by default:** uncertainty marking when ownership controls are not documented.
- [x] **Trained model baked into shipped image.**
- [x] **Model-size policy decision (user-mandated):** production baseline is a local model; quality achieved via better teaching data, prompts, and evaluation loops.
- [x] **Small-model teaching phase 1.**
- [x] **Documentation quality skill available:** project docs edits should follow `.cursor/skills/docs-authoring-quality/SKILL.md`.
- [x] **Artifact archetyping for training tasks:** scenario prompts produce structural logic seeds aligned to HAR/OpenAPI/SQL archetypes.
- [x] **Template-wrapped synthetic artifacts:** task generation emits deterministic blueprint templates (OpenAPI, HAR-like logs, SQL DDL) instead of prose-only seeds.
- [x] **Artifact syntax validation gate in teaching cycle:** generated artifacts are parsed/validated by type (`json/yaml`, HAR JSON shape, SQL parse) before acceptance.
- [x] **Memory-safe task generation batching:** task pack writing uses bounded batch flushing to keep local RAM stable.
- [x] **From-scratch retrain policy:** model rebuild must start from base model in `docker/Modelfile` (not previous custom model), with old local custom model removed before `ollama create`.

---

## Conversational Follow-up Support

The agent must respond appropriately to simple user follow-up questions — not just full security analysis requests. Different question types require different response shapes:

- **"Generate a request to verify [finding]"** → complete, copy-pasteable HTTP request (curl-first for REST), grounded to the ingested doc.
- **"What does 200 vs 403 mean for this test?"** → brief, focused explanation of secure vs vulnerable outcome interpretation.
- **"Verify [endpoint]" / "Show me the request for [endpoint]"** → targeted curl with method, path, auth header; no full analysis prose.
- **General findings question** → structured findings response with finding headings and verification steps.

The response type must match the question type. Asking for "a request" must produce a request; asking for "findings" must produce findings — not the other way around.

**Teaching mechanism:** short-circuit fast paths in `runner._maybe_short_circuit_response()` and `_enforce_strict_adaptive_shapes()` handle deterministic question patterns. Training data (via `generate_data.py` and teacher prompts) reinforces the correct response shape per question type.

- [ ] **Conversational follow-up support:** tool responds to simple user questions with the appropriate response type — request generation, outcome explanation, or structured findings — grounded to ingested documentation.
- [ ] **Per-question-type response shape training:** training data includes examples of simple follow-up questions (request generation, outcome explanation, path verification) with gold-standard answers in the correct shape.

---

## Interactive Web Chat Interface

- [x] **Web chat UI:** interactive chat at `/chat` with markdown rendering, fully offline.
- [x] **Smart message routing:** ingest commands, help, analysis, and status handled intelligently.
- [x] **Shared docs awareness:** users can reference files in the shared volume.
- [x] **Usage guidance:** self-documenting help system.
- [x] **Manual web E2E verification.**
- [x] **Startup loading indicator.**

---

## User Document Awareness & Analysis Integrity

- [x] **Auto-ingest on startup.**
- [x] **Analysis requires user documents:** never runs analysis from training data alone.
- [x] **Broader ingest vocabulary.**
- [x] **Chat history persistence.**

---

## Startup Reliability & Testing Process

- [x] **Non-blocking auto-ingest.**
- [x] **All-in-one image smoke test in E2E.**
- [x] **Release verification cycle is mandatory after runtime bugs.**

---

## Hands-free Analysis (run, wait, read)

- [x] **Auto-analyze on startup:** users can run the container, wait, and see findings without typing anything.
- [x] **Context window configured** for model size to prevent prompt truncation.
- [x] **Conversational follow-up support goal defined:** new goal section added to `docs/GOALS.md`; training data expanded with 25 follow-up Q&A examples (request generation, outcome interpretation, findings summary); E2E logical correctness checker validates per-question-type response shape every run.
