# Analysis: Person-style E2E drift (why answers were not “good enough”)

## What you asked for

1. **New** user-perspective data → ingest → **person-like** API dialogue (including **more detail / support**).
2. **Evaluate** answers: good, grounded, **no spurious improvement proposals** only if truly clean.

## What actually happened (energy billing E2E, 2025-03-18)

| Call | Intent | Problem |
|------|--------|---------|
| q1–q3 | Initial BOLA + bulk + GraphQL | Mostly grounded to `/energy/v2/...`, `usagePoint`. |
| q4 | SOC runbook + 200 vs 403 | Model emitted **long** answer with **GraphQL** (`billingAnalyst`, `exportJob`, `customer`, `user { orders }`) and **SOQL** — **none appear in the ingested doc**. |
| q5 | Fake-token curls | **Good:** used `/energy/v2/meters/obj-demo-9911/readings` etc. |
| q6 | Path audit YES/NO | Listed real paths but also **invented** `document(id)`, GraphQL `meter`, SOQL `User` — **not in doc**. |

So: **partial success.** Follow-ups that demanded **length and structure** triggered **pattern completion** from training + **generic system prompt** (GraphQL/SOQL examples), not from the doc.

## Root causes (ordered)

1. **System prompt** explicitly teaches GraphQL *and* SOQL as **always-relevant** patterns (`user(id)`, SOQL examples). The model generalizes to “security answer = include GraphQL + SOQL blocks” even when the **retrieved excerpt is REST-heavy**.
2. **No hard negative constraint** in the user message: “Do not mention X if not in excerpt.”
3. **RAG** may retrieve chunks that mention SOQL/GraphQL from the **knowledge base**, mixing with a **REST-only** one-time doc → context pollution.
4. **Long-form follow-ups** (runbook, 8 steps) increase **hallucination rate** (fill tokens with plausible templates).
5. **Process gap:** Docs said “evaluate” but did not **require** a written pass/fail on **grounding** before declaring the loop done.

## Documentation / prompt updates (to avoid repeat)

| Layer | Change |
|-------|--------|
| **System prompt** | GraphQL section **only if doc has GraphQL**; SOQL **only if doc mentions SOQL/Salesforce**; otherwise **forbid** those topics. |
| **User prompt (every analyze)** | Append **hard constraint:** every path/operation/example must appear **verbatim** in excerpt; zero invented APIs. |
| **AGENT_PROMPT / E2E_TESTING** | After person E2E, **grounding checklist:** any operation not in doc → **failure** → fix prompt or file `[E2E-LOOP]`. |
| **Evaluation** | Do not claim “no improvements” if q4/q6 contain **any** path/operation not in source doc. |

## Solution implemented (code)

- `prompts.py`: conditional GraphQL/SOQL in system text; **`GROUNDING_USER_SUFFIX`** every analyze; ban **"Assume the API has…"** for undocument features.
- **q4 script text** duplicated **STRICT** block (models often weight last user message heavily).
- This doc + ISSUES Last E2E pointer.

## Second observation (WMS REST-only, after first fix)

Even with suffix, **q4** still emitted hypothetical SOQL/GraphQL ("Assume the API has…"). **Second fix:** explicit **STRICT** paragraph at start of q4 + system prompt line. Re-test WMS q4 after that.

## Residual risk

- Small models may still drift; **post-LLM validation** (reject/report unknown tokens) is a possible next step.
- **RAG `N_CONTEXT`:** fewer chunks reduces cross-topic bleed.

## Re-run criterion

After changes, repeat **6-step person E2E** on **REST-only** doc; **q4** must contain **zero** of: `graphql`, `soql`, `salesforce`, `User { orders`, `Assume the API has` (case-insensitive checks).
