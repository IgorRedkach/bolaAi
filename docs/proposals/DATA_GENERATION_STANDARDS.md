# Data Generation Standards for PRISM-HAR Training Examples
**Date:** 2026-04-24  
**Applies to:** All 580 training examples in `bola_har_specialist_train.jsonl` and `bola_har_specialist_eval.jsonl`

---

## The Core Principle: Individual Reasoning, Not Templates

Every training example must be generated through deliberate individual thought.
Before generating any example, the generator (human or agent) must answer:

1. **Which specific real-world system does this HAR represent?** Name it specifically — not "an e-commerce API" but "a mid-size B2B SaaS CRM for logistics companies called FreightCo." The more specific, the more realistic the example.

2. **Why does this pattern appear here?** What business logic created this vulnerability? What does the developer who wrote this API think they're doing vs. what they're actually allowing?

3. **What does a real security analyst write in this report?** Not a template sentence but the actual analytical observation a senior pentester would make.

4. **What makes this example different from the previous 14 examples for this pattern?** If you cannot name a concrete difference (different domain, different ID format, different noise context, different response content, different confidence level), you are generating a duplicate.

Scripted examples → model memorizes template → fails on real HAR files.
Individual thoughtful examples → model learns security reasoning → works on real HAR files.

---

## Section 1: Example Structure Specification

Every training example is a single JSON object (one line in JSONL):

```json
{
  "id": "har-001",
  "category": "positive_single",
  "pattern_id": "1.1",
  "confidence_level": "high",
  "noise_types": [],
  "instruction": "You are a BOLA/authorization security analyzer. Analyze the following HAR entries for authorization vulnerabilities. Output a JSON array of findings. Reference only entry IDs from the entries provided. For every finding, evidence_quote must be a verbatim substring of the corresponding entry text.",
  "context": "### HAR Entry [1]\n...",
  "target": "[{...}]"
}
```

Field rules:
- `id`: sequential within category, e.g. `har-001` through `har-500` for SFT, `har-dpo-001` through `har-dpo-080` for DPO
- `category`: one of `positive_single` | `positive_multi` | `negative` | `noisy_positive` | `ambiguous` | `edge_case`
- `pattern_id`: the BOLA taxonomy ID from `bola_patterns.md` (e.g., `"1.1"`, `"10.2"`)
- `noise_types`: list of noise type codes present in this example (e.g., `["N1", "N3"]`)
- `instruction`: IDENTICAL for all SFT examples — do not vary it
- `context`: the condensed HAR excerpt (see Section 2)
- `target`: valid JSON string (passes `json.loads()`) — the expected model output

---

## Section 2: HAR Excerpt Format (Context Field)

The context must use this exact format for every entry. Consistency is critical: the model learns
the format during training and will expect it at inference time.

```
### HAR Entry [N]
Method: {GET|POST|PUT|PATCH|DELETE}
URL: https://{host}{path}?{query_if_any}
Path: {path_only}
{Query: key1=val1&key2=val2}          ← include only if query string is present
{Headers:}                             ← include only security-relevant headers
  Authorization: Bearer {40chars}...
  Cookie: sid={value}; ...
  X-Tenant-Id: {value}
  Content-Type: {value}
  Cache-Control: {value}              ← response header, include only if relevant
  ETag: "{value}"                     ← response header, include only if relevant
  Vary: {value}                       ← response header, include only if relevant
{Body (JSON):}                        ← include for POST/PUT/PATCH with JSON body
  {
    "field1": "value1",
    ...
  }
{Body (form-encoded):}                ← include for URL-encoded POST
  field1=value1
  field2=value2
Response: {status_code} {status_text}
{Response body:}                      ← include when content provides evidence (e.g. shows multi-user data)
  {first 300 chars}
```

Rules:
- Blank lines between `### HAR Entry [N]` blocks — use double newline (`\n\n`)
- No trailing whitespace on any line
- Always include `Method:`, `URL:`, `Path:`, `Response:` — these four are required
- Include `Headers:` block only if at least one security-relevant header exists
- Include body only for POST/PUT/PATCH or if body content is evidence
- Include response body excerpt only when it provides direct evidence of the finding
  (e.g., it shows data belonging to a different user than the request's auth token)
- Response headers (`Cache-Control`, `Vary`, `ETag`) appear in the `Headers:` block, indented
- Bearer tokens: always truncate to first 40 characters + `...`
- Never use placeholder strings like `<token>`, `<id>`, `{placeholder}` — use realistic values

---

## Section 3: Target JSON Specification

The target must be a valid JSON string (will be passed through `json.loads()` at validation time).

### For positive examples (one or more findings):

```json
[
  {
    "entry_id": 1,
    "pattern_id": "1.1",
    "pattern_name": "ID in Path Without Ownership Check",
    "evidence_quote": "GET /api/v1/invoices/84721 ... Response: 200 OK",
    "attack_delta": "Enumerate adjacent integer IDs (/api/v1/invoices/84720, 84719, ...) using the same Authorization: Bearer token to retrieve invoices belonging to other customers.",
    "poc_entry_id": 1,
    "confidence": "high",
    "note": ""
  }
]
```

### For negative examples (no findings):

```json
[]
```

### Field-level rules:

**`evidence_quote`** — this is the most important field and the most likely failure mode.
- Must be a verbatim substring of the context string for `entry_id` (exact character match including spaces)
- Must include the most diagnostic content: the URL path with the ID + the response status
- Length: 40–200 characters (shorter = more precise; longer = OK if needed for context)
- Must NOT include `[N]` or `### HAR Entry` — just the content of the entry
- If the evidence comes from multiple entries (e.g., entry [1] and entry [2] both show the same
  pattern), pick the single most diagnostic entry. Multi-entry evidence goes in `note`.
- WRONG: `"The fields array is caller-controlled"` (interpretation, not quote)
- RIGHT: `"fields: ['Account.Name', 'Account.Industry']"` (verbatim from entry body)
- RIGHT: `"GET /api/v1/invoices/84721 ... Response: 200 OK"` (verbatim from entry)

**`attack_delta`** — the minimal change a tester would make to probe the vulnerability.
- Must name the specific parameter/path/field to modify
- Must specify the value to use (or a description specific enough to implement)
- Must reference only paths/hosts/params that exist in the context entries
- Length: 80–300 characters
- WRONG: `"Try changing the ID"` (too vague)
- RIGHT: `"Replace the invoice ID 84721 in the URL path /api/v1/invoices/84721 with 84720 (or any adjacent integer) while keeping the Authorization: Bearer token unchanged. If the server returns a different invoice, BOLA is confirmed."`

**`confidence`**:
- `"high"`: the HAR directly demonstrates the vulnerability signal (200 response to different IDs, caller-controlled fields array, etc.)
- `"medium"`: the surface is exposed but the HAR doesn't confirm exploitation (no second ID to compare, response body truncated, unclear ownership)
- `"low"`: weak signal or conflicting evidence (server might enforce ownership but we can't tell from this HAR)

**`note`**:
- Leave as `""` for simple, clear findings
- Use for: multi-entry evidence references, single-session HAR limitations (1.11), borderline cases, degraded confidence explanations

---

## Section 4: Realism Standards for HAR Content

### 4.1 Hosts

Use domain names that feel like real company APIs. The domain must match the scenario.
Do NOT use: `example.com`, `test.com`, `api.test`, `localhost`, `127.0.0.1`, `placeholder.io`.

Good examples:
- `api.freight-connect.io`
- `app.legalops-suite.com`
- `platform.medicloud-emr.com`
- `api.fintracker-pro.com`
- `crm.talentflow-hr.io`
- `cloud.scm-nucleus.com`
- `{tenant}.acmecloud.io`

### 4.2 IDs

Each ID must be appropriate for its type. Think about what system generates this ID.

Integer IDs in paths (1.1, 1.8, 10.1):
- User IDs: 5-7 digits (not starting at 1), e.g., `84721`, `23094`, `118243`
- Invoice/order IDs: 5-6 digits, possibly non-sequential
- Case/ticket IDs: use mixed prefix format (`CASE-2024-00421`, `TKT-88291`, `ORD-2441098`)

UUID IDs:
- Must be valid v4 UUID format: `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`
- Use realistic examples: `550e8400-e29b-41d4-a716-446655440000` is fine, don't make them too short
- Never use `00000000-0000-0000-0000-000000000000` (too obviously fake)

Salesforce IDs:
- 15-char: `001cT00000DQOoo` (format: `001` + 12 alphanumeric)
- 18-char: `001cT00000DQOooQAH` (15-char + 3 checksum chars)
- RecordType prefixes: `001` (Account), `003` (Contact), `500` (Case), `006` (Opportunity)

Temporary/short IDs (10.3):
- 6-char base62: `a7f3x2`, `b9kQrT`
- Short integer: 4-5 digits: `88291`, `34012`
- Job/export tokens: `exp_a7f3x2k9`, `job_2024042188291`

### 4.3 Bearer Tokens

Format: always `eyJhbGci...` prefix (base64url of JWT header) truncated to exactly 40 chars + `...`

Examples:
- `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...`
- `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`
- `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...`

Vary the algorithm prefix (RS256, HS256, ES256) across examples. Never use `Bearer token`, `Bearer abc123`, or `Bearer REDACTED`.

### 4.4 Response Bodies

Response body excerpts serve as evidence when they confirm the finding (multi-user data, mass assignment fields accepted, etc.). When included:
- Use realistic field names and values for the domain
- Vary the structure (sometimes flat JSON, sometimes nested)
- Include a `userId`, `ownerId`, or `customerId` field when this is evidence for 1.1, 1.3, 10.1
- Do not include more than 300 characters

### 4.5 Domain Scenarios

The 6 domain contexts to rotate across examples (at least 2-3 examples per domain per pattern):

1. **B2B SaaS CRM for logistics/freight** — invoice management, freight orders, carrier documents
2. **Healthcare administration platform** — patient records, appointment scheduling, prescriptions
3. **Legal/contracts platform** — contract drafts, e-signatures, billing records
4. **Financial services / fintech** — account statements, transaction history, payment methods
5. **HR/talent management SaaS** — employee records, payroll, performance reviews
6. **E-commerce / retail platform** — orders, returns, customer accounts, product listings

For each example, decide which domain BEFORE writing the HAR content. Do not mix domain context mid-example.

---

## Section 5: Thinking Process for Each Example

Before writing any example, work through these questions:

### For positive examples:

1. **Which domain and scenario?** (be specific: "a B2B logistics CRM where carrier companies manage their freight orders and invoices")
2. **What API endpoint is exposed?** (specific path, not generic)
3. **What is the realistic business context?** (why does this endpoint exist, who normally calls it)
4. **What observable HAR signal proves the pattern?** (specific field/header/ID that is the smoking gun)
5. **What noise entries, if any, should accompany this entry?** (at least one N3 or N2 noise entry for noisy examples)
6. **What would the evidence_quote be?** (write it out verbatim from the context you're about to create)
7. **What confidence level?** (apply the rules from Section 3)

### For negative examples:

1. **What type of noise is this?** (be specific: "OAuth2 authorization code flow for a healthcare app")
2. **What misleading signals are present?** (IDs in URLs, tokens in bodies, etc. that are NOT BOLA)
3. **Why is this not a BOLA finding?** (the specific reason: proper 403, auth flow only, static resource, etc.)
4. **Would a naive model flag this?** (the best negative examples are ones that would fool a template-based model)

### For noisy positive examples:

1. **Which BOLA entry is the real finding?**
2. **Which 2-5 noise entries accompany it?** (mix types: auth + static, or analytics + internal)
3. **Are the noise entries realistic for this scenario?** (a healthcare app would have HIPAA-audit telemetry, not gaming analytics)
4. **Is the BOLA entry clearly distinguishable from the noise?** (it should require actual security reasoning to identify, not just "the longest entry")

---

## Section 6: Anti-Patterns to Avoid

These are specific patterns that produce low-quality training data. Check every example against this list.

### Anti-Pattern 1: Generic Domain Context

WRONG: "An API for a company that manages user data"
RIGHT: "A B2B SaaS CRM for freight logistics companies, FreightCo, where carrier companies (e.g., 'Alpine Freight Partners') manage their shipping documents and invoices"

### Anti-Pattern 2: Placeholder IDs

WRONG: `GET /api/users/{userId}`, `GET /api/users/123`, `GET /api/users/1`
RIGHT: `GET /api/users/84721/profile` (realistic 5-digit user ID, specific resource)

### Anti-Pattern 3: Evidence Quote That Is Not in Context

WRONG: Target says `"evidence_quote": "caller controls the field selection"` but context
says `"fields: ['Account.Name', 'Account.Industry']"`.
The evidence quote `"caller controls the field selection"` does not appear in context.

RIGHT: `"evidence_quote": "fields: ['Account.Name', 'Account.Industry']"` — verbatim.

### Anti-Pattern 4: Same Evidence Quote Across Multiple Examples

If examples `har-001` and `har-007` both have `evidence_quote: "Response: 200 OK"`,
that evidence quote is worthless — it's present in almost every positive example.
The evidence quote should uniquely identify the BOLA signal in that specific entry.

### Anti-Pattern 5: Attack Delta That Invents New Endpoints

WRONG: `"attack_delta": "Try calling GET /api/users/84721/admin-panel"` (admin-panel not in HAR)
RIGHT: `"attack_delta": "Replace the user ID 84721 in /api/v1/users/84721/profile with an adjacent integer (84720, 84722) using the same Bearer token."` (path is from the HAR)

### Anti-Pattern 6: Confidence "High" for Ambiguous Signals

A single GET with a UUID in the path and a 200 response is NOT high confidence BOLA.
It's medium confidence — we can see the surface but not confirm exploitation from one HAR entry.
High confidence requires: multiple IDs showing same 200 behavior, OR caller-controlled ID array in body, OR response body showing data from a different user.

### Anti-Pattern 7: Noise Entries That Don't Feel Like the Same System

If the BOLA entry is from `api.freight-connect.io`, the noise entries must also be from the
same browsing session of a FreightCo user — not random endpoints from unrelated systems.
The noise should be what a real HAR capture of that session would contain:
- The user logged in → auth flow (N1)
- The page loaded → static assets from `cdn.freight-connect.io` (N3)
- The user's browser sent analytics → N2 entry to `analytics.freight-connect.io`

### Anti-Pattern 8: 10+ Entries in One Example

Keep HAR excerpts to 2-8 entries. More than 8 entries makes the context very long and dilutes
the training signal. If you need to show a multi-step flow, use 3-4 key entries and omit the rest.

### Anti-Pattern 9: Multi-Finding Example Where Findings Are Identical Pattern

A multi-finding example should demonstrate 2-3 DIFFERENT patterns, not two instances of pattern 1.1.
E.g., a multi-finding example might have: [1.1: ID in path] + [1.6: write without ownership] OR
[1.3: bulk list] + [1.12: mass assignment].

---

## Section 7: Validation Checklist (Per Example)

Run through this checklist mentally before finalizing each example:

- [ ] `json.loads(target)` succeeds (no JSON syntax errors)
- [ ] For every finding in target: `entry_id` appears as `[{entry_id}]` in context
- [ ] For every finding in target: `evidence_quote` is a verbatim substring of context
- [ ] For every finding in target: `poc_entry_id` appears as `[{poc_entry_id}]` in context
- [ ] `attack_delta` references only URLs/paths present in context
- [ ] No finding has `confidence: "high"` for a pattern where only medium is warranted (see Section 3)
- [ ] No evidence quote is shorter than 20 characters (too vague to be useful)
- [ ] HAR entry format uses real-looking values (no placeholders, no sequential 1/2/3 IDs)
- [ ] Domain context is consistent across all entries in the example
- [ ] This example is meaningfully different from similar examples already generated for this pattern

---

## Section 8: DPO Pair Specification

Each DPO pair has three fields: `prompt`, `chosen`, `rejected`.

`prompt`: same as an SFT context (the HAR excerpt + instruction), WITHOUT the target.
Use one of the existing positive SFT examples as the prompt.

`chosen`: the correct target from that SFT example.

`rejected`: a corrupted version of chosen with EXACTLY ONE of these errors:

**Type R1** (35 pairs): `evidence_quote` does not appear in context.
Corrupt by: inventing a quote that sounds plausible but isn't in the context.
Example: context has `"fields: ['Account.Name']"` but rejected has `"evidence_quote": "fields: ['Account.Name', 'Account.AnnualRevenue']"` — the extra field isn't in the entry.

**Type R2** (20 pairs): `entry_id` is out of range.
Corrupt by: incrementing `entry_id` by 1 past the last entry in the example.
Example: context has entries [1], [2], [3] but rejected has `"entry_id": 4`.

**Type R3** (15 pairs): `pattern_id` is wrong.
Corrupt by: using a plausible-but-incorrect pattern ID for the signal.
Example: the signal is clearly 1.1 (ID in path) but rejected uses `"pattern_id": "1.3"` (bulk list).

**Type R4** (10 pairs): `attack_delta` references a path not in context.
Corrupt by: inventing an endpoint not present in the context.
Example: context has only `/api/v1/invoices/84721` but rejected attack_delta says "call GET /api/v1/invoices/84721/audit-log" (audit-log not in context).

For each DPO pair: the `chosen` must pass all Section 7 validation checks. The `rejected` must fail exactly one check (the one corresponding to its type).

---

## Section 9: Category Distribution Enforcement

Before writing examples, plan the distribution:

| Pattern | Positive single | Multi-finding | Noisy positive | Negative | Ambiguous |
|---|---|---|---|---|---|
| 1.1 | 15 | 3 | 4 | 3 | 2 |
| 1.2 | 15 | 2 | 3 | 2 | 2 |
| 1.3 | 15 | 3 | 4 | 3 | 2 |
| 1.4 | 15 | 2 | 2 | 2 | 1 |
| 1.5 | 15 | 2 | 3 | 2 | 2 |
| 1.6 | 15 | 3 | 3 | 3 | 2 |
| 1.7 | 15 | 2 | 2 | 2 | 1 |
| 1.8 | 15 | 2 | 3 | 2 | 2 |
| 1.9 | 15 | 2 | 2 | 2 | 1 |
| 1.10 | 15 | 2 | 2 | 2 | 1 |
| 1.11 | 15 | 1 | 2 | 3 | 4 |
| 1.12 | 15 | 3 | 3 | 3 | 2 |
| 10.1 | 15 | 2 | 3 | 2 | 2 |
| 10.2 | 15 | 2 | 3 | 2 | 2 |
| 10.3 | 15 | 2 | 2 | 2 | 1 |
| 10.4 | 15 | 2 | 2 | 2 | 2 |
| 10.5 | 15 | 2 | 2 | 2 | 1 |
| 10.6 | 15 | 2 | 2 | 2 | 1 |
| **Total** | **270** | **40** | **48** | **41** | **31** |

The eval split takes 80 examples (approximately 15% of each category). 
Ensure eval examples are as varied as train examples — do NOT put all 4-5 examples of the 
same pattern variation in eval.
