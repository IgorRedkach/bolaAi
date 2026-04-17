# AI Teacher — Authorization Quality Patterns (Domain-General)

This document defines high-standard patterns for generating and validating authorization findings across regulated sectors.

## Scope

- Government service portals
- Healthcare and payer systems
- Financial and billing systems
- Utilities and transportation platforms
- Salesforce Experience Cloud / Aura platform APIs

## What a valid authorization finding must contain

1. Exact endpoint/object from source documentation.
2. Clear authorization gap — one of:
   - Field-level: caller-supplied field list not validated against user permission set.
   - Write escalation: user can set attributes outside their permission scope.
   - Object enumeration: ID swap exposes objects the caller does not own.
   - Cross-principal isolation: same endpoint serves different scope to different users/tenants.
3. Verification steps matched to the gap class (see verification patterns below).
4. Actionable expected outcomes (secure vs vulnerable behavior).

## What must NOT be labeled as BOLA or authorization gap

- Missing authentication alone (401-only outcomes with no valid session)
- Invalid-token behavior
- Pagination/filter concerns without object access abuse
- Rate-limiting concerns without authz gap

## Grounding requirements

- Do not invent endpoints not present in source docs/logs/schemas.
- If an endpoint is not in source, it must not appear in findings.
- GraphQL findings must reference real operation/field names from source.
- Salesforce/Aura findings must reference real `descriptor`, `recordId`, and `fields` values from the HAR.

## Verification gold patterns — choose by finding class

### Pattern A: Field-level authorization (SINGLE USER — most impactful, check first)

Used when an endpoint accepts a caller-supplied field list (Aura `getRecordWithFields`, GraphQL selections, OData `$select`, REST `?fields=`).

```
Step 1 — Baseline: reproduce the original successful request exactly.
Step 2 — Field injection: add field names the user's profile/role should NOT see
         (e.g. Account.SecuredEnvironment__c, Case.AccessRestrictions__c, custom restricted fields).
Step 3 — Observe the response.

Secure:   Server returns FIELD_ACCESS_EXCEPTION / omits restricted fields / returns error.
Vulnerable: Server returns values for the injected fields alongside normal fields.
```
Only ONE authenticated session needed. The question is whether THIS user can see fields their role/profile should not expose.

### Pattern B: Write escalation (SINGLE USER)

Used when a write endpoint may accept attributes the user's role should not be allowed to set.

```
Step 1 — Baseline write with permitted fields.
Step 2 — Add restricted attributes to the request body:
         ownership fields (ownerId, assignedTo), role/permission fields,
         status fields normally set only by workflow/admin.
Step 3 — Observe whether the write succeeds and whether the restricted field is persisted.

Secure:   Server rejects the request or silently ignores restricted attributes.
Vulnerable: Write succeeds; restricted field persisted with attacker-supplied value.
```
Only ONE authenticated session needed.

### Pattern C: Object enumeration / ID swap (SINGLE USER)

Used when an endpoint accepts an object ID in path, query, or body.

```
Step 1 — Record an ID for an object you own (baseline 200).
Step 2 — Replace with a plausible ID you do not own (adjacent integer, UUID guess, or known foreign ID).
Step 3 — Observe whether the server returns data or an authorization error.

Secure:   403 / 404 / empty result for the unowned ID.
Vulnerable: 200 with data for the unowned ID.
```
Only ONE authenticated session needed.

### Pattern D: Cross-principal isolation (TWO USERS — use ONLY when the above are insufficient)

Used when the finding is specifically about isolation between two different accounts, tenants, or roles.

```
Step 1 — Pick object owned by User A.
Step 2 — Request with Token A (baseline 200).
Step 3 — Request same object with Token B (different user/tenant).
Step 4 — Compare:
   A=200, B=403/404: likely secure.
   A=200, B=200 with protected data: cross-principal BOLA confirmed.
```

## Example mini-fixtures for teaching

### Salesforce / Aura field injection (Pattern A)

- `POST /css/s/sfsites/aura?aura.RecordUi.getRecordWithFields=1`
- Descriptor: `aura://RecordUiController/ACTION$getRecordWithFields`
- Attack: inject `Account.SecuredEnvironment__c`, `Account.AnnualRevenue__c` into the `fields` array.
- One portal session needed; no second user.

### Salesforce / Aura write escalation (Pattern B)

- `POST /css/s/sfsites/aura?aura.RecordUi.updateRecord=1`
- Attack: include `Case.AccessRestrictions__c` or `Case.InternalOnly__c` in the update body.
- One portal session needed; no second user.

### Transit cards — object enumeration (Pattern C)

- `GET /api/v2/cards/{cardId}/balance`
- Attack: enumerate adjacent card IDs with a single valid token.
- One token needed.

### Municipal permits — cross-tenant (Pattern D)

- `GET /api/v3/citizens/{citizenId}/permits/{permitId}`
- Attack: use Token B to access Token A's permit.
- Two tokens needed.

## Priority order for investigation

1. Field-level injection (Pattern A) — highest business impact, one token.
2. Write escalation (Pattern B) — high impact, one token.
3. Object enumeration (Pattern C) — classic BOLA, one token.
4. Cross-principal isolation (Pattern D) — traditional cross-tenant test, two tokens.

## Reviewer scoring rubric (0-5 each, must all be >=4)

- Grounding accuracy
- Authorization specificity (correct pattern chosen for the gap class)
- Verification validity (single vs dual token correctly matched)
- Auditor actionability
- Output consistency

Reject generated examples that use Pattern D (two-user) for findings that Pattern A, B, or C would prove with one token.
