# AI Teacher — BOLA Quality Patterns (Domain-General)

This document defines high-standard patterns for generating and validating BOLA findings across regulated sectors.

## Scope

- Government service portals
- Healthcare and payer systems
- Financial and billing systems
- Utilities and transportation platforms

## What a valid BOLA finding must contain

1. Exact endpoint/object from source documentation.
2. Clear object-level authorization gap (owner/tenant/linked-resource check missing).
3. Two-valid-user verification logic on the same object ID.
4. Actionable expected outcomes (secure vs vulnerable behavior).

## What must NOT be labeled as BOLA

- Missing authentication alone (401-only outcomes)
- Invalid-token behavior
- Pagination/filter concerns without object access abuse
- Rate-limiting concerns without object authz gap

## Grounding requirements

- Do not invent endpoints not present in source docs/logs/schemas.
- If an endpoint is not in source, it must not appear in findings.
- GraphQL findings must reference real operation/field names from source.
- Salesforce/SOQL findings must reference record-level controls actually discussed.

## Verification gold pattern

For each finding:

1. Pick object owned by User A (existing object).
2. Request with Token A.
3. Request same object with Token B.
4. Compare results:
   - A=200, B=403/404 (with hidden existence policy): likely secure behavior.
   - A=200, B=200 with protected data: likely BOLA.
   - A denied: do not claim BOLA; verify setup/object existence first.

## Example mini-fixtures for teaching

### Transit cards

- `GET /api/v2/cards/{cardId}/balance`
- `GET /api/v2/cards/{cardId}/trips/{tripId}`
- `POST /api/v2/cards/{cardId}/refunds`

Risk theme: ownership checks on card and trip linkage.

### Municipal permits

- `GET /api/v3/citizens/{citizenId}/permits/{permitId}`
- `PATCH /api/v3/citizens/{citizenId}/permits/{permitId}/status`
- `POST /api/v3/review-queue/reassign`

Risk theme: write actions using foreign IDs from request body.

### Agency operations

- `PATCH /api/v2/agencies/{agencyId}/operators/{operatorId}/roles`
- `GET /api/v2/agencies/{agencyId}/fraud-events/{eventId}`

Risk theme: tenant-boundary and admin-scope enforcement.

## Reviewer scoring rubric (0-5 each, must all be >=4)

- Grounding accuracy
- BOLA specificity
- Verification validity
- Auditor actionability
- Output consistency

Reject generated examples that fail any category.
