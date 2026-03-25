# Government Benefits Portal — REST API Reference (v2)

**Base URL:** `https://api.benefits.gov/v2`
**Auth:** All endpoints require `Authorization: Bearer <token>`
**Format:** REST only. JSON responses. No GraphQL.

---

## Claimant Profile

### GET /claimants/{claimantId}/profile

Returns the full profile of the specified claimant: name, national ID, address, contact, and benefit eligibility status.

**Path parameters:**
- `claimantId` (string): Unique identifier for the claimant (e.g. `clt-0042`).

**No documentation states that the server verifies the token holder is the claimant or an authorized caseworker for that claimant.**

**Response 200:**
```json
{
  "claimantId": "clt-0042",
  "name": "Jane Doe",
  "nationalId": "NID-9900-X",
  "address": "12 Elm St, Capital City",
  "eligibilityStatus": "ACTIVE"
}
```

---

## Payment Records

### GET /payments/{paymentId}

Returns a single payment record: amount, date, beneficiary claimant ID, and benefit program code.

**Path parameters:**
- `paymentId` (string): Unique payment identifier (e.g. `pay-8801`).

**No documentation states that the caller's token must belong to the beneficiary claimant.**

**Response 200:**
```json
{
  "paymentId": "pay-8801",
  "claimantId": "clt-0042",
  "amount": 450.00,
  "date": "2026-01-15",
  "program": "UNEMPLOYMENT"
}
```

---

## Payment History

### GET /claimants/{claimantId}/payments

Returns a list of all payments made to the specified claimant.

**Path parameters:**
- `claimantId` (string): The claimant whose payment history to return.

**No documentation states that the server checks whether the token holder is authorized to see this claimant's payment history.**

**Response 200:**
```json
[
  { "paymentId": "pay-8801", "amount": 450.00, "date": "2026-01-15" },
  { "paymentId": "pay-8802", "amount": 450.00, "date": "2026-02-15" }
]
```

---

## Appeals

### POST /appeals

Submit a new appeal. Request body must include `claimantId`, `reason`, and `details`.

**No documentation states that the server verifies the token holder is the claimant identified in `claimantId`.**

**Request body:**
```json
{
  "claimantId": "clt-0042",
  "reason": "ELIGIBILITY_DISPUTE",
  "details": "I believe my eligibility was incorrectly assessed."
}
```

**Response 201:**
```json
{ "appealId": "app-3301", "status": "SUBMITTED" }
```

---

## Appeal Status

### GET /appeals/{appealId}

Returns the current status and reviewer notes for an appeal.

**Path parameters:**
- `appealId` (string): Unique identifier of the appeal (e.g. `app-3301`).

**No documentation states that the caller must be the claimant who filed the appeal.**

**Response 200:**
```json
{
  "appealId": "app-3301",
  "claimantId": "clt-0042",
  "status": "UNDER_REVIEW",
  "reviewerNotes": "Awaiting additional documentation from claimant."
}
```

---

## Notes

- All endpoints require a valid Bearer token issued by the SSO gateway.
- The API is REST-only; there are no GraphQL operations.
- Object IDs (`claimantId`, `paymentId`, `appealId`) are UUIDs in production.
- Rate limit: 60 requests per minute per token.
