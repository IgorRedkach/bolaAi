## Findings

1. **SQL Injection via `filter_reference_id` enabling cross-tenant bulk data exfiltration** at `POST https://api.shopflow-b2b.com/api/v1/orders/batch-lookup`. The Order Status Service (Java/Spring Boot) concatenates the `filter_reference_id` request field directly into a SQL `WHERE` clause without parameterization. Injecting `' OR '1'='1' --` nullifies the mandatory `tenant_id` predicate, making the query return all rows across every tenant in the `customer_orders` table.

2. The HAR entry (startedDateTime `2026-04-09T17:15:33.411Z`) confirms successful exploitation: the attacker authenticating as `RETAIL_ATTACK_99X` (x-partner-id header, JWT prefix `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJQRVJfO`) received a 200 OK response containing `total_orders: 45180` and an 8.5 MB payload — orders belonging to `RETAIL_VICTIM_01` and `RETAIL_VICTIM_02` inclusive.

## Evidence

- **Malicious request payload** (from HAR `postData.text`):
  ```json
  {"order_ids": ["88192a-44f2-8921-b3c4"], "filter_reference_id": "' OR '1'='1' --"}
  ```
- **Vulnerable Java code** (`OrderLookupService`, section 6.0): `filterRefId` is appended via string concatenation — `whereClause.append(" AND o.partner_reference_id = '").append(filterRefId).append("'")` — while only `callingTenantId` and `orderIds` are bound via `PreparedStatement.setString()`. The injection rewrites the effective predicate to `WHERE o.tenant_id = 'RETAIL_ATTACK_99X' OR '1'='1'`, eliminating tenant isolation entirely.
- **Response confirms breach** (HAR `response.content.text`): the returned array contains orders with `tenant_id: "RETAIL_VICTIM_01"` and `tenant_id: "RETAIL_VICTIM_02"`, along with `shipping_address` (PII) and `last_four_card_digits` (PCI scope data).
- **Volume and performance artifact**: `total_orders: 45180`, `content.size: 8500000`, `x-db-query-time-ms: 390` — the elevated query time confirms a full-table scan on `customer_orders`, consistent with `OR '1'='1'` forcing PostgreSQL to evaluate every row.
- **Architectural debt note** (section 4.0): `RISK-ECOM-044` explicitly records that `partner_reference_id` was converted from an integer-only field to a free-form string without updating the prepared statement configuration — the direct root cause of this injection path.

## Reproduction

Step 1 — obtain a low-tier partner JWT for `RETAIL_ATTACK_99X` and issue the legitimate lookup to confirm baseline access:

```bash
curl -i -X POST "https://api.shopflow-b2b.com/api/v1/orders/batch-lookup" \
  -H "Authorization: Bearer <JWT_RETAIL_ATTACK_99X>" \
  -H "x-partner-id: RETAIL_ATTACK_99X" \
  -H "Content-Type: application/json" \
  -d '{"order_ids": ["88192a-44f2-8921-b3c4"], "filter_reference_id": "ERP-TRACKING-10045"}'
```

Expected secure outcome: response contains only orders owned by `RETAIL_ATTACK_99X`.

Step 2 — inject the SQL bypass via `filter_reference_id`:

```bash
curl -i -X POST "https://api.shopflow-b2b.com/api/v1/orders/batch-lookup" \
  -H "Authorization: Bearer <JWT_RETAIL_ATTACK_99X>" \
  -H "x-partner-id: RETAIL_ATTACK_99X" \
  -H "Content-Type: application/json" \
  -d '{"order_ids": ["88192a-44f2-8921-b3c4"], "filter_reference_id": "'\'' OR '\''1'\''='\''1'\'' --"}'
```

Expected vulnerable outcome: response returns `total_orders` in the tens of thousands, containing orders with `tenant_id` values other than `RETAIL_ATTACK_99X` (e.g., `RETAIL_VICTIM_01`, `RETAIL_VICTIM_02`), including `shipping_address` and `last_four_card_digits` fields belonging to foreign tenants.

## Remediation

- Replace the string-concatenation path in `OrderLookupService` with a parameterized bind for `partner_reference_id` — add it to the `parameters` list and bind it via `ps.setString()` before execution; remove `whereClause.append("'").append(filterRefId).append("'")`.
- Enforce input validation on `filter_reference_id` at the API Gateway layer (pattern-allowlist matching `RISK-ECOM-044` integer or ERP-ID format) as a defense-in-depth layer prior to the service call.
- Implement a mandatory row-level tenant filter applied after query construction that cannot be overridden by optional parameter injection — verify the effective SQL predicate always retains `AND o.tenant_id = ?` with a bound parameter even when supplemental filters are injected.
- Add audit logging for any response where `total_orders` exceeds a per-partner threshold (e.g., > 500) and alert on `x-db-query-time-ms` spikes that correlate with cross-tenant data volumes.
