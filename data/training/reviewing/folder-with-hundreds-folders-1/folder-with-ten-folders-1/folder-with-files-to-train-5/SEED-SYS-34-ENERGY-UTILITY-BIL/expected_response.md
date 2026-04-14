## System

- System: PowerGrid Customer Billing GraphQL API v4.0.0
- Domain: ENERGY / UTILITIES / CUSTOMER BILLING
- Risk ID: RISK-GRPH-501

## Findings

### 1. Authorization-Bypass SQL Injection via GraphQL `filter` Argument — Cross-Tenant Invoice Exfiltration (Pattern 5.1 + Pattern 9.1)

The Python Django resolver (`billingResolvers.py`, section 6.1) constructs the SQL `WHERE` clause using direct string interpolation of the client-supplied `filter` argument:

```python
base_query = "SELECT * FROM invoices WHERE tenant_id = '%s'" % tenant_id
if filter:
    # VULNERABILITY 5.1 & 9.1: Authorization Bypass Injection
    base_query += " AND (%s)" % filter
invoices = db.execute(base_query)
```

The intended query form is: `WHERE tenant_id = 'TENANT_A' AND (<client_filter>)`. By injecting `billing_period < '2026-04-01' OR tenant_id IS NOT NULL` as the `filter` value, the attacker constructs:

```sql
SELECT * FROM invoices WHERE tenant_id = 'TENANT_A' AND (billing_period < '2026-04-01' OR tenant_id IS NOT NULL)
```

The `OR tenant_id IS NOT NULL` predicate is always true (all rows have a `tenant_id`), so the outer `AND` clause evaluates to `true` for every row regardless of `tenant_id`. The tenant isolation check `WHERE tenant_id = 'TENANT_A'` is logically nullified. All 4,122 invoices across all tenants are returned.

**HAR evidence**: POST `https://api.powergrid.com/graphql` with TENANT_A JWT. `filter` argument: `"billing_period < '2026-04-01' OR tenant_id IS NOT NULL"`. Response: HTTP 200 OK, response header `x-records-returned: 4122`. Response body includes invoices for `TENANT_A` (1,250 kWh, $150.00), `COMPETITOR_CORP_Z` (55,000 kWh, $6,120.00), and `TENANT_MUNICIPAL_X` (190,000 kWh, $21,000.00) — confirmed cross-tenant billing data.

## Evidence

- **HAR trace**: TENANT_A JWT → `filter: "... OR tenant_id IS NOT NULL"` → HTTP 200 OK → `x-records-returned: 4122` → records for `COMPETITOR_CORP_Z` and `TENANT_MUNICIPAL_X` in response body.
- **Python resolver** (section 6.1): `base_query += " AND (%s)" % filter` — direct string interpolation, no parameterized query, no input validation.
- **Schema** (section 5.0): `tenant_id NOT NULL` — isolation field; `invoices` is a single shared table for all tenants.
- **Architecture** (sections 2.2 + 4.0, RISK-GRPH-501): string interpolation used to avoid rewriting the query layer; BOLA predicate assumed safe but overridable.

## Reproduction

```http
POST /graphql HTTP/2.0
Host: api.powergrid.com
Authorization: Bearer <TENANT_A_JWT>
Content-Type: application/json

{"query": "query MassInvoiceLeak { invoices(filter: \"billing_period < '2026-04-01' OR tenant_id IS NOT NULL\") { invoiceId tenantId consumptionKwh totalAmount } }"}
```

Expected secure outcome: GraphQL error — invalid filter syntax or parameterized query rejects the injection; only TENANT_A records returned.  
Observed vulnerable outcome: HTTP 200 OK, `x-records-returned: 4122`, records for `COMPETITOR_CORP_Z` and `TENANT_MUNICIPAL_X` included in response.

## Remediation

- **Replace string interpolation with parameterized queries** (RISK-GRPH-501): the `filter` argument must never be used as raw SQL. Use an ORM filter object or a safe filter DSL (e.g., `invoices.filter(billing_period__lt=date)`) — never `"AND (%s)" % filter`.
- **Use a structured filter input type instead of a raw string**: replace `filter: String` with a typed GraphQL input object (`filter: InvoiceFilterInput { billingPeriodBefore: Date }`) — the resolver maps explicit fields to parameterized query conditions and has no free-form SQL surface.
- **Always enforce the `tenant_id` predicate in the ORM layer, not in a constructed string**: use `Invoices.objects.filter(tenant_id=tenant_id).filter(<safe_filter>)` — the ORM chains filters with AND and the tenant check cannot be overridden by user input.
- **Validate and restrict accepted filter fields**: if raw filter expressions must be supported, maintain an allowlist of permitted field names and operators — reject any input containing SQL keywords (`OR`, `IS`, `NULL`, `--`, `'`, etc.).
