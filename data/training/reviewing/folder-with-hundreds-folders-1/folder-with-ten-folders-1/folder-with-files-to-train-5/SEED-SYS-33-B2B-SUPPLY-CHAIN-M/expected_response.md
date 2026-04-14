## System

- System: SupplyChain Partner GraphQL Portal v4.1.0
- Domain: B2B / SUPPLY CHAIN MANAGEMENT / PARTNER INTEGRATION
- Risk ID: RISK-GRPH-905

## Findings

### 1. GraphQL Introspection Enabled in Production — Schema Over-Exposure (Pattern 6.1)

The GraphQL-Ruby server is misconfigured to allow introspection queries in the production environment (section 2.1, RISK-GRPH-905). The standard `{ __schema { types { name fields { name } } } }` query returns the full type system, including all fields on the `Order` type. The `internal_audit_notes` field is visible in the introspection response because it is defined in the `Types::OrderType` schema (section 6.1). This field was manually excluded from the REST API documentation but the GraphQL schema was not audited after the transition. An authenticated external partner can discover `internalAuditNotes` by running an introspection query — no prior knowledge required.

### 2. Missing Field-Level Authorization — `internalAuditNotes` Returned to External Partners (Pattern 9.1)

The `Order.internalAuditNotes` field resolver in the Ruby GraphQL type definition (section 6.1) has no authorization guard:

```ruby
# VULNERABILITY 6.1: This field is defined in the schema (revealed via Introspection)
# but has no authorization guard on its resolution.
field :internal_audit_notes, String, null: true
# There is NO method called 'authorized?' or 'can_read_notes?' applied here.
def internal_audit_notes
    object.internal_audit_notes
end
```

The parent `order` resolver performs a BOLA check (section 3.2) — the order must belong to the requesting partner. Once the parent object is authorized, the nested `internalAuditNotes` resolver simply returns `object.internal_audit_notes` from the ActiveRecord model without checking if the caller's role is `AUDITOR`. The database schema stores `internal_audit_notes` in the same `orders` table as the public fields (section 5.0), so a `SELECT *` / ActiveRecord object load returns the sensitive column along with all others.

**HAR evidence**: POST `https://api.supplychain-portal.com/graphql` with `PARTNER_JWT_88192A`. Query includes `internalAuditNotes` on `order(id: "ORD-99182A")`. Response: HTTP 200 OK, `"internalAuditNotes": "Order flagged for potential fraud. High risk of chargeback (92%). Ship only to verified billing address. DO NOT offer rush shipping."` — internal fraud flag, chargeback risk score, and operational instructions returned to the external partner whose order has been flagged.

## Evidence

- **HAR trace**: partner JWT queries `internalAuditNotes` on own order `ORD-99182A`; HTTP 200 OK; internal fraud notes and 92% chargeback risk score returned.
- **Ruby type definition** (section 6.1): `field :internal_audit_notes` with no `authorized?` guard; resolver returns `object.internal_audit_notes` unconditionally.
- **Schema** (section 5.0): `internal_audit_notes TEXT` comment states "SENSITIVE: ONLY FOR INTERNAL AUDITORS" but no DB-level restriction.
- **Architecture** (section 3.2, RISK-GRPH-905): "introspection was enabled in the production environment during a debugging sprint and was never disabled" — enabling partner discovery of the internal field name.

## Reproduction

**Step 1 — Discover the field via introspection:**

```http
POST /graphql HTTP/2.0
Host: api.supplychain-portal.com
Authorization: Bearer <PARTNER_JWT>
Content-Type: application/json

{"query": "query Introspection { __schema { types { name fields { name } } } }"}
```

Response includes `Order.internalAuditNotes` in the type list.

**Step 2 — Fetch the internal field:**

```http
POST /graphql HTTP/2.0
Host: api.supplychain-portal.com
Authorization: Bearer <PARTNER_JWT>
Content-Type: application/json

{"query": "query AuditNoteLeak { order(id: \"ORD-99182A\") { orderId orderStatus internalAuditNotes } }"}
```

Expected secure outcome: HTTP 200 with `"internalAuditNotes": null` or a GraphQL error — field access denied for non-AUDITOR roles.  
Observed vulnerable outcome: HTTP 200, `"internalAuditNotes": "Order flagged for potential fraud. High risk of chargeback (92%)..."`.

## Remediation

- **Disable introspection in production** (RISK-GRPH-905): configure GraphQL-Ruby with `introspection: false` for production environments — partners cannot query undocumented fields they cannot discover.
- **Add role-level field authorization on `internalAuditNotes`**: in the `OrderType` definition, add a guard method: `def self.authorized?(object, context) = context[:current_role] == 'AUDITOR'`. GraphQL-Ruby will return `null` or raise an error for unauthorized roles.
- **Move `internal_audit_notes` to a separate `InternalOrderAudit` table**: separating internal and external data at the schema level prevents accidental exposure regardless of resolver guards.
- **Audit all GraphQL fields against the REST API documentation allowlist**: any field not in the partner-facing REST documentation must have an explicit role guard before the GraphQL type is published.
