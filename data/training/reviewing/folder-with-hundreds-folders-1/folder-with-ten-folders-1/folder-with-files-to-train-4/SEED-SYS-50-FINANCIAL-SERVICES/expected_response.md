## System

- System: FinFlow Corporate Payment Gateway v4.4.0
- Domain: FINANCIAL SERVICES / CORPORATE B2B PAYMENTS / WIRE TRANSFERS
- Risk ID: RISK-FIN-044

## Findings

### 1. Cross-Tenant BOLA on Payment Approval — Missing `tenant_id` Boundary Check (Pattern 1.5)

The approval endpoint `PATCH /api/v4/payments/{payment_id}/approve` in the Java Transaction Service fetches the target payment by `payment_id` alone:

```java
PaymentRecord targetPayment = db.findPaymentById(paymentId);
```

The code explicitly comments out the missing tenant boundary check:

```java
// VULNERABILITY 1.5: CROSS-TENANT BOLA FAILURE
// The code FAILS to enforce the boundary:
// if (!targetPayment.getTenantId().equals(callingTenantId)) { throw 403 }
```

The `corporate_payments` table contains `tenant_id` as the critical isolation field. `callingTenantId` is extracted from the JWT (`userContext.getTenantId()`), but is never compared against `targetPayment.getTenantId()`. Any authenticated user from any tenant can approve any payment in the entire ledger by substituting the target `payment_id` in the URL.

**HAR evidence**: attacker `usr_corp_a` (JWT: `tenant_id: "CORP_A"`, `role: "PAYMENT_SIGNATORY"`) sends `PATCH /api/v4/payments/PID-99201/approve` with empty body (`bodySize: 0`). Response: HTTP 200 OK, `{"status": "APPROVED", "payment_id": "PID-99201"}`. `PID-99201` belongs to CORP_B — the $50,000,000 wire transfer is now `APPROVED` by a CORP_A employee.

### 2. Workflow Decoupling — SOX Two-Signatory Requirement Bypassed (Pattern 3.2)

The system specification (section 3.2) requires two distinct `PAYMENT_SIGNATORY` users from the **same corporation** to approve a payment before it is dispatched. The approval controller applies a single-user state transition:

```java
db.updatePaymentStatus(paymentId, "APPROVED", callingUserId);
```

There is no check for a prior `approved_by_1` from the same tenant. A single `PATCH` call transitions `PID-99201` from `PENDING_APPROVAL` directly to `APPROVED`. The HAR response time of 78 ms confirms no secondary authorization signal is awaited. The `approved_by_1` column in the schema would normally record the first signatory — it is never validated before the second approval. CORP_A's `usr_corp_a` acts as the sole approver for a CORP_B payment, satisfying neither the tenant boundary nor the two-signatory requirement simultaneously.

## Evidence

- **HAR trace**: CORP_A JWT approved CORP_B payment `PID-99201` — 200 OK with `"status": "APPROVED"` returned.
- **Java controller** (section 6.1): `db.findPaymentById(paymentId)` without tenant filter; commented-out check explicitly marks the gap. `db.updatePaymentStatus()` without prior signatory count validation.
- **Schema** (section 5.0): `tenant_id` is a `NOT NULL` foreign key — the isolation contract is in the database schema but enforced nowhere in the application write path.
- **Architecture** (section 3.2): requires two-step approval by two users from the same corporation before SWIFT dispatch.
- **System debt note** (section 4.0, RISK-FIN-044): fast-track endpoint "skipped some internal audit checks, assuming the API Gateway upstream was enforcing all BOLA/BAC rules" — the upstream does not.

## Reproduction

```http
PATCH /api/v4/payments/PID-99201/approve HTTP/2.0
Host: api.finflow.com
Authorization: Bearer <JWT_tenant_id=CORP_A, sub=usr_corp_a, role=PAYMENT_SIGNATORY>
Content-Type: application/json
```

No body required. `PID-99201` must exist in the ledger as `PENDING_APPROVAL` and belong to a different tenant (`CORP_B`).

Expected secure outcome: HTTP 403 — tenant mismatch detected, request denied.  
Observed vulnerable outcome: HTTP 200 — `{"status": "APPROVED", "payment_id": "PID-99201"}`, CORP_B's $50M wire queued for SWIFT dispatch.

## Remediation

- **Fix the BOLA check (RISK-FIN-044)**: after `db.findPaymentById(paymentId)`, add: `if (!targetPayment.getTenantId().equals(callingTenantId)) { return ResponseEntity.status(403).body("Forbidden"); }`.
- **Enforce two-signatory workflow**: count distinct signatories with matching `tenant_id` before setting `APPROVED`; require at least two unique users with `PAYMENT_SIGNATORY` role from the same tenant before state advance.
- **Parameterize the approval query with tenant filter**: replace `findPaymentById(paymentId)` with `findPaymentByIdAndTenantId(paymentId, callingTenantId)` — return 404 on mismatch so payment IDs of other tenants are not distinguishable.
- **Add integration tests**: test that CORP_A JWT cannot approve CORP_B payment IDs — both for 403 response and for no DB state change.
