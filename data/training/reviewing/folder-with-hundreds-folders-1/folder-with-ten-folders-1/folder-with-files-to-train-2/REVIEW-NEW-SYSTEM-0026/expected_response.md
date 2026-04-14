## Findings

1. **Functional Pivot (weak RBAC) on `POST /api/v3/transactions/{id}/approve`**: the `approveTransaction` controller checks `IF role != TIER_1_SUPPORT` instead of `IF role == AML_ADMIN`, which allows a `COMPLIANCE_OFFICER` to invoke the high-privilege approve action. According to the RBAC table (section 3.1), approve/unfreeze is exclusively an `AML_ADMIN` operation; `COMPLIANCE_OFFICER` is only authorised for `POST /transactions/{id}/flag`.

2. **TOCTOU race condition (Pattern 8.1) enabling state corruption**: the approve endpoint reads `IS_FROZEN` without a `SELECT FOR UPDATE` row lock. Because the AML Risk Engine's freeze command is dispatched asynchronously via Kafka (RISK-AML-019), there is a sub-millisecond window between Thread A writing `is_frozen = TRUE` and Thread B reading the unfrozen state. The HAR trace proves `user_comp_991X` exploited this window: Thread B (`startedDateTime: 2026-04-09T11:05:00.012Z`, elapsed 125 ms) committed `STATUS: APPROVED` before Thread A (`startedDateTime: 2026-04-09T11:05:00.010Z`, elapsed 250 ms) could finalise the freeze. The resulting database state (`status: APPROVED`, `is_frozen: false`) is invalid by business rules and cannot be reversed.

## Evidence

- **HAR Thread B request** — `POST https://api.aml-sentinel.bank/api/v3/transactions/TX-991A/approve`, bearer token encodes `user_id: user_comp_991X`, `role: COMPLIANCE_OFFICER`; `x-compliance-override: false`; empty JSON body `{}`.
- **HAR Thread B response** — HTTP 200 OK, body `{"status": "APPROVED", "txId": "TX-991A", "settlement_event": true}` confirming the approval succeeded and a settlement event was published.
- **HAR timing** — Thread A freeze starts at `...0.010Z` (250 ms), Thread B approval starts at `...0.012Z` (125 ms). Thread B completes first (≈0.137Z) while Thread A's DB write lands at ≈0.260Z. The 2 ms offset and lower latency of Thread B prove it read `is_frozen: FALSE` before Thread A committed.
- **HAR final audit trace** — `SELECT status, is_frozen FROM core_transactions WHERE transaction_id = 'TX-991A'` returns `{status: "APPROVED", is_frozen: false}` at `2026-04-09T11:05:00.300Z`. This is an impossible state under valid business logic (any approved high-risk transaction must have passed through `is_frozen: TRUE`).
- **Flawed controller code** (section 6.0): the role guard is `if ("TIER_1_SUPPORT".equals(userRole)) { return 403; }` — COMPLIANCE_OFFICER passes this check. The frozen check `if (record.isFrozen())` uses a non-locking read (`transactionRepo.findById()` without `@Lock(PESSIMISTIC_WRITE)`), making it vulnerable to the concurrent freeze not yet being committed.

## Reproduction

Step 1 — confirm that `COMPLIANCE_OFFICER` can reach the approve endpoint (baseline role boundary test):

```bash
curl -i -X POST "https://api.aml-sentinel.bank/api/v3/transactions/TX-991A/approve" \
  -H "Authorization: Bearer <JWT_user_comp_991X_COMPLIANCE_OFFICER>" \
  -H "x-compliance-override: false" \
  -H "Content-Type: application/json" \
  -d '{}'
```

Expected secure outcome: HTTP 403 — role is not `AML_ADMIN`.  
Observed vulnerable outcome: HTTP 200 `{"status": "APPROVED", "txId": "TX-991A", "settlement_event": true}`.

Step 2 — reproduce the TOCTOU window (send the approval request within milliseconds of a high-risk transaction being flagged, before the async Kafka freeze message is consumed):

```bash
# Fire both requests near-simultaneously to race Thread A (freeze) with Thread B (approve)
curl -i -X POST "https://api.aml-sentinel.bank/api/v3/transactions/TX-991A/freeze" \
  -H "Authorization: Bearer <INTERNAL_AML_ENGINE_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"reason": "AML_RISK_SCORE_EXCEEDED_9.0"}' &

curl -i -X POST "https://api.aml-sentinel.bank/api/v3/transactions/TX-991A/approve" \
  -H "Authorization: Bearer <JWT_user_comp_991X_COMPLIANCE_OFFICER>" \
  -H "x-compliance-override: false" \
  -H "Content-Type: application/json" \
  -d '{}'
```

Expected secure outcome: approve returns 403 (frozen) or 409 (already in freeze workflow).  
Expected corrupt outcome: approve returns 200 and subsequent `SELECT status, is_frozen FROM core_transactions WHERE transaction_id = 'TX-991A'` returns `status: APPROVED`, `is_frozen: false`.

## Remediation

- **Fix the RBAC check immediately**: replace `if ("TIER_1_SUPPORT".equals(userRole))` with `if (!"AML_ADMIN".equals(userRole))` in `TransactionController.approveTransaction()` — this closes the functional pivot regardless of the race condition.
- **Introduce a pessimistic row lock**: change the repository call to `transactionRepo.findByIdWithLock(txId)` using JPA `@Lock(LockModeType.PESSIMISTIC_WRITE)`, so the `IS_FROZEN` read and the `STATUS: APPROVED` write are serialised against the concurrent freeze update.
- **Use serializable transaction isolation** for all state-changing operations on `core_transactions` where a frozen check must be atomic with the subsequent write.
- **Resolve RISK-AML-019**: the Kafka-based async freeze was introduced without a compensating database lock — document and require that any async state transition provides an idempotency guard that rejects updates when the row has already transitioned to a terminal state (`APPROVED` or `REJECTED`).
- **Add an audit alert** for any `status: APPROVED` record where `is_frozen: false` exists and the approving `user_id` holds role `COMPLIANCE_OFFICER` — flag for immediate regulatory review under BSA obligations.
