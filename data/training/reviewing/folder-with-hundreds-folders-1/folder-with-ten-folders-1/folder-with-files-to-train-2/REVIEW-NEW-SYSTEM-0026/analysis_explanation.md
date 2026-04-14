## Analysis reasoning

I reviewed the AML Sentinel Transaction Review Gateway specification (v7.0.2) and the accompanying HAR trace as engineering artifacts, not as pre-labeled vulnerability text.

1. **Role and permission boundary extraction**: from section 3.1 I established the authorised action scope per role — `COMPLIANCE_OFFICER` is limited to `POST /transactions/{id}/flag`, while `POST /transactions/{id}/approve` requires `AML_ADMIN`. Any successful `APPROVE` action by a `COMPLIANCE_OFFICER` is by definition a privilege escalation.

2. **Code-level RBAC flaw identification**: section 6.0 (`TransactionController.approveTransaction()`) contains the guard `if ("TIER_1_SUPPORT".equals(userRole)) { return 403; }`. This is a denylist of one role, not an allowlist of the required role. A `COMPLIANCE_OFFICER` passes this guard unconditionally, establishing the functional pivot (Pattern 2.1).

3. **Concurrency gap analysis**: section 4.0 (RISK-AML-019) records that the Kafka-based asynchronous freezing was introduced without a row-level database lock. Section 6.0 confirms that `transactionRepo.findById()` is used without `@Lock(PESSIMISTIC_WRITE)` or serializable isolation, creating the time-of-check vs time-of-use window (Pattern 8.1).

4. **HAR timing analysis for TOCTOU proof**: Thread A (freeze) starts at `2026-04-09T11:05:00.010Z` with a 250 ms duration, meaning it commits at approximately `0.260Z`. Thread B (approve by `user_comp_991X`) starts at `0.012Z` with 125 ms latency, committing at approximately `0.137Z`. Thread B completes before Thread A — the 2 ms offset at start combined with the lower approval latency means the `IS_FROZEN` read in Thread B returned `FALSE` while Thread A's write was still pending.

5. **State corruption confirmation**: the final audit DB trace at `0.300Z` returns `status: APPROVED`, `is_frozen: false`. This combination is explicitly impossible under valid state machine rules (section 3.2 mandates that `FLAGGED` → `FREEZE` must precede any `APPROVE`). The corrupted state confirms Pattern 8.5.

6. **Settlement event consequence**: the 200 OK response body `{"settlement_event": true}` confirms that the `eventBus.publish(new TransactionApprovedEvent("TX-991A"))` was triggered, meaning the $500,000 wire transfer entered the settlement pipeline with no regulatory hold — a direct BSA violation.

7. **Reproduction path**: structured in two steps — first a pure role boundary test (no race required) to prove the functional pivot independently, then a concurrent race test to demonstrate the TOCTOU window using only endpoint URLs, identities, and transaction IDs observed in the context.
