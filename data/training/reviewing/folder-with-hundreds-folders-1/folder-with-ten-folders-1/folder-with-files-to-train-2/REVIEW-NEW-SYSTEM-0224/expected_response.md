## Findings

1. **TOCTOU race condition enabling double-spend on `POST /api/v1/orders/submit` (RISK-FIN-009)**: the `submitOrder` controller reads `shares_owned` from `asset_inventory` without a row-level lock (`SELECT ... FOR UPDATE` was removed per PR-HFT-404). During the 50–100 ms handoff to the matching engine (`executionEngine.submitOrder()`), the `asset_inventory` row is not locked. Two concurrent requests from the same account (`acc_88192A`) with identical payloads both read `shares_owned = 1000`, both pass the `currentShares >= amount` check, and both proceed to execution — resulting in 2,000 shares sold against an actual holding of 1,000 shares.

2. **Both orders confirmed executed**: the HAR captures two distinct 200 OK responses with unique order IDs (`ord_991A_1111` and `ord_991A_2222`), each confirming `"executed_shares": 1000.00`. Both were submitted within 3 ms of each other (`10:42:56.001Z` and `10:42:56.004Z`) — within the execution engine's latency window — proving the second thread read the unfrozen balance before the first thread's `UPDATE asset_inventory SET shares_owned = shares_owned - ?` was committed.

## Evidence

- **HAR Thread A** (`startedDateTime: 2026-04-09T10:42:56.001Z`, elapsed 75 ms): `POST https://api.quantex-hft.finance/api/v1/orders/submit`; `x-quantex-client-id: algo-trader-991A`; body `{"ticker": "TSLA", "order_type": "MARKET_SELL", "amount": 1000.00, "account_id": "acc_88192A"}`; response HTTP 200, `order_id: ord_991A_1111`, `executed_price: 185.45`.
- **HAR Thread B** (`startedDateTime: 2026-04-09T10:42:56.004Z`, elapsed 82 ms): identical request body and headers; response HTTP 200, `order_id: ord_991A_2222`, `executed_price: 185.46`. The 3 ms start-time offset combined with the 50–100 ms execution-engine latency confirms Thread B's ToC occurred before Thread A's ToU (inventory deduction).
- **Flawed controller** (section 6.0): `SELECT shares_owned FROM asset_inventory WHERE account_id = ? AND ticker = ?` — plain read, no `FOR UPDATE`. The `@Transactional` annotation provides ACID isolation for the enclosing transaction's own writes but does not prevent a concurrent transaction from reading the same row before the first transaction commits its deduction.
- **Consequence**: `asset_inventory` for `acc_88192A` / `TSLA` ends at `shares_owned = -1000` after both `UPDATE` statements execute sequentially. The brokerage executed a 1,000-share naked short sale, creating a covering obligation at market price — a direct financial loss and an SEC/FINRA compliance violation.

## Reproduction

Submit two identical SELL orders concurrently (within the matching engine's 50–100 ms window):

```bash
curl -i -X POST "https://api.quantex-hft.finance/api/v1/orders/submit" \
  -H "Authorization: Bearer <JWT_acc_88192A>" \
  -H "Content-Type: application/json" \
  -H "x-quantex-client-id: algo-trader-991A" \
  -d '{"ticker": "TSLA", "order_type": "MARKET_SELL", "amount": 1000.00, "account_id": "acc_88192A"}' &

curl -i -X POST "https://api.quantex-hft.finance/api/v1/orders/submit" \
  -H "Authorization: Bearer <JWT_acc_88192A>" \
  -H "Content-Type: application/json" \
  -H "x-quantex-client-id: algo-trader-991A" \
  -d '{"ticker": "TSLA", "order_type": "MARKET_SELL", "amount": 1000.00, "account_id": "acc_88192A"}'
```

Expected secure outcome: one request returns HTTP 200 `ORDER_EXECUTED`; the concurrent request returns HTTP 400 `Insufficient shares for sale` (or 409 Conflict) after the first thread's deduction is committed.  
Observed vulnerable outcome: both requests return HTTP 200 with distinct `order_id` values (`ord_991A_1111` and `ord_991A_2222`), each reporting `executed_shares: 1000.00` — 2,000 shares sold from a 1,000-share holding.

## Remediation

- **Re-introduce the row-level lock (restore RISK-FIN-009 mitigation)**: change the inventory query to `SELECT shares_owned FROM asset_inventory WHERE account_id = ? AND ticker = ? FOR UPDATE`. This serialises concurrent sell orders for the same account/ticker, ensuring only one thread reads and decrements the balance at a time.
- **Use an atomic `UPDATE ... WHERE shares_owned >= amount RETURNING shares_owned`**: replace the two-step read-then-update with a single atomic `UPDATE asset_inventory SET shares_owned = shares_owned - ? WHERE account_id = ? AND ticker = ? AND shares_owned >= ? RETURNING shares_owned` — if the UPDATE affects 0 rows, the sale is rejected. This eliminates the TOCTOU window entirely.
- **Add a per-account concurrent order lock at the application layer**: use a distributed lock (e.g., Redis `SET NX EX`) keyed on `account_id:ticker` to serialise concurrent submissions for the same instrument from the same account, as a defense-in-depth layer before hitting the database.
- **Restore PR-HFT-404 decision review**: RISK-FIN-009 was accepted without a concrete mitigation. The `SELECT FOR UPDATE` removal must be reversed or replaced by the atomic UPDATE pattern before the next peak-volume event.
