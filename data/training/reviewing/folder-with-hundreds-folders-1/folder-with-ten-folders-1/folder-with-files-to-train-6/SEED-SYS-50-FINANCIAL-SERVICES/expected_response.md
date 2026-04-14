## System

- System: FinEdge Investment Portfolio API v4.0.1
- Domain: FINANCIAL SERVICES / WEALTH MANAGEMENT
- Risk ID: RISK-FIN-412

## Findings

### 1. GraphQL Resolver Traversal Injection (Pattern 5.2) + Nested BOLA Bypass (Pattern 1.7) — `recentTransactions(assetId:)` Argument in Asset Subgraph

The Asset Subgraph's `recentTransactions` resolver exposes an optional `assetId` argument on the `Asset` GraphQL type. This argument was intended for internal debugging use. The resolver executes a direct query:

```java
String query = "SELECT tx_id, amount, type, executed_date FROM transactions WHERE asset_id = ?";
List<Transaction> transactions = db.executeQuery(query, assetId);
```

There is no ownership verification — the code comment explicitly marks the missing check: `// FLAW: Missing BOLA check. The resolver should perform: if (!db.checkAssetOwnership(userId, assetId)) { throw new AccessDeniedException() }`. The resolver trusts that the Asset ID was pre-filtered by the Portfolio Subgraph (the architectural trust flaw, RISK-FIN-412).

**Traversal injection (Pattern 5.2)**: the attacker queries their own authorized root `me { portfolios { assets { ... } } }` to legitimately enter the GraphQL execution context, then injects `recentTransactions(assetId: "A-10001")` — an explicit argument overriding the parent Asset object's ID. The Asset Subgraph resolver processes `A-10001` directly without re-validating ownership against the JWT `user_id`.

**Nested BOLA (Pattern 1.7)**: the `recentTransactions` resolver inherits no authorization from its parent `Asset` context when an explicit argument is provided. Authorization exists at the root Portfolio level (the Portfolio Subgraph checks portfolio ownership) but is absent in the Asset Subgraph's child resolver.

**HAR evidence**: attacker JWT `sub: u-88192A` — owns portfolio `P-A-88192`. Injected `assetId: "A-10001"` (victim's asset, not in attacker's portfolio). Response HTTP 200 with transaction history: `[{"amount": 50000.00, "type": "BUY", "executedDate": "2026-04-01"}, {"amount": 12000.00, "type": "SELL", "executedDate": "2026-04-05"}]` — victim's financial transactions returned to attacker.

## Evidence

- **Section 6.1** (Java resolver): missing ownership check explicitly annotated in code — `if (!db.checkAssetOwnership(userId, assetId)) { throw new AccessDeniedException() }` absent.
- **Section 3.1** (architectural trust flaw): "The Asset Subgraph assumes any Asset ID it receives via a nested query is already authorized because it came from the trusted Portfolio Subgraph."
- **Section 4.0** (RISK-FIN-412): "Asset Subgraph lacks native ownership checks in its transaction resolver. We rely entirely on the Portfolio Subgraph to sanitize the input list."
- **HAR trace**: attacker's portfolio `P-A-88192`, injected victim's asset `A-10001`, response includes `amount: 50000.00` and `amount: 12000.00` trades.

## Reproduction

**Step 1 — Establish authorized baseline:**

```graphql
query {
  me {
    portfolios {
      id
      assets {
        recentTransactions {
          amount type executedDate
        }
      }
    }
  }
}
```

Expected: returns only `P-A-88192` with attacker's own asset transactions.

**Step 2 — Traversal injection (primary HAR attack):**

```graphql
query TraversalAttack {
  me {
    portfolios {
      id
      assets {
        recentTransactions(assetId: "A-10001") {
          amount
          type
          executedDate
        }
      }
    }
  }
}
```

Expected secure outcome: `AccessDeniedException` / 403 error — `A-10001` not in attacker's portfolio.  
Expected vulnerable outcome: HTTP 200 with victim's transaction history — `BUY $50,000` and `SELL $12,000`.

**Step 3 — Direct Asset Subgraph probe (verify child resolver has no independent auth):**

Send a query where the parent asset context belongs to the attacker but `assetId` argument is substituted with multiple victim IDs in sequence.

Expected secure outcome: ownership check at resolver rejects all IDs not owned by JWT `user_id`.  
Expected vulnerable outcome: all valid asset IDs return transaction data regardless of ownership.

## Remediation

- **Add ownership check to `recentTransactions` resolver** (RISK-FIN-412): verify `db.checkAssetOwnership(userId, resolvedAssetId)` before executing the transaction query — throw `AccessDeniedException` on mismatch.
- **Remove the explicit `assetId` argument from the public schema**: if the argument was for internal debugging only, remove it from the public GraphQL type definition or restrict it to internal callers via a directive.
- **Enforce "independent authorization" in the Asset Subgraph**: each subgraph resolver must validate the JWT `user_id` against the requested object via the `user_ownership` → `assets` join, not rely on upstream parent-resolver filtering.
- **Resolve RISK-FIN-412**: the architectural decision to rely solely on the Portfolio Subgraph for sanitization is documented as a known risk — this must be closed.
