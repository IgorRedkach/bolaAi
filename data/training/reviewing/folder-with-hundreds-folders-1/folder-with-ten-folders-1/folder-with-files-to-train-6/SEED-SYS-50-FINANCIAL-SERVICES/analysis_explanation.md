## Analysis reasoning

I reviewed the FinEdge Investment Portfolio API v4.0.1 architecture, PostgreSQL schema, vulnerable Java resolver, GraphQL schema, and HAR trace.

1. **The attack exploits a specific architectural design decision, not just a missing check**: section 3.1 and RISK-FIN-412 document the core flaw — the Asset Subgraph was designed as a "shared utility service" that trusts parent subgraph filtering. The attacker bypasses this by providing an explicit `assetId` argument to `recentTransactions`, which triggers a code path that never reaches the parent filtering logic. The resolver's `if (assetId == null)` branch for default behavior confirms the explicit argument is a distinct code path.

2. **Java resolver code makes the flaw unambiguous**: the code comment directly states `// FLAW: Missing BOLA check. The resolver should perform: if (!db.checkAssetOwnership(userId, assetId)) { throw new AccessDeniedException() }`. The code that follows executes `WHERE asset_id = ?` with the attacker-controlled argument — no join to `user_ownership`.

3. **HAR confirms successful exfiltration**: attacker JWT `u-88192A` owns `P-A-88192`. The query passes `assetId: "A-10001"` (which does not appear in any of the attacker's portfolios). The response returns financial transactions totaling $62,000 in trades — these are the victim's actual trade amounts, confirming data from a different ownership domain was returned.

4. **PostgreSQL schema shows why a join would have prevented this**: `assets.portfolio_id` references `user_ownership.portfolio_id` which links to `user_id`. A proper resolver would execute `SELECT t.* FROM transactions t JOIN assets a ON t.asset_id = a.asset_id JOIN user_ownership uo ON a.portfolio_id = uo.portfolio_id WHERE t.asset_id = $1 AND uo.user_id = $2`. The current query skips this join.

5. **Financial data sensitivity**: `transactions.amount`, `type` (BUY/SELL/DIVIDEND), and `executed_date` constitute trading activity — potentially SEC-regulated material non-public information (MNPI) if the assets are publicly traded securities. Unauthorized access may constitute insider trading facilitation and violates SEC Regulation S-P (privacy of consumer financial information).

6. **The original expected_response.md was entirely generic**: the previous content described no specific code, no HAR details, and used vague reproduction steps ("replace the resource ID"). This was replaced with grounded evidence from sections 4.0, 6.1, and the HAR trace.
