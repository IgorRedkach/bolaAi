## Analysis reasoning

I reviewed the NexaBank Open Finance API v5.8.9 architecture specification, GraphQL schema, and HAR trace.

1. **HAR shows bulk lookup as the primary attack**: the request `postData` contains `bulkAccountLookup(ids: ["A-2002", "A-1002", "A-3002"])` — a mutation with three account IDs. This maps directly to the documented section 4.0 gap: "bulkAccountLookup accepts an arbitrary array of IDs without per-ID ownership filtering." The attack is cross-tenant: `tenant-4af9` JWT submitting IDs including `A-2002` (which belongs to `tenant-125d` per the response).

2. **Response tenant mismatch is the primary signal**: the response contains `"tenantId": "tenant-125d"` while the JWT carries `x-tenant-id: tenant-4af9`. This is a direct cross-tenant data access confirmation. The response also includes `sensitiveField` and `internalNotes` — financial PII from a different tenant's account.

3. **RISK-GQL-002 documents the single-ID path**: in addition to the bulk gap, section 4.0 (RISK-GQL-002) explicitly states the `getAccount` resolver does not check `tenantId` against the JWT. This means both single-ID (`getAccount`) and bulk (`bulkAccountLookup`) paths are vulnerable — the bulk path is just more efficient for an attacker.

4. **Redis cache keyed by `accountId` only**: the cache design in section 2.0 means tenant boundaries could be crossed via cache poisoning — if an account from `tenant-125d` was recently fetched (perhaps legitimately by a `tenant-125d` user), subsequent requests from `tenant-4af9` for the same `accountId` would receive the cached entry. This is a secondary risk that compounds the resolver-level BOLA.

5. **Financial/banking context**: account records contain financial transaction history (`transactions: [Transaction!]`), `sensitiveField` (likely account balance or credit details), and `internalNotes` (internal banking flags). Cross-tenant access to this data in a retail banking platform likely violates Gramm-Leach-Bliley Act (GLBA) privacy protections.
