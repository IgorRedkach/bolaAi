## Analysis reasoning

1. **HAR shows `listCandidates` tenant override as the primary attack**: HAR request is `listCandidates(tenantId: "tenant-ad9d")` from `tenant-4b77`. The original expected_response.md started with a `getCandidate` single-ID substitution step, ignoring the HAR. The primary reproduction must lead with the HAR-demonstrated attack.

2. **Pattern 1.10 (Cross-service identity propagation drift) explained**: the JWT carries `tenantId` but when the request crosses from the API gateway into the Apollo Server resolver, the `tenantId` claim is not passed through to the database WHERE clause. Instead, the resolver uses the client-supplied argument, which is the identity drift. This is the canonical Pattern 1.10 mechanism — the identity is authenticated at the edge but lost at the data access layer.

3. **HR domain context makes this particularly sensitive**: `Candidate` objects with `assessments: [Assessment!]` in a talent acquisition platform hold employment-related PII (SSN, salary, background checks). Cross-tenant access is not just a data breach — it is corporate espionage into a competitor's hiring pipeline and a potential employment law violation (CCPA, GDPR Article 9 for special category data in assessments).

4. **Bulk lookup is confirmed, not conditional**: section 4.0 explicitly documents `bulkCandidateLookup` lacking per-ID ownership filtering — a confirmed architectural gap, not a hypothesis.

5. **Introspection removed**: not documented as a risk in sections 4.0 or 5.0. Including it as "if Pattern 6.1 also present" is speculative.

6. **Redis cache risk added**: section 2.0 documents `candidateId`-only cache key. Candidate PII cached without a tenant dimension could be served cross-tenant.

7. **HAR response/request type mismatch**: request is `listCandidates` query but response body is structured as `getCandidate`. Same synthetic artifact pattern. The confirmed signal is `tenantId: tenant-ad9d` in the response with HTTP 200.
