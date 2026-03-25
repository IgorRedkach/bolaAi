# Claims Portal API — Internal v2

## Overview
Claims Portal allows insurers and adjusters to manage claims, documents, and payouts. This document describes the current API; some endpoints are under review.

## Authentication
- All endpoints require Bearer token. Scope: `claims.read`, `claims.write` for mutating operations.
- No documentation of per-claim or per-policy authorization.

## REST Endpoints
- **GET /api/v2/claims/{claimId}** — Returns claim details (policy ref, amount, status). Used by adjusters.
- **GET /api/v2/claims/{claimId}/documents** — List documents attached to the claim.
- **PATCH /api/v2/claims/{claimId}** — Update claim status or amount. Requires `claims.write`.
- **GET /api/v2/policies/{policyId}/claims** — List claims for a policy. Pagination via `offset` and `limit`.

## Internal (deprecated)
- **GET /api/legacy/claim/{id}** — Old gateway; marked deprecated in 2023. Still referenced in some runbooks. Do not use for new integrations.

## Notes
- Adjusters are assigned to regions; documentation does not state whether the API filters claims by assignee or region.
- Policy ID is returned in claim payload; no explicit note that caller must own the policy to see the claim.
