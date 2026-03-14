# ClaimsHub API — Insurance Claims Platform

## Overview
ClaimsHub handles claim records, attachments, and payout workflow for multiple insurers.

## Authentication
- OAuth2 Bearer token with scopes `claims.read`, `claims.write`.
- Token contains `insurerId` and `userRole`.

## Endpoints
- **GET /claims/v2/claims/{claimId}** — Retrieve full claim details (accident report, policy reference, customer details).
- **GET /claims/v2/claims/{claimId}/attachments/{attachmentId}** — Download claim attachment.
- **PUT /claims/v2/claims/{claimId}/decision** — Set decision (`approved`, `denied`).
- **POST /claims/v2/batch/lookup** — Body with `claimIds` list; returns matching claims.

## Security notes
- The docs mention authentication and scopes only.
- No explicit rule that `insurerId` from token must match claim owner insurer.
