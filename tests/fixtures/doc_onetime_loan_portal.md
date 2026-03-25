# Loan Portal API — Internal v2

## Overview
Loan Portal allows lenders and back-office to manage loans, documents, and status updates. All endpoints require Bearer token. This document describes the current API; authorization details are not fully specified here.

## Authentication
- Bearer token required. Scopes: `loans.read`, `loans.write` for mutations.
- No documentation of per-loan or per-organization authorization checks.

## REST Endpoints

- **GET /api/v2/loans/{loanId}** — Returns loan details (amount, status, borrower ref). Used by servicing team.
- **GET /api/v2/loans/{loanId}/documents** — List documents attached to the loan. Pagination via `offset` and `limit`.
- **PATCH /api/v2/loans/{loanId}/status** — Update loan status (e.g. active, closed). Requires `loans.write`.
- **GET /api/v2/orgs/{orgId}/settings** — Returns organization settings (name, region, limits). Used by org admins.
- **POST /api/v2/loans/batch** — Request body: `{"loanIds": ["id1", "id2", ...]}`. Returns loan summaries for the given IDs. Used for bulk reporting.

## Notes
- Servicing team is assigned by region; documentation does not state whether the API filters loans by assignee or region.
- Organization ID appears in token claims; no explicit note that caller must belong to orgId when calling orgs/{orgId}/settings.
