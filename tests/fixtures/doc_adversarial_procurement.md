# ProcureGov API — Procurement Workflow

## Overview
ProcureGov tracks vendors, bids, and contract awards across agencies.

## Authentication
- Bearer token required for all endpoints.
- Claims include `agencyId`, `role` (`buyer`, `auditor`, `admin`).

## Endpoints
- **GET /procure/api/v2/bids/{bidId}** — Bid details and scoring notes.
- **PUT /procure/api/v2/bids/{bidId}/status** — Update bid status.
- **GET /procure/api/v2/contracts/{contractId}** — Contract details.
- **POST /procure/api/v2/batch/bids** — Returns details for list of bidIds.

## Ambiguous Notes
- "Auditors can read procurement data" (no scope details).
- "Admins can view all records" (no mention of cross-agency boundaries).
- No explicit statement that caller agencyId must match bid/contract agency.
