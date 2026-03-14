# GovGrants API — Internal Technical Documentation

## Overview
GovGrants is used by federal and state teams to manage grant applications and disbursements.

## Authentication
- Bearer JWT required for all endpoints.
- Claims include `sub`, `agencyId`, and `role` (`reviewer`, `approver`, `admin`).
- Documentation does not describe object-level checks by `applicationId` or `grantId`.

## Endpoints
- **GET /grants/api/v1/applications/{applicationId}** — Returns full application packet including applicant PII and scoring notes.
- **PATCH /grants/api/v1/applications/{applicationId}/status** — Update status (`submitted`, `under_review`, `approved`, `rejected`).
- **GET /grants/api/v1/grants/{grantId}/disbursements** — Returns disbursement history for grant.
- **POST /grants/api/v1/grants/{grantId}/disbursements** — Add disbursement record.

## Notes
- The docs only state "valid token required" for all operations.
- No statement that reviewer/approver must belong to same `agencyId` as application/grant.
