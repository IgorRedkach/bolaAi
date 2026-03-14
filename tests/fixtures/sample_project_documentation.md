# HealthHub API — Internal System Documentation

## Overview

HealthHub is a patient portal and clinical API used by healthcare providers. This document describes the main API surface for integration and security review.

## Authentication

- All API requests require a Bearer token in the `Authorization` header.
- Tokens are issued by the identity provider after user login. No document scope or tenant is described here.

## API Endpoints

### Patients

- **GET /api/v1/patients/{patientId}** — Returns the patient record for the given `patientId`. Response includes: name, date of birth, contact info, and list of assigned providers. Requires valid token.
- **GET /api/v1/patients/{patientId}/orders** — Returns lab and medication orders for the patient. Paginated by `page` and `limit`.
- No documentation of how the system checks that the caller is allowed to access this specific patient (e.g. no "caller must be assigned provider" or "tenant scope" described).

### Orders and Prescriptions

- **GET /api/v1/orders/{orderId}** — Returns the order details (status, type, patient reference, timestamps). Requires authentication.
- **GET /api/v1/prescriptions/{prescriptionId}** — Returns prescription details including medication name and patient reference. Used by pharmacy integration.
- Authorization section only states "user must be authenticated". No mention of verifying that the authenticated user is permitted to access this specific order or prescription.

### Internal / Admin

- **GET /api/internal/cases** — List support cases. Optional filter: `?assignedTo=userId`. Linked data: each case has `case_team_members` (user IDs). Used by support dashboard.
- Documentation does not state whether `case_team_members` or related data is filtered by the same access rules as the case itself.

## Data Model (excerpt)

- **Patient** — id, name, dob, tenantId (optional), assignedProviderIds.
- **Order** — id, patientId, type, status, createdAt.
- **Prescription** — id, patientId, medicationId, prescribedAt.
- **Case** — id, subject, status, case_team_members (array of user IDs).

## Operational Notes

- Logs include request path and response status. Retry queue stores full request payload for failed calls. Logs and queue UI are available to operations team.
