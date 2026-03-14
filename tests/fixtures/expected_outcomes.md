# Expected outcomes for manual test docs

When we ingest each fixture and ask for BOLA findings, the report should satisfy the following.

## doc_ecommerce_orders.md

- **Must mention** (from doc): `/store/v2/` or `orders` or `invoices` in the context of BOLA/ownership.
- **Must NOT suggest** endpoints not in doc: e.g. `/api/users/`, `/api/tenants`, `/api/patients/`.
- **Verification**: At least one step must mention two different user tokens or two users (or we append the reminder).
- **Structure**: Single `###` per finding; Rationale should focus on ownership/permission for order/invoice ID, not "no authentication" (doc says API key required).
- **Paths**: Prefer exact paths from doc: `/store/v2/orders/{orderId}`, `/store/v2/invoices/{invoiceId}`.

## doc_file_storage.md

- **Must mention**: `/files/api/` or `documents` or `folders` in BOLA context.
- **Must NOT suggest**: `/api/users/`, `/api/tenants`, or endpoints not in doc.
- **Verification**: Two-token or two-user phrasing (or reminder appended).
- **Rationale**: Ownership/access for docId/folderId, not "no auth" (doc says OAuth2 required).

## doc_support_tickets.md

- **Must mention**: `/support/tickets/` or `/support/comments/` or ticket/comment in BOLA context.
- **Must NOT suggest**: Endpoints not in doc (e.g. `/api/users/`, `/api/tenants`).
- **Verification**: Two-token or two-user phrasing (or reminder).
- **Rationale**: Ownership/access for ticketId or commentId, not "no authentication".

## sample_project_documentation.md (HealthHub)

- **Must mention**: `/api/v1/patients/`, `/api/v1/orders/`, `/api/v1/prescriptions/`, or `/api/internal/cases` (or equivalent).
- **Must NOT suggest**: `/api/users/`, `/api/tenants` (not in doc).
- **Verification**: Two-token phrasing or reminder.
- **Rationale**: Ownership for patient/order/prescription/case, not "no auth".

## doc_crm_contacts.md

- **Must mention**: `/v2/contacts/`, `/v2/companies/`, or contact/company in BOLA context.
- **Must NOT suggest**: `/api/users/`, `/api/tenants`, `/api/patients/` (not in doc).
- **Verification**: Two-token phrasing or reminder.
- **Rationale**: Ownership for contact/company, not "no auth" (doc says OAuth2 required).
