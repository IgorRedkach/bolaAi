# CRM Contacts API — Developer Guide

## Overview

The Contacts API allows applications to read and update contact records. All requests require a valid OAuth2 access token with scope `contacts.read` or `contacts.write`.

## Authentication

- Bearer token in `Authorization` header. Tokens are scoped per organization (orgId in claim).
- No documentation states whether a user can access only contacts belonging to their org or if object-level checks are enforced.

## Endpoints

### Contacts

- **GET /v2/contacts/{contactId}** — Returns contact details: name, email, companyId, ownerId. Requires `contacts.read`.
- **PATCH /v2/contacts/{contactId}** — Update contact fields. Requires `contacts.write`. Documentation does not state that the caller must be the contact owner or have permission for that contact.

### Companies

- **GET /v2/companies/{companyId}** — Returns company record. Requires `contacts.read`. No mention of checking that the caller’s org can access this company.

## Data Model

- **Contact** — contactId, companyId, ownerId, email, name.
- **Company** — companyId, name, orgId.

## Security Note

Authorization is described only as "valid token and scope". There is no description of how the API ensures that a user with token for org O can only access contacts or companies that belong to org O.
