# SecureBank API — Integration Specification

## Overview

SecureBank provides a REST API for account management, transaction history, and fund transfers. Used by mobile banking apps and third-party fintech integrations.

## Authentication

- All requests require a Bearer token (JWT) in the `Authorization` header.
- JWT contains claims: `sub` (userId), `orgId` (bank branch), `role` (customer|teller|admin).
- No documentation describes per-account or per-transaction ownership checks.

## Endpoints

### Accounts

- **GET /banking/v1/accounts/{accountId}** — Returns account details: balance, holder name, accountType, branchId. Requires valid token with any role.
- **GET /banking/v1/accounts/{accountId}/transactions** — Returns transaction history for the account. Paginated with `?page=&limit=`. Requires valid token.
- Documentation does not state that the caller must be the account holder or have explicit permission for that accountId.

### Transfers

- **POST /banking/v1/transfers** — Initiate a fund transfer. Body: `{ "fromAccountId": "...", "toAccountId": "...", "amount": 100.00 }`. Requires valid token.
- No documentation states that the caller must own the `fromAccountId`.

### Beneficiaries

- **GET /banking/v1/accounts/{accountId}/beneficiaries** — List saved beneficiaries for the account. Requires valid token.
- **POST /banking/v1/accounts/{accountId}/beneficiaries** — Add a beneficiary. Body: `{ "name": "...", "accountNumber": "..." }`.
- No mention of checking that the caller is the account holder before listing or adding beneficiaries.

## Data Model

- **Account** — accountId, holderId, balance, accountType, branchId.
- **Transaction** — txId, accountId, amount, type (debit/credit), timestamp.
- **Beneficiary** — beneficiaryId, accountId, name, accountNumber.

## Operational Notes

- Failed transfer attempts are logged with full request body (including fromAccountId, toAccountId, amount) in the operations dashboard visible to branch staff.
- Audit trail: GET /banking/v1/audit/{userId} returns all actions by a user. Accessible to any admin role without branch-level scope.
