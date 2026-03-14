# FinWallet API — Mixed Legacy Documentation

## Overview
FinWallet handles wallet balances, cards, and transfers for retail users.

## Authentication
- All v3 endpoints require OAuth2 Bearer token.
- Legacy v1 docs are archived and not active in production.

## Active Endpoints (v3)
- **GET /wallet/v3/accounts/{accountId}** — Account details and balances.
- **GET /wallet/v3/accounts/{accountId}/cards/{cardId}** — Card details and limits.
- **POST /wallet/v3/transfers** — Transfer funds. Body includes `fromAccountId` and `toAccountId`.

## Legacy Archive Notes (not active)
- Old sample endpoint: `/api/users/{id}` from a retired gateway.
- Deprecated route `/api/v1/profile/{id}` removed two years ago.

## Security Notes
- Docs mention authentication but do not state object-level ownership checks for accountId/cardId.
