# Energy retail — customer usage API (internal)

OAuth2 Bearer. **Row-level authorization for meter/account IDs is not specified.**

## REST

- `GET /energy/v2/meters/{meterId}/readings` — Hourly kWh for a meter.
- `GET /energy/v2/accounts/{accountId}/invoices` — Invoice list for a billing account.
- `POST /energy/v2/accounts/bulk-usage` — Body `{ "accountIds": ["..."] }`. Returns aggregated usage. **Billing analyst role.** No statement that caller may only query accounts in their service territory.

## GraphQL

- `usagePoint(id: ID!) { id meterId intervalReadings { ts kwh } }`

## Legacy

- `GET /energy/v1/export/run/{runId}` — Async CSV export job status. Token required; **runId** scoping not documented.
