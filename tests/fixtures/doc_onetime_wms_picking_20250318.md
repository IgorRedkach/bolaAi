# Warehouse WMS — picking API (internal v1)

API key per site. **No per-bin or per-batch authorization is described.**

## Endpoints (REST only — no GraphQL in this product)

- `GET /wms/v1/bins/{binId}/contents` — SKU quantities in a bin.
- `POST /wms/v1/pick-tasks/{taskId}/complete` — Mark pick task done. **Picker role.**
- `POST /wms/v1/batch/picks` — Body `{ "taskIds": ["t-1", "t-2"] }`. Completes multiple tasks. Does not state picker may only act on tasks assigned to them.

There is **no** GraphQL, SOQL, or Salesforce in this API.
