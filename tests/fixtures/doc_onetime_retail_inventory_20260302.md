# Retail chain — store inventory API (internal)

API keys per region. **No statement that a caller may only read inventory for stores they operate.**

REST only — **no GraphQL.**

## Endpoints

- `GET /retail/v1/stores/{storeId}/inventory/skus` — List SKU quantities for a store.
- `POST /retail/v1/transfers` — Body `{ "fromStoreId", "toStoreId", "skuIds": [] }`. Moves stock between stores; **does not state** the caller must own or manage both stores.
- `GET /retail/v1/batches/{batchId}/line-items` — Line items for a replenishment batch.
