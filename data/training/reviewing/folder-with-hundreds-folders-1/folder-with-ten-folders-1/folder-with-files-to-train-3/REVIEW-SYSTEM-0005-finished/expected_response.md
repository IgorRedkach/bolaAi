## Findings

1. **Client-controlled price on `POST /api/v1/checkout/init` — backend trusts frontend-declared order total**: the checkout Lambda uses `const amountToCharge = payload.order_total` directly from the HTTP request body without recalculating the total from the DynamoDB cart items. The attacker (`usr_99182A`) submitted `"order_total": 200` (i.e., $2.00) for `cart_88192`, which contains one `LAPTOP-PRO-15` with `UnitBasePriceCents: 250000` ($2,500.00). The Stripe `PaymentIntent` was created for $2.00 — 99.92% below the true item value.

2. **Decoupled payment verification on `POST /api/v1/checkout/complete` — amount paid not verified against cart value**: the completion Lambda checks only `if (intent.status === 'succeeded')` from Stripe — it never validates that `intent.amount` equals the sum of `UnitBasePriceCents × Quantity` for the order's items. Since the $2.00 PaymentIntent (`pi_3MtwBwLkdIwHu7ix28a3tq`) succeeded, the order `ord_55419B` was marked `PAID` and fulfillment was triggered — releasing the $2,500 laptop for shipping after a $2.00 payment.

## Evidence

- **HAR entry 1 — checkout/init** (`startedDateTime: 2026-04-08T19:20:05.112Z`, elapsed 215 ms): `POST https://api.cartvantage.com/api/v1/checkout/init`; JWT encodes `cognito:username: usr_99182A`; body `{"cart_id": "cart_88192", "order_total": 200}`; response HTTP 200, `{"client_secret": "pi_3MtwBwLkdIwHu7ix28a3tq_secret_abc123", "order_id": "ord_55419B"}` — a Stripe PaymentIntent for $2.00 was created.
- **DynamoDB order record** (section 5.0): `FrontendDeclaredTotalCents: 200` vs `UnitBasePriceCents: 250000` for `SKU: LAPTOP-PRO-15`. The schema security note explicitly flags this discrepancy: "the backend does not enforce mathematical integrity between these two fields."
- **HAR entry 2 — checkout/complete** (`startedDateTime: 2026-04-08T19:21:30.441Z`, elapsed 450 ms): `POST https://api.cartvantage.com/api/v1/checkout/complete`; body `{"order_id": "ord_55419B", "payment_intent_id": "pi_3MtwBwLkdIwHu7ix28a3tq"}`; response HTTP 200, `{"status": "SUCCESS", "message": "Order PAID. Fulfillment triggered."}` — EventBridge fulfillment rule fired.
- **Flawed init Lambda** (section 6.0): `const amountToCharge = payload.order_total` — no server-side total calculation. `await stripe.paymentIntents.create({ amount: amountToCharge, ... })` — Stripe is given the attacker-supplied amount.
- **Flawed completion Lambda** (section 6.0): `if (intent.status === 'succeeded')` — status check only. The commented line `// intent.amount === calculateTrueCartValue(order.Items)` is never executed.

## Reproduction

Step 1 — intercept the checkout/init request and manipulate `order_total`:

```bash
curl -i -X POST "https://api.cartvantage.com/api/v1/checkout/init" \
  -H "Authorization: Bearer <JWT_usr_99182A_Cognito>" \
  -H "Content-Type: application/json" \
  -d '{"cart_id": "cart_88192", "order_total": 200}'
```

Expected secure outcome: HTTP 400 — `order_total` is ignored; backend recalculates `250000` from cart items; Stripe PaymentIntent created for `250000`.  
Observed vulnerable outcome: HTTP 200 with `client_secret` for a $2.00 PaymentIntent; `order_id: ord_55419B`.

Step 2 — complete the $2.00 payment via Stripe and submit the completion callback:

```bash
curl -i -X POST "https://api.cartvantage.com/api/v1/checkout/complete" \
  -H "Authorization: Bearer <JWT_usr_99182A_Cognito>" \
  -H "Content-Type: application/json" \
  -d '{"order_id": "ord_55419B", "payment_intent_id": "pi_3MtwBwLkdIwHu7ix28a3tq"}'
```

Expected secure outcome: HTTP 400 — `intent.amount` ($2.00) does not match the true cart value ($2,500.00); order remains `PENDING_PAYMENT`.  
Observed vulnerable outcome: HTTP 200 `{"status": "SUCCESS", "message": "Order PAID. Fulfillment triggered."}` — $2,500 laptop released for shipment after $2.00 payment.

## Remediation

- **Server-side price calculation in checkout/init**: replace `const amountToCharge = payload.order_total` with a lookup of the cart items from DynamoDB and calculation of `sum(UnitBasePriceCents × Quantity)`. Pass this server-calculated amount to `stripe.paymentIntents.create()`. Reject or ignore any client-supplied `order_total` field entirely.
- **Amount verification in checkout/complete**: implement `calculateTrueCartValue(order.Items)` and assert `intent.amount === trueCartValueCents` before marking the order `PAID`. If amounts differ, return 400 and flag the order for fraud review.
- **Store server-calculated amount in DynamoDB at init time**: persist the authoritative `AuthoritativeTotalCents` in the order record during checkout/init so the completion Lambda can compare without recalculating.
- **Remove `FrontendDeclaredTotalCents` from DynamoDB schema**: the schema security note (section 5.0) identifies this field as the root of the integrity gap — eliminate it to prevent any confusion between client-declared and server-authoritative totals.
