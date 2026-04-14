# Analysis Explanation

**System analysed:** OptaSync Enterprise SCIM Gateway v10.0.1 (IAM / B2B SaaS)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method

1. **Read Section 3.1 (OAuth Scopes)** — identified the scope hierarchy: `scim.user.read` (standard) vs `scim.tenant.manage` (admin). Confirmed the PreviewTemplate endpoint is an admin function.

2. **Read Section 4.0 (Attack Surface)** — two patterns: Pattern 1.2 (function level auth bypass — missing scope enforcement on Kong route) and Pattern 7.3 (SSTI — Nunjucks without sandbox). Noted RISK-IAM-412.

3. **Read Section 5.0 (Kong YAML)** — compared `get-users-route` (has `required_scopes`) with `template-preview-route` (missing `required_scopes`). This is the direct evidence for Finding 1.

4. **Read Section 6.0 (templateController.js)** line by line:
   - `const env = new nunjucks.Environment()` — no sandbox, autoescape false (comment confirms)
   - `env.renderString(html_body, {...})` — untrusted attacker input evaluated by template engine
   - No input validation before `renderString` call

5. **Read Section 7.0 (malicious payload)** — identified the SSTI exploit string: `{{ range.constructor("return global.process.mainModule.require('child_process').execSync('cat /var/run/secrets/kubernetes.io/serviceaccount/token').toString()")() }}`

6. **Decoded the HAR JWT** from the `authorization` header:
   - `eyJzdWIiOiJ1XzM4OTExIiwic2NvcGVzIjpbInNjaW0udXNlci5yZWFkIl0sInRlbmFudCI6InRfODgxOTIifQ` → `{"sub":"u_38911","scopes":["scim.user.read"],"tenant":"t_88192"}` — confirms user-level scope, not admin

7. **Analysed the HAR response**:
   - `200 OK` — not `403` — confirms auth bypass
   - `preview_html` contains a base64url-encoded K8s service account JWT for `system:serviceaccount:optasync-prod:notification-worker`
   - The presence of a JWT token in `preview_html` (instead of HTML) is the definitive SSTI success indicator
   - `x-worker-node: ip-10-44-2-19.ec2.internal` — reveals internal EC2 node

8. **Constructed reproduction steps** using only:
   - The exact endpoint URL and tenant ID from the HAR (`t_88192`)
   - The exact JWT from the HAR
   - The exact SSTI payload from Section 7.0
   - The exact K8s JWT subject from the HAR response

## Consistency Guard
- No data from any other training example was used.
- All URLs, tenant IDs, JWT values, SSTI payloads, and Kubernetes identifiers in expected_response.md are drawn directly from this folder's context.txt.
- The Kubernetes cluster escalation dimension is stated in Section 7.0 of the context and cited specifically.
