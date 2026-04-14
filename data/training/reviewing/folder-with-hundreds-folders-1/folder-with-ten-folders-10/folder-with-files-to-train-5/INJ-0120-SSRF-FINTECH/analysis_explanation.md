# Analysis Explanation — INJ-0120-SSRF-FINTECH

## Changes Made

### 1. context.txt — Removed Vulnerability Label, Fixed Architecture
- Removed "**Vulnerability Type:** SSRF" from spec header
- Section 2.0 "Database: backend HTTP fetch" corrected to PostgreSQL (pg library) as actual database; added "External Data Enrichment" as separate field with fetch() description
- Added Node.js `fetch()` code snippet (Section 3.0) showing `filter` passed directly as URL without validation — this is the technical SSRF evidence
- Section 6.0 added `internal-payments.paybridge.local` as a known internal service (adds realism to SSRF pivot step)
- RISK-INJ-120 updated to mention both SQL concatenation and fetch() URL injection

### 2. expected_response.md — Corrected Endpoint and Parameter
Original used `/api/v1/users?search=`. Context Section 3.0 and HAR specify `/api/v1/orders?filter=`. Corrected throughout.

### 3. Corrected Hostname
Original Steps 3-4 used generic `api.example.com`. HAR specifies `api.paybridge-trans.example.com`. Corrected.

### 4. SSRF Primary with Cloud Credential and Internal Pivot Escalation
SSRF is the declared vulnerability. Added:
- Step 2: AWS metadata listing (HAR payload)
- Step 3: AWS IAM credential theft (AccessKeyId/SecretAccessKey)
- Step 4: Internal payment processor pivot (PCI DSS relevance)
- Step 5: Out-of-band SSRF probe to confirm + leak ENRICHMENT_API_KEY

In Fintech context: AWS IAM credentials enable access to S3 transaction records, RDS, SQS. Internal payment processor pivot is a PCI DSS cardholder data environment boundary violation.

### 5. HAR Inconsistency Addressed
HAR response returns SQL order records rather than metadata content. Acknowledged: both SQL path and fetch() path process the same `filter` parameter; SQL path executed first in observed response. Both surfaces are present.

### 6. SQL Injection Secondary
Code snippet shows raw pg string concatenation with `db_owner`. Made Secondary (Steps 6-7).

### 7. SSRF-Specific Remediations
Added URL allowlist validation with specific blocked ranges (169.254.*, 10.*, 172.16-31.*, 127.*).
