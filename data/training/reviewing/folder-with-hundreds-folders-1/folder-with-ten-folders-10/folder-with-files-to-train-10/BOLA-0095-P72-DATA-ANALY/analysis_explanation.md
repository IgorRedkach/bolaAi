# Analysis Explanation — BOLA-0095-P72-DATA-ANALY

## What was wrong

### 1. Incorrect API version in endpoint

Original `expected_response.md` used `/api/v1/resources` throughout. Section 2.0 and HAR both specify `/api/v2/resources`. Fixed to `/api/v2/resources` in all reproduction steps.

### 2. Pattern 7.2 (anti-forensic) not demonstrated — only BOLA read shown

The original response showed a basic ID-substitution read (Step 1-2) and then stated "No specific variant documented for Pattern 7.2 — use Steps 1-2." This fails to teach Pattern 7.2's core distinguishing characteristic.

Pattern 7.2 (Anti-Forensic Capabilities / Logging Failures) has two components:
1. The authorization failure enables access across tenant boundaries (the BOLA component — same as 1.1-1.3).
2. The access occurs without generating a security audit log entry, making forensic investigation and breach detection impossible.

To demonstrate this to a model, the response must explain *why* the logging failure is the critical differentiator from ordinary BOLA: the attacker can operate indefinitely because no SIEM, no IDS, and no audit log captures the cross-tenant access. Added explanation of this mechanism.

### 3. Write/delete as anti-forensic extensions missing

Section 4.0 explicitly documents GET/PATCH/DELETE all share the same non-enforcing handler. The original response only demonstrated GET. PATCH and DELETE steps were added to show the full severity: an attacker can corrupt or destroy analytics resources (dashboards, datasets, pipeline configurations) with zero forensic attribution. This is the most dangerous consequence of Pattern 7.2.

## Domain context

InsightGraph is a Data Analytics / BI Platform. Resources represent analytics dashboards, reports, or data pipeline configurations with proprietary business intelligence. Cross-tenant access allows competitor intelligence exfiltration. Anti-forensic write/delete allows silent sabotage of competitor analytics — corporate espionage with no detectable trace.

## HAR alignment

HAR primary: `GET /api/v2/resources/RES-2095` → HTTP 200 → `tenantId: "ORG-CFB4"` with `sensitiveData`. This is Step 2 in the response. Endpoint version corrected to `/api/v2`.
