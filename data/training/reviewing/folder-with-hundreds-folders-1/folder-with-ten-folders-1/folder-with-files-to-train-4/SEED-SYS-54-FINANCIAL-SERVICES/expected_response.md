## System

- System: CreditDecision Real-Time Scoring API v5.0.0
- Domain: FINANCIAL SERVICES / CONSUMER CREDIT SCORING (GLBA / FCRA)
- Risk ID: RISK-FIN-BOLA-110

## Findings

### 1. BOLA — Cross-Partner Credit Score Access via Missing `partner_id` Filter in SQL Query (Pattern 1.10)

The Rust Score Retrieval controller (section 6.1) fetches the credit request record using only `request_id`:

```sql
SELECT * FROM credit_requests WHERE request_id = $1
-- THE FLAW: Missing AND partner_id = $2
```

The `credit_requests` table has `partner_id` as the critical isolation field. `auth_partner_id` is extracted from the `X-Partner-ID` header (set by the upstream Go-lang gateway from the validated API key). However, `auth_partner_id` is never included in the `WHERE` clause. Any partner who can guess or enumerate a `request_id` belonging to another partner can retrieve that record, including the cached credit score and SSN prefix.

The code annotation confirms the gap: `// THE FLAW: Missing AND partner_id = $2`.

**HAR evidence**: GET `https://api.creditdecision.com/api/v5/scores/RID-Victim` with `X-Partner-ID: PARTNER-A` and PARTNER-A JWT. Response: HTTP 200 OK, `{"request_id": "RID-Victim", "score": 810, "status": "READY", "consumer_ssn_prefix": "123--"}`. `RID-Victim` belongs to PARTNER-B. PARTNER-A received PARTNER-B's customer's credit score (FICO 810) and partial SSN.

### 2. Identity Propagation Drift — Post-Fetch Partner Check Bypassed by Kafka Context Race (Pattern 8.1 + Pattern 1.10)

A post-read authorization check is present: `if record.partner_id != auth_partner_id { return Forbidden }`. Under normal conditions this would block PARTNER-A from seeing PARTNER-B records. However, section 3.2 documents the Kafka event race: when the Python Credit Fetcher Service completes the bureau call, it notifies the Score Retrieval Service via a Kafka event that includes only `request_id` and `score` — omitting `partner_id`. The comment in section 4.0 (RISK-FIN-BOLA-110) notes: "if the partner_id parameter is missing or stale, it defaults to checking the database, which leads to a concurrency flaw."

During the 500–1200ms bureau call window, a concurrent read can observe a record in an intermediate state where the Kafka-driven update has partially written the score but the `partner_id` context has not been re-propagated from the database. The post-read check against `record.partner_id` is therefore unreliable under concurrency — the field may reflect a stale or intermediate value. Combined with the missing `WHERE` clause filter, the final check provides no reliable protection.

**The HAR confirms**: a single 75ms request returned the full score — the response latency (`x-service-latency-ms: 35`) is consistent with a Redis cache HIT (the score was already `READY`), meaning the Kafka update race window was already past when the attacker queried. The 200 OK confirms the post-read check did not block the response despite the partner mismatch.

## Evidence

- **HAR trace**: PARTNER-A `X-Partner-ID` + JWT → `GET /RID-Victim` → 200 OK with score 810 and SSN prefix for a PARTNER-B customer. Single request, no timing exploit needed — the missing SQL filter is sufficient.
- **Rust SQL query** (section 6.1): `SELECT * FROM credit_requests WHERE request_id = $1` — missing `AND partner_id = $2` annotation is explicit.
- **Response body**: `"consumer_ssn_prefix": "123--"` — partial SSN returned alongside credit score to unauthorized partner.
- **Architecture** (section 3.2): Kafka event from Credit Fetcher to Score Retrieval omits `partner_id`, introducing the concurrency/drift risk.
- **Schema** (section 5.0): `partner_id NOT NULL` is the isolation field — the contract exists at the schema level but is not enforced in the application query.

## Reproduction

```http
GET /api/v5/scores/RID-Victim HTTP/2.0
Host: api.creditdecision.com
X-Partner-ID: PARTNER-A
Authorization: Bearer <PARTNER_A_JWT>
Accept: application/json
```

`RID-Victim` must be a `READY` request belonging to PARTNER-B.

Expected secure outcome: HTTP 403 — `record.partner_id ("PARTNER-B") != auth_partner_id ("PARTNER-A")`.  
Observed vulnerable outcome: HTTP 200 OK — `{"score": 810, "request_id": "RID-Victim", "consumer_ssn_prefix": "123--"}`.

## Remediation

- **Add `partner_id` to the SQL WHERE clause** (RISK-FIN-BOLA-110): replace the query with `SELECT * FROM credit_requests WHERE request_id = $1 AND partner_id = $2` — pass `auth_partner_id` as `$2`. The fetch will return `NOT FOUND` (404) for cross-partner ID guessing, leaking no information about the existence of other partners' records.
- **Move the authorization check into the query, not after it**: the post-read `if record.partner_id != auth_partner_id` check is a late defence that can be circumvented; the `WHERE` clause filter eliminates the attack surface entirely.
- **Include `partner_id` in the Kafka notification event**: the Credit Fetcher → Score Retrieval Kafka event must carry the `partner_id` alongside `request_id` and `score`, so the consuming service never needs to fall back to a stale database read for authorization context.
- **Redact SSN prefix from responses**: `consumer_ssn_prefix` must not be included in score retrieval responses — SSN data should only be present in authenticated profile endpoints with stronger authorization controls.
