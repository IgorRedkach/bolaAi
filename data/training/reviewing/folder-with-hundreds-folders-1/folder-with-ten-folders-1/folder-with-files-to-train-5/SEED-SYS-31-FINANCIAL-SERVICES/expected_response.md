## System

- System: CapitalFlow Underwriting GraphQL API v8.0.0
- Domain: FINANCIAL SERVICES / LOAN ORIGINATION / CREDIT REPORTING (GLBA / FCRA)
- Risk ID: RISK-GRPH-802

## Findings

### 1. GraphQL Traversal with ID Substitution — BOLA on Nested `creditReportSummary` Field (Pattern 5.2 + Pattern 1.7)

The `CreditSummaryResolver` (section 6.1) accepts a client-supplied `summaryId` argument on the nested `creditReportSummary` field and prioritizes it over the parent application context:

```java
if (summaryId != null) {
    finalSummaryId = summaryId; // Attacker-supplied ID is used here: 'sum-victim-001'
} else {
    finalSummaryId = db.findSummaryIdByAppId(parentApplication.getAppId());
}
// VULNERABILITY 1.7: Missing Foreign Key BOLA Check
// The code FAILS to check that finalSummaryId's parent app_id matches the
// current parentApplication.getAppId().
CreditReportSummary summary = db.findSummaryById(finalSummaryId);
```

The resolver does not verify that `summaryId` belongs to the parent `LoanApplication`. The `credit_report_summaries` table has an `app_id` foreign key linking each summary to its parent application (section 5.0). The resolver ignores this FK relationship and performs a direct lookup by `summary_id` alone.

**HAR evidence**: POST `https://api.capitalflow.com/graphql` with `LO_A_JWT_88192`. Query: `loanApplication(id: "app-991")` (authorized parent) with nested `creditReportSummary(summaryId: "sum-victim-001")` (unauthorized child). Response: HTTP 200 OK. `creditReportSummary.summaryId: "sum-victim-001"`, `creditScore: 790`, `creditUtilization: 0.15`, `rawCreditData: {"full_ssn": "*--5555"}`. The credit report of a victim application (`sum-victim-001`) was returned using the attacker's loan officer token, with no error.

## Evidence

- **HAR trace**: authorized parent `app-991` used as entry point; nested `summaryId: "sum-victim-001"` substituted; response includes victim's credit score, credit utilization, and partial SSN. HTTP 200 OK with no error.
- **Java resolver** (section 6.1): `summaryId` accepted as direct argument, prioritized over parent context; `db.findSummaryById(finalSummaryId)` called without FK validation against `parentApplication.getAppId()`. Comment explicitly marks the missing check.
- **Schema** (section 5.0): `credit_report_summaries.app_id` references `loan_applications(app_id)` — the FK exists in the database but is never validated in the resolver.
- **Architecture** (section 3.2 + RISK-GRPH-802): "The nested resolver fails to perform a cross-reference check to ensure the supplied `summaryId` actually belongs to the parent `LoanApplication` ID being queried." — documented as known debt since the `CreditReportSummary` refactor.

## Reproduction

```http
POST /graphql HTTP/2.0
Host: api.capitalflow.com
Authorization: Bearer <LO_A_JWT>
Content-Type: application/json

{"query": "query BOLAOnNestedField { loanApplication(id: \"app-991\") { appId creditReportSummary(summaryId: \"sum-victim-001\") { summaryId creditScore rawCreditData } } }"}
```

`app-991` must be the attacker's authorized application. `sum-victim-001` must be a summary ID belonging to a different application.

Expected secure outcome: GraphQL error — `sum-victim-001` is not associated with `app-991`; HTTP 200 with `{"errors": [{"message": "Access denied to requested credit summary"}]}`.  
Observed vulnerable outcome: HTTP 200 OK, response includes `creditScore: 790` and `rawCreditData` containing partial SSN for the victim's credit report.

## Remediation

- **Enforce FK relationship in the nested resolver** (RISK-GRPH-802): after `db.findSummaryById(finalSummaryId)`, add: `if (!summary.getAppId().equals(parentApplication.getAppId())) { throw new ForbiddenException("Access denied to requested credit summary."); }` — return a 403 error, not null.
- **Reject client-supplied `summaryId` argument entirely**: remove the `summaryId` argument from the `creditReportSummary` field definition and derive the summary exclusively from the parent application's FK: `db.findSummaryIdByAppId(parentApplication.getAppId())`. This eliminates the ID substitution vector.
- **Add the FK check to the SQL query**: replace `db.findSummaryById(finalSummaryId)` with `db.findSummaryByIdAndAppId(finalSummaryId, parentApplication.getAppId())` — the DB returns null for mismatches, preventing any data from reaching the resolver layer.
- **Redact `rawCreditData` from the GraphQL response type**: `raw_credit_data` JSONB (including SSN prefix) must not be surfaced through the public-facing API — expose only computed, redacted summary fields.
