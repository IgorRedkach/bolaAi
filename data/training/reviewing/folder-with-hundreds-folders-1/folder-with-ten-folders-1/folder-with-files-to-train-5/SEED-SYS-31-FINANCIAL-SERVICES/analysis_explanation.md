## Analysis reasoning

I reviewed the CapitalFlow Underwriting GraphQL API v8.0.0 architecture specification, Java Spring resolver code, schema, and HAR trace.

1. **Traversal-with-ID-substitution pattern**: the attacker starts with an authorized root object (`loanApplication(id: "app-991")`) to pass the top-level BOLA check. They then inject a different ID (`summaryId: "sum-victim-001"`) as an argument to the nested resolver. This is pattern 5.2: the authorized parent context provides a foothold, but the nested resolver ignores the parent context for its own lookup. The key evidence is the `summaryId` argument at the nested field level — this argument should not be client-controllable.

2. **FK relationship documented in schema but not enforced in code**: the `credit_report_summaries` table has `app_id REFERENCES loan_applications(app_id)` — this is the correct security contract. The resolver has access to `parentApplication.getAppId()` but uses it only in the `else` fallback. When `summaryId != null`, the parent context is completely bypassed. The comment explicitly marks: "The code FAILS to check that finalSummaryId's parent app_id matches the current parentApplication.getAppId()."

3. **HAR confirms full credit data exposure**: the response body contains `summaryId: "sum-victim-001"` (not `sum-A`), `creditScore: 790`, and `rawCreditData` with `"full_ssn": "*--5555"`. The `applicantName: "Attacker Loan Officer"` in the parent confirms the root application was the attacker's own — only the nested field was hijacked. The response header `x-resolver-nodes: Application, CreditSummary: 2` confirms two resolver nodes were executed: the parent Application resolver (authorized) and the CreditSummary resolver (unauthorized but executed).

4. **RISK-GRPH-802 documents the refactor as the origin**: the `CreditReportSummary` was originally tied to its parent application without a separate ID. When it was refactored as a standalone entity with `sum-UUID` IDs for caching, the nested resolver was not updated to enforce the FK relationship. This is a common pattern in GraphQL refactors: caching optimizations introduce standalone IDs, and the previous implicit parent-child authorization is lost.

5. **GLBA/FCRA impact**: credit report summaries containing SSN data and credit scores are consumer financial information under FCRA. The attacker (Loan Officer A, authorized for `app-991`) obtained the credit report of a different loan applicant (`sum-victim-001`). This is unauthorized access to a consumer report — a FCRA violation requiring breach notification.
