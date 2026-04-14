# Analysis Explanation — SF-0252-FINANCIAL-SERVI

## Changes Made

### 1. context.txt — Removed Vulnerability Labels
- Section 5.0 "Vulnerability Context" renamed to "Behavioral Notes"; removed "**Pattern:** 10.2 — Parameter escalation" label
- Section 5.0 now describes the technical behavior: user substitutes `accountId` to extend session scope, without naming the pattern
- Removed "// VULNERABILITY:" comments from Section 4.0 Apex code; replaced with neutral observational comments
- HAR message params corrected to use escaped JSON (`\"`) instead of unescaped quotes

### 2. expected_response.md — Corrected Controller and Parameters
Original used `c.QuoteController.getQuoteDetails` with `quoteId`. HAR specifies `c.AccountController.getAccounts` with `accountId`. Corrected throughout including remediation class name.

### 3. Corrected Org Host and Session Token
Original used `<ORG_ID>.lightning.force.com`. HAR specifies `7d68cfad.lightning.force.com` and `00D7D68CFAD!AR7d68cfad...`. Corrected.

### 4. Explained Pattern 10.2 in Financial Services Context
Pattern 10.2 "parameter escalation (own session scope extension)": a user with a legitimate session substitutes an ID parameter to extend their session's access beyond their own records. In Retail Banking, Account records hold GLBA-protected financial data and SSN. This is a GLBA financial privacy violation.

### 5. Method Name Inconsistency
Section 4.0 code defines `getAccountDetails`; HAR and Section 5.0 use `getAccounts`. HAR is authoritative.
