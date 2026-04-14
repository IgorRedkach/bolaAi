# Analysis Explanation
**Folder:** SF-0045-DATA-ANALYTICS | **Context source:** This folder's context.txt only.

## Step-by-step Analysis

### 1. Platform Review (§2.0)
InsightGraph Analytics API (SF-0045), Data Analytics, Salesforce Lightning. OWD = Private on Account object.

### 2. Apex Controller (§4.0)
`AccountController` — `public class AccountController` without `with sharing`. SOQL: `FROM Account WHERE Id = :accountId` — no ownership predicate.

### 3. Pattern 2.1 — Functional Pivot
The attacker uses the `getAccounts` action as a pivot to read Account records outside their authorization scope. No privilege escalation needed — just parameter substitution.

### 4. HAR (§6.0)
- Host: `29fb1527.lightning.force.com`, token: `00D29FB1527!AR29fb1527...`
- Descriptor: `c.AccountController.getAccounts`, `accountId: "0011527"`
- Response: `OwnerId: 005VICTIM`, `SensitiveData__c: SSN: 000-34-5864`
- RISK-SF-045, RISK-SF-046

### 5. Domain Impact
Data analytics Account records may contain workspace configs, pipeline metadata, and analyst PII. SSN exposure is a direct regulatory breach.

**Consistency Guard:** system `InsightGraph Analytics API`, host `29fb1527.lightning.force.com`, token `00D29FB1527!AR29fb1527...`, `accountId: 0011527`, `SSN: 000-34-5864`, RISK-SF-045/046, Pattern 2.1 — from this folder's context.txt only.
