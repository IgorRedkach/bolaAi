## System

- System: VaultGuard IAM API (Salesforce-Integrated) v4.6.0
- Domain: CLOUD IAM / IDENTITY PROVIDER
- Example ID: SF-0244
- Risk IDs: RISK-SF-244, RISK-SF-245

## Findings

### 1. Pattern 9.2 — SOQL Authorization Bypass: `c.OpportunityController.getOpportunity` (HAR Primary)

**HAR evidence**: Aura action `c.OpportunityController.getOpportunity` with `opportunityId: "001CF4A"`, client-supplied `fields: ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]`. Response: `state: "SUCCESS"`, `OwnerId: "005VICTIM"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`, `SensitiveData__c: "SSN: 000-32-9515"`.

**Pattern 9.2 (SOQL and Salesforce Record-Level Access)**: the Apex controller exploits two SOQL authorization failures. First, the controller runs `without sharing` (Section 7.0, RISK-SF-244), bypassing Salesforce OWD=Private on the Opportunity object — all Opportunity records in the org become accessible regardless of sharing rules. Second, the SOQL query uses only `WHERE Id = :opportunityId` without `AND OwnerId = UserInfo.getUserId()` (Section 4.0, RISK-SF-245) — no record-level ownership check. Third, Section 8.0: "Client-supplied `opportunityId` is directly interpolated into SOQL without validation" — potential SOQL injection risk if SOQL metacharacters are not stripped.

**Cloud IAM / Identity Provider impact**: Opportunity records represent IAM vendor deals, customer identity contracts, or access management proposals. SSN exposure (`SensitiveData__c: "SSN: 000-32-9515"`) from cross-user Opportunity access enables identity theft of IAM customers. Internal notes expose deal negotiation strategy. In an IAM context, unauthorized access to Opportunity records may also expose access control architecture details of customers.

Note: Section 4.0 names the method `getOpportunityDetails` but HAR uses `getOpportunity`. HAR is authoritative.

## Reproduction

**Step 1 — Capture baseline Aura request:**

Intercept a legitimate Aura request via Burp Suite or DevTools. Identify `c.OpportunityController.getOpportunity` in the `message` body. Record your own `opportunityId`.

**Step 2 — Substitute victim `opportunityId` — SOQL authorization bypass (primary HAR attack):**

```
POST https://3f47cf4a.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D3F47CF4A!AR3f47cf4a...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D3F47CF4A!AR3f47cf4a...

message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN",
"params":{"opportunityId":"001CF4A","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

Expected secure: `state: "ERROR"` / INSUFFICIENT_ACCESS / empty `records`.  
Expected vulnerable: `state: "SUCCESS"` with `OwnerId: "005VICTIM"`, `SensitiveData__c: "SSN: 000-32-9515"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`.

**Step 3 — Enumerate other Opportunity IDs:**

Salesforce Opportunity IDs use `006` prefix. Enumerate to access all IAM customer contract records in the org.

## Evidence

- **HAR**: `c.OpportunityController.getOpportunity` with `opportunityId: "001CF4A"` → `SUCCESS` → `SensitiveData__c: "SSN: 000-32-9515"`, `OwnerId: "005VICTIM"`.
- **Section 4.0**: Apex controller declared `public class OpportunityController` (no `with sharing`) — RISK-SF-244.
- **Section 4.0**: SOQL missing `AND OwnerId = UserInfo.getUserId()` and `WITH SECURITY_ENFORCED` — RISK-SF-245.
- **Section 7.0**: `Opportunity OWD: Private` — sharing rules bypassed by `without sharing`.
- **Section 8.0**: Client-supplied `opportunityId` directly interpolated into SOQL — SOQL injection risk.

## Remediation

1. **Add `with sharing` to Apex class** (RISK-SF-244):
   ```apex
   public with sharing class OpportunityController { ... }
   ```
2. **Add ownership filter to SOQL** (RISK-SF-245):
   ```apex
   WHERE Id = :opportunityId AND OwnerId = :UserInfo.getUserId()
   ```
3. **Add `WITH SECURITY_ENFORCED`** to all SOQL queries.
4. **Validate `opportunityId`** format and against user's accessible record list before querying.
5. **Whitelist allowed fields server-side**: do not accept client-supplied `fields` array.
6. **Regression test**: Apex test authenticates as User A, requests User B's `opportunityId` — assert `INSUFFICIENT_ACCESS` or empty `records`.
