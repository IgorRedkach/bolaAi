# Expected Response

## System
- System: PatientCore EHR API (Salesforce-Integrated) v2.9.0
- Domain: HEALTHCARE / EHR PLATFORM
- Example ID: SF-0251
- Risk IDs: RISK-SF-251, RISK-SF-252

## Findings

### 1. Pattern 9.2 — SOQL Record-Level Access Bypass: `c.ContractController.approveContract` (HAR Primary)

The Aura controller `c.ContractController.approveContract` is vulnerable to Pattern 9.2 (SOQL and Salesforce record-level access bypass). The SOQL query filters by `contractId` only, without enforcing Salesforce's record-level access model (OWD=Private). The `without sharing` class declaration (RISK-SF-251) means Salesforce platform-level row-level security is not applied, and the missing `OwnerId = :UserInfo.getUserId()` predicate (RISK-SF-252) means the Apex code does not compensate with explicit ownership checks.

In a Healthcare/EHR context, Contract records contain patient agreements, SSN PII, and HIPAA-protected health information. SOQL record-level bypass enables any authenticated EHR user to access any other patient's contract record.

**Evidence from HAR:**
- Aura action: `c.ContractController.approveContract`
- Requested `contractId`: `001B9DE` — belongs to `OwnerId: "005VICTIM"`
- Response state: `SUCCESS` — SOQL record-level access not enforced
- Response includes `SensitiveData__c: "SSN: 000-57-2073"` and `InternalNotes__c: "CONFIDENTIAL: internal review notes"` — PHI/SSN exposed

## Reproduction

**Step 1 — Capture baseline Aura request:**
Intercept a legitimate Aura request using Burp Suite or browser DevTools.
Identify `c.ContractController.approveContract` in the `message` POST body.
Record your own `contractId`.

**Step 2 — Substitute victim `contractId` — SOQL record-level access bypass (primary HAR attack):**
```
POST https://88a9b9de.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D88A9B9DE!AR88a9b9de...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D88A9B9DE!AR88a9b9de...

message={"actions":[{"id":"1;a","descriptor":"c.ContractController.approveContract","callingDescriptor":"UNKNOWN",
"params":{"contractId":"001B9DE","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Step 3 — Enumerate adjacent Contract IDs:**
Increment the last segment to enumerate patient contract records:
```
contractId: 001B9DD, 001B9DF, 001B9E0, ...
```

**Step 4 — Verify SOQL record-level access bypass:**
**Vulnerable outcome:** Response `state: "SUCCESS"` with victim Contract data including:
- `SensitiveData__c: "SSN: 000-57-2073"` — SSN/PHI exposed (HIPAA §164.312 violation)
- `InternalNotes__c: "CONFIDENTIAL: internal review notes"`
- `OwnerId: "005VICTIM"` — SOQL returned record owned by another user

**Secure outcome:** Response `state: "ERROR"` with `INSUFFICIENT_ACCESS` or empty `records` array.

## Remediation
1. **Add `with sharing` to Apex class (RISK-SF-251):**
   ```apex
   public with sharing class ContractController { ... }
   ```
2. **Add ownership filter to SOQL (RISK-SF-252):**
   ```apex
   WHERE Id = :contractId AND OwnerId = :UserInfo.getUserId()
   ```
3. **Use `WITH SECURITY_ENFORCED` in all SOQL queries** to enforce field-level and record-level security at the platform layer.
4. **Automated test:** Apex test authenticating as User A requesting User B's `contractId` — assert `INSUFFICIENT_ACCESS` or empty result.
