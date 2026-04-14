# Analysis Explanation

**Folder:** SF-0040-NUCLEAR
**Context source:** This folder's context.txt only. No other example was consulted.

---

## Step-by-step Analysis

### 1. Platform and Architecture Review (§2.0)
ReactorCore Safety API (v1.6.0) is a nuclear / safety systems platform on Salesforce Lightning Experience. OWD = Private on Account object means users should only access Account records they own. Authorization must be enforced both by Salesforce sharing rules AND explicitly in Apex code using `WITH SECURITY_ENFORCED` or ownership predicates.

### 2. Apex Controller Inspection (§4.0)
`AccountController` is declared `public class AccountController` — without `with sharing`. The SOQL:
```apex
SELECT Id, Name, OwnerId, SensitiveData__c, InternalNotes__c
FROM Account
WHERE Id = :accountId
```
has no `AND OwnerId = UserInfo.getUserId()` and no `WITH SECURITY_ENFORCED`. Client-supplied `accountId` is directly interpolated into SOQL without sanitization.

### 3. Context Artifact Inconsistency
§4.0 defines the method as `getAccountDetails(String accountId, ...)`. §5.0 and the HAR descriptor (§6.0) both reference `c.AccountController.getAccounts`. Both reference the same `AccountController` class declared without sharing; the vulnerability root cause is identical regardless of which method is called. This inconsistency is in context.txt and is documented as-is.

### 4. Vulnerability Pattern (§5.0)
Pattern 3.1 — Client-assumed authority (Insecure Design): The design assumes the client will only submit `accountId` values it is authorised to access. No server-side verification exists to challenge this assumption. An attacker simply submits a victim's `accountId` and receives their record.

### 5. Risk Assessment (§8.0)
- **RISK-SF-040:** Controller without `with sharing` — sharing rules bypassed.
- **RISK-SF-041:** No ownership check in SOQL WHERE clause.
- Client-supplied `accountId` is directly interpolated into SOQL — potential SOQL injection if input validation is absent.

### 6. HAR Trace Analysis (§6.0)
- **Endpoint:** `POST https://193a22f6.lightning.force.com/aura`
- **Auth headers:** `Authorization: Bearer 00D193A22F6!AR193a22f6...` and `X-SFDC-Session: 00D193A22F6!AR193a22f6...`
- **Aura action descriptor:** `c.AccountController.getAccounts`
- **Params:** `accountId: "00122F6"`, `fields: ["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]`
- **`aura.token: "undefined"`** — token validation bypassed
- **Response state:** `SUCCESS` — no authorization error
- **Response data:** `Id: 00122F6`, `Name: Victim Account Record`, `OwnerId: 005VICTIM`, `InternalNotes__c: CONFIDENTIAL: internal review notes`, `SensitiveData__c: SSN: 000-14-5377`

### 7. Nuclear / Safety Systems Domain Impact
Account records in ReactorCore may represent nuclear facility operators, safety inspectors, vendors with site access, or regulatory contacts. The exposed `SensitiveData__c: SSN: 000-14-5377` is a direct PII breach. In a nuclear context, personnel identity data is subject to IAEA safeguards, NRC regulations (10 CFR 73), and UK ONR requirements. Unauthorised access to nuclear personnel data constitutes a security event reportable under these frameworks.

### 8. Reproduction Construction
The curl command uses the exact HAR values from §6.0: host `193a22f6.lightning.force.com`, token `00D193A22F6!AR193a22f6...`, descriptor `c.AccountController.getAccounts`, `accountId: 00122F6`, full fields list. No placeholder or cross-example data was used.

### 9. Remediation Justification
`with sharing` closes OWD bypass (RISK-SF-040). SOQL ownership predicate + `WITH SECURITY_ENFORCED` closes RISK-SF-041. Removing client-controlled `fields` eliminates the mass-field-exposure surface. Input validation on `accountId` prevents SOQL injection. In a nuclear context, defense-in-depth is mandatory — all four controls should be applied simultaneously.

---

**Consistency Guard:** All details (system name `ReactorCore Safety API`, domain `Nuclear/Safety Systems`, version `1.6.0`, host `193a22f6.lightning.force.com`, session token `00D193A22F6!AR193a22f6...`, descriptor `c.AccountController.getAccounts`, `accountId: 00122F6`, `OwnerId: 005VICTIM`, `SSN: 000-14-5377`, RISK-SF-040, RISK-SF-041, Pattern 3.1) are sourced exclusively from this folder's context.txt.
