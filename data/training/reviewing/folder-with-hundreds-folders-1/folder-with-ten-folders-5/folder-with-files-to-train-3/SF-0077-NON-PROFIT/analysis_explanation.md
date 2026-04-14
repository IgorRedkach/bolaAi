# Analysis Explanation
**Folder:** SF-0077-NON-PROFIT | **Context source:** This folder's context.txt only.
- System: GrantFlow CRM API, Non-Profit/Grant Management, OWD: Private on Lead
- Host: `10793266.lightning.force.com`, token: `00D10793266!AR10793266...`
- Descriptor (HAR): `c.LeadController.getLeadData`, `leadId: "0013266"`
- **Inconsistency in context.txt:** Apex method in §4.0 is `getLeadDetails` but Aura descriptor in §6.0 is `getLeadData`. HAR is authoritative; analysis follows HAR.
- Response: `OwnerId: 005VICTIM`, `SSN: 000-86-8311`
- Pattern 10.2: Parameter escalation — attacker substitutes `leadId` to read victim grant Lead records beyond their own session scope
**Consistency Guard:** All values from this folder's context.txt only.
