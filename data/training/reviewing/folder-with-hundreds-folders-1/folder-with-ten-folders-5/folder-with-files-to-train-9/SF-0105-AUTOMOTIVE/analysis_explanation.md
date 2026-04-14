# Analysis Explanation
**Folder:** SF-0105-AUTOMOTIVE | **Context source:** This folder's context.txt only.
- System: AetherDrive V2X Telematics (SF), Automotive/Connected Car, OWD: Private on Lead
- Host: `b175ac70.lightning.force.com`, token: `00DB175AC70!ARb175ac70...`
- Descriptor (HAR): `c.LeadController.getLeadData`, `leadId: "001AC70"`
- **Inconsistency in context.txt:** Apex method in §4.0 is `getLeadDetails` but Aura descriptor in §6.0 is `getLeadData`. HAR is authoritative.
- Response: `OwnerId: 005VICTIM`, `SSN: 000-54-3922`
- Pattern 10.2: Parameter escalation (own session scope extension) — attacker uses their own valid session and substitutes `leadId` to extend access scope to victim connected car Lead records; no ownership check in `without sharing` controller
- §8.0 RISK-SF-105/106: controller without `with sharing`; no ownership check; client-supplied `leadId` directly interpolated
**Consistency Guard:** All values from this folder's context.txt only.
