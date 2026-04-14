# Analysis Explanation
**Folder:** SF-0057-INDUSTRIAL-IOT | **Context source:** This folder's context.txt only.
- System: ManuControl Robotics Fleet, Industrial IoT/Robotics, OWD: Private on Lead
- Host: `e70317ef.lightning.force.com`, token: `00DE70317EF!ARe70317ef...`
- Descriptor (HAR): `c.LeadController.getLeadData`, `leadId: "00117EF"`
- **Inconsistency in context.txt:** Apex method in §4.0 is `getLeadDetails` but Aura descriptor in §6.0 is `getLeadData`. HAR is authoritative; analysis follows HAR.
- Response: `OwnerId: 005VICTIM`, `SSN: 000-91-7749`
- Pattern 1.5: Cross-tenant/cross-user access — no tenant isolation in controller; attacker reads any Lead by substituting `leadId`.
**Consistency Guard:** All values from this folder's context.txt only.
