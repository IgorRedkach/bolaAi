# Analysis Explanation
**Folder:** SF-0087-AVIATION | **Context source:** This folder's context.txt only.
- System: AeroOps Flight Management, Aviation/Flight Ops, OWD: Private on Event
- Host: `312d9b87.lightning.force.com`, token: `00D312D9B87!AR312d9b87...`
- Descriptor (HAR): `c.EventController.updateEvent`, `eventId: "0019B87"`
- **Inconsistency in context.txt:** Apex method in §4.0 is `getEventDetails` but Aura descriptor in §6.0 is `updateEvent`. HAR is authoritative; analysis follows HAR.
- Response: `OwnerId: 005VICTIM`, `SSN: 000-20-7340`
- Pattern 2.1: Functional pivot (BAC) — controller provides unauthorized access path for lower-privileged flight ops users
**Consistency Guard:** All values from this folder's context.txt only.
