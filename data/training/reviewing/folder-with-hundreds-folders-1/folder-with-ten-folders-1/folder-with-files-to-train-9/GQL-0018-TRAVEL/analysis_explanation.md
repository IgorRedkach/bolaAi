## Analysis reasoning

1. **HAR shows `bulkResourceLookup` batch attack as primary**: the HAR request is `bulkResourceLookup(ids: ["R-2018", "R-1018", "R-3018"])` from `tenant-50cd`. The original expected_response.md ignored this and started with `getResource` single-ID — wrong primary step.

2. **Pattern 7.1 (Operational PII/PHI leakage via Logging Failures) has a dual nature**: (a) the BOLA enables access to traveler PII, and (b) the logging failure means this access is not detected. The remediation must address both — not just the BOLA fix but also the logging/audit requirement. In a GDS, bulk unauthorized access to PNRs is a reportable data breach; if audit logs don't flag cross-tenant access, the breach is undetectable by the victim carrier/agency.

3. **`auditLog` field exposure is a secondary unique finding**: the `ResourceData` schema includes `auditLog: [AuditEntry!]`. When an attacker reads a cross-tenant booking record, they also receive the victim's operational audit history — who modified the booking, when, and the modification history. This is operational intelligence beyond the PII itself.

4. **GDS/travel domain context**: booking records in a Global Distribution System contain multi-leg itineraries, passenger names, seat assignments, and potentially frequent flyer numbers. Cross-tenant bulk access is equivalent to a carrier reading a competitor's reservation database.

5. **Bulk lookup is the HAR-primary, not conditional**: section 4.0 documents the gap, and the HAR demonstrates the attack.

6. **Introspection removed**: not documented in sections 4.0 or 5.0.

7. **Redis cache added**: section 2.0 documents `resourceId`-only cache key. Booking records cached without tenant dimension could serve cross-carrier PNR data.
