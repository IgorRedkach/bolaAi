# Analysis Explanation

**System analysed:** RealmForge Game API — GQL-0032 (Gaming / MMO Backend)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method

1. **Read Section 5.0** — Pattern 1.12 (mass assignment via object fields). `updateCharacter` accepts `ownerId` and `tenantId` as writable input fields.
2. **Read Section 3.0 schema** — confirmed `Character` type with `characterId` (not `resourceId`), and `CharacterData` type. Redis cache is by `characterId` (Section 2.0 note).
3. **Read HAR** — `updateCharacter(id: "C-2032", input: {status: "approved", ownerId: "attacker-be1ad999"})`. Attacker `tenant-be1a` targeted character belonging to `tenant-d999`. `ownerId` was overwritten — ownership hijack confirmed.
4. **Combined BOLA + mass assignment** — the write goes to a cross-tenant character (BOLA), and the `ownerId` is mass-assigned to attacker value.

## Consistency Guard
- All tenant IDs (`tenant-be1a`, `tenant-d999`), character IDs (`C-2032`), and field values drawn from this folder's context.txt only.
