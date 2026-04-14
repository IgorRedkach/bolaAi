# Agent weak-place registry (mandatory)

**Purpose:** Every **weak spot**, **partial fix**, or **“could be improved”** item must be **recorded here** until it is **fixed and verified**. The coding agent **must not** treat a session as complete while **any row below is OPEN** (unless the only blocker is documented in ISSUES.md as environment/stack unavailable — still file OPEN issue).

## Rules

1. **On starting work:** Read `docs/ISSUES.md` and `docs/GOALS.md` files. **OPEN** rows = mandatory work before claiming “all goals met.”
2. **When you find a gap** (E2E miss, wrong curl method vs doc, grounding slip, test gap, doc drift): **append** a row with status **OPEN**.
3. **After you fix:** Change status to **FIXED**, run the verification (unit test / E2E / script), then set **VERIFIED** with date and evidence (test name or log path).
4. **Automatic next loop:** After fixing, **do not stop** at “fixed in code” — **re-run** the failing check **immediately**. If anything still fails, add/update rows and **repeat** until **no OPEN rows** remain for this cycle’s scope.
5. **Registry clear:** When there are **no OPEN rows**, keep a short history table below **or** a single line: `*(none — registry clear; YYYY-MM-DD)*`
6. **Goal protection:** Do not delete user-defined goals from `docs/GOALS.md` unless the user explicitly requests deletion; treat accidental removal as a weak place.
7. see `docs/ISSUES.md` for bugs and add new problems there or reopen old ones with additional information