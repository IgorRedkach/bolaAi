# Live E2E tests — run one-by-one (timing & tuning)

Run **each** live LLM test **separately** so you can see **wall-clock time per test** and spot slow cases (embedding cold start, long prompts, retries).

## Why

- **`pytest tests/test_issues_resolved.py -v`** runs 10+ full **ingest + analyze** flows; one slow test is hidden in the total.
- Per-test runs give a **table** you can track over commits (model changes, prompt size, RAG `N_CONTEXT`).

## Automated timing report

From repo root (stack must be up, or use `BOLA_AI_SKIP_LIVE_E2E=1` only for non-live files):

```bash
cd /path/to/bolaAi
PYTHONPATH=src python scripts/run_live_e2e_tests_one_by_one.py
```

Writes **`docs/live_e2e_test_timings.md`** (overwritten each run): markdown table with **test node id** and **seconds**.

## Manual one test

```bash
PYTHONPATH=src pytest tests/test_issues_resolved.py::TestIssuesResolved::test_report_does_not_reference_unknown_endpoints -v -s
```

Repeat for each `::test_*` you care about. Use `/usr/bin/time` or a stopwatch for wall time.

## Improving slow tests

| Lever | Effect |
|-------|--------|
| Smaller / fewer chunks in fixture doc | Faster ingest + sometimes faster analyze |
| `BOLA_AI_N_CONTEXT` | Lower = less context = faster LLM (may hurt quality) |
| Model size / hardware | Dominates analyze latency |
| Parallel runs | **Do not** run multiple live analyze tests in parallel against one Ollama — queue instead |

Re-run **`scripts/run_live_e2e_tests_one_by_one.py`** after changes to compare the table.

## Latest sample table

After a run, open **`docs/live_e2e_test_timings.md`**. Typical pattern: **ingest+analyze** API smoke ~**180s**; each **test_issues_resolved** call ~**30–135s** depending on query and model load.

## Related

- [E2E_TESTING.md](E2E_TESTING.md) — live stack, timeouts, **6-step person E2E**
- [AGENT_PROMPT_FULL_CYCLE.md](AGENT_PROMPT_FULL_CYCLE.md) section E — full person-style E2E including follow-ups
