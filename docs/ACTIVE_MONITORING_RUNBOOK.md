# Active Monitoring Runbook (Training)

This runbook defines what "active monitoring" means for long 3B training jobs.

## Scope

- Applies to QLoRA/LoRA/DPO/RLVR and packaging/e2e flows.
- Applies whenever a long-running command is active.

## Required Monitoring Loop

At each checkpoint, collect all four items:

1. **Liveness**: process exists and parent chain is valid.
2. **Progress signal**: CPU work and at least one additional indicator
   (e.g., increasing CPU ticks, step/log movement, output file growth).
3. **Artifact signal**: expected output files presence/changes.
4. **Decision**: explicit action:
   - `continue` (healthy progress),
   - `intervene` (stalled/hung),
   - `restart` (misconfigured run).

Never describe monitoring as active without this loop.

### Mandatory Loop Tail (anti-stop guard)

At the end of each checkpoint, do not stop at "status verified".
Execute one of:

- `decision=continue` -> immediately run next timed checkpoint.
- `decision=intervene` -> apply corrective action now, then re-enter loop.
- `decision=restart` -> restart process now, then re-enter loop.

Pseudo-flow:

`checkpoint -> decision -> action -> next checkpoint`

No terminal status check is considered complete without scheduling the next checkpoint.

### Extra Safeguards (anti-third-loop break)

Use this fixed checklist at every iteration:

1. Record checkpoint ledger row:
   - `checkpoint_id`
   - `process_alive`
   - `cpu_ticks_total`
   - `artifact_count`
   - `has_training_result`
   - `decision`
2. Immediately launch next short checkpoint (1-3 min).
3. Immediately launch next medium checkpoint (5-10 min).
4. If either launch is skipped, correct immediately before any other task.

Recommended decision template:

- `decision=continue`: progress increases and no failure signature.
- `decision=intervene`: process alive but no progress across two consecutive checkpoints.
- `decision=restart`: process dead/misconfigured; restart and re-enter checklist.

## Cadence

- Default: check every 1-5 minutes.
- During uncertainty/stall investigation: 30-90 seconds.
- During steady long compute: up to 10 minutes max between checks.

## Stall Criteria

Intervene immediately if any condition holds:

- Process exited with non-zero code.
- Two consecutive checkpoints show no progress signal.
- Runtime exceeds expected window and output artifacts remain unchanged.
- Wrong run configuration detected (e.g., truncated/cut-quality run when full run is required).

## 24-Hour Completion Policy

- If progress is present (even small), continue monitoring and do not interrupt.
- If progress is absent across consecutive checkpoints, estimate completion window.
- If estimated completion exceeds 24 hours, intervene with performance-improving actions
  while keeping model family and quality goals unchanged.
- Allowed performance actions:
  - tune CPU thread env for better utilization,
  - adjust data pipeline inefficiencies,
  - restart from the same full-quality configuration after corrective changes.

## Allowed Interventions

- Kill hung or misconfigured run.
- Restart with corrected configuration.
- Keep same base model family (no downgrade) unless user explicitly approves.
- Preserve training quality goals; do not silently switch to shortcut rebuild-only paths.

## End Goal Enforcement

Monitoring is not complete when training ends. Mandatory follow-through:

1. confirm artifacts and successful completion,
2. run packaging/promotion,
3. run e2e against trained context,
4. report results and any corrective loop if e2e fails.

## Completion Criteria

Training stage is complete only when:

- terminal shows successful exit, and
- expected training artifacts exist (e.g., `training_result.json`), and
- downstream promotion/eval stages run successfully.

Then proceed immediately to:

1. packaging/promotion,
2. e2e verification against trained contexts,
3. final report with evidence of completion.
