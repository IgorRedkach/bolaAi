# 24-Hour Active Monitoring Plan (Strict)

Goal: do not stop until model teaching is completed, then run e2e, then package/push image.

## Current Run Status (Live)

- Active training process: `pid=852375` (`train_qlora_unsloth.py`)
- Current state: running
- Active run id: `qlora_20260410T125146Z`
- Latest progress signal: heartbeat ticker active (`stage=train_alive`, timestamp updates every ~30s)
- Adapter artifact status: `training_result.json` not present yet
- Current decision: `continue` (progress exists)
- Next scheduled checkpoints: short + medium (always pre-queued)

## Execution Phases (Live Checklist)

- [x] Phase 1: Monitoring policy/rules hardened
- [x] Phase 2: Full-quality 3B training started
- [ ] Phase 3: Training completed + artifacts verified
- [ ] Phase 4: Packaging/promotion completed
- [ ] Phase 5: E2E completed on trained context
- [ ] Phase 6: Image build completed
- [ ] Phase 7: Image push completed

## Stop Conditions (Only Allowed)

- [ ] Training completed successfully and artifacts exist.
- [ ] Packaging/promotion completed successfully.
- [ ] E2E test completed successfully on trained context.
- [ ] Image build and push completed successfully.

No other stop reason is allowed unless the user explicitly asks to stop.

## Mandatory Loop Tasks (Every Round)

- Check process liveness (`process_alive`).
- Check progress signal (`cpu_ticks_total` or equivalent) and compare with previous round.
- Check artifacts (`training_result.json`, adapter dir changes).
- Check error signals (tracebacks/runtime failures).
- Emit explicit decision: `continue` / `intervene` / `restart`.
- Queue next short checkpoint (1-3 min).
- Queue next medium checkpoint (5-10 min).
- Review checkpoint trend across at least 3 recent checkpoints (not latest only).

## Checkpoint Ledger (append-only)

- MON-021: alive=true, ticks=3762521, artifacts=none, decision=continue
- MON-022: queued/collected in loop, decision=continue
- MON-023: alive=true, ticks=3776262, artifacts=none, decision=continue
- MON-024: alive=true, ticks=3796248, artifacts=none, decision=continue
- MON-025: queued/collected in loop, decision=continue
- MON-026: queued in loop
- MON-027: queued in loop
- MON-LIVE: alive=true, ticks=3909129, artifacts=none, decision=continue
- MON-RESTART-001: process restarted after heartbeat refactor, decision=continue
- MON-RESTART-002: heartbeat observed (`stage=load_model`, then `state=train_begin`), decision=continue
- MON-RESTART-003: periodic ticker confirmed (`train_alive` updates), decision=continue

## Full-Document Review Requirement

At each decision point, review and reconcile all active monitoring documents:

- `docs/TRAINING_MONITORING_24H_PLAN.md`
- `docs/ACTIVE_MONITORING_RUNBOOK.md`
- `docs/retrain_live_heartbeat.json`
- `docs/retrain_loop_status.json`

Do not decide from latest checkpoint only.

If any item above is missing, fix immediately before doing anything else.

## 24-Hour Checklist (Hour-by-hour tracking)

- [x] H00
- [x] H01
- [x] H02
- [x] H03
- [x] H04
- [x] H05
- [x] H06
- [x] H07
- [x] H08
- [x] H09
- [x] H10
- [ ] H11
- [ ] H12
- [ ] H13
- [ ] H14
- [ ] H15
- [ ] H16
- [ ] H17
- [ ] H18
- [ ] H19
- [ ] H20
- [ ] H21
- [ ] H22
- [ ] H23

## 24-Hour Rule

- If progress exists (even small): continue.
- If there is zero progress across consecutive checkpoints:
  - estimate completion time,
  - if projected >24h, intervene with throughput improvements (threads/data path),
  - do not downgrade model family or switch to rebuild-only shortcuts.

## Completion Sequence (Required order)

1. Finish training and verify artifacts.
2. Package/promote trained model.
3. Run e2e on trained context.
4. Build and push image.


