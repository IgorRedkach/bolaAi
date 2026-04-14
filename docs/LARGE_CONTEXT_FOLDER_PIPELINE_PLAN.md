# Large Context Folder Pipeline Plan

## Objective

Move training data from row-level JSON records to folder-based training sets, generate very large realistic contexts (>=10MB each), and train on 10 sets with health monitoring.

## Checkpoints

- [x] C1 Refactor generation to folder-per-record sets
  - Output per set:
    - `context.txt`
    - `expected_response.md`
    - `analysis_explanation.md`
    - `meta.txt`
  - Maintain lightweight global manifest: `data/training/records_manifest.tsv`
  - Enforce `context.txt >= 10MB`

- [x] C2 Refactor split builder to consume folder sets
  - Read `records_manifest.tsv`
  - Stream each record from files (no full dataset in memory)
  - Write SFT/DPO/EVAL outputs in streaming mode

- [x] C3 Adapt training ingestion for large contexts
  - Keep source record format folder-based
  - Ensure tokenization/training stage can run with bounded memory
  - Use chunk caps where needed for controlled runs

- [x] C4 Generate 10 training sets and verify size
  - Produce exactly 10 sets
  - Verify each `context.txt` is >10MB

- [ ] C5 Train from scratch on 10 sets with monitoring
  - Run training with 10-set source
  - Monitor process health + memory usage until completion
  - Capture run result summary
