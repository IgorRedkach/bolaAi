This directory stores git-pushable split bundles for trained model snapshots.

Expected contents after packaging:
- `LATEST` - bundle directory name to use at image build time
- `<model-name>-<timestamp>/trained_model_bundle.part-0001` ... `part-N`
- `<model-name>-<timestamp>/RESTORE_COMMAND.txt`

These split parts are intentionally capped below 100MB each so standard git remotes
can accept them without Git LFS.
