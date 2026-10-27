# Historical migration backup retention

## Explicit legacy diagnostic and generated-copy expiry

`PWN::SessionCleanup.expire_legacy` is a separate, explicit maintenance entry point, defaulting to a preview. Apply requires `dry_run: false` and a **new external** `manifest:` path for one compressed metadata ledger; it does not archive payloads back into the managed home or run session/swarm retirement.

Only recognized expired closed request logs, the exact `learning.jsonl.bak-lean-YYYYMMDD` and `preferences.jsonl.bak-p15-YYYYMMDDhhmmss` recovery families, and verified duplicate BinaryParser triage caches qualify. Root recovery retains at least the latest three nonempty parseable copies per family, all literal reference pins, and copies younger than thirty days. Cache expiry requires byte-identical retained ArtifactRegistry evidence; absent inputs are not claimed reproducible. Decompiler stdout caches are not adopted by this policy.

The operation holds the canonical maintenance lock, rejects unsafe path/inode identities, checks retained references without exposing content, and checks process descriptors before classification and unlink. Existing producer leases must be available. Retained recovery/evidence proofs and candidate hashes are rechecked before unlink. An unreadable process inventory fails closed; do not bypass it when an older client is active. Coordinate any legacy writers before applying, and keep the learning producer lock during root recovery expiry. The external ledger records prepared versus completed state; it is not an undo archive. Existing immutable workers require a separately verified matched release before this entry point is deployed; it is not automatically enabled by importing the source.

## Migration generations

Migration backups are recovery generations, not an indefinite archive of every distinct historical byte. `PWN::Migrate.prune_backups` stays duplicate-only until an operator explicitly authorizes historical expiry. Its optional `expire_history: true` argument or private `~/.pwn/backup/.retention-policy.json` enables generation retention:

```json
{"version":1,"expire_history":true,"keep":3,"pins":[]}
```

`keep` cannot be less than three. `pins` contains exact timestamp generation directory names. Current structured evidence paths and prepared/interrupted or explicitly pinned maintenance records also retain their referenced generations. Quoted directory inventories and historical prose are not evidence dependencies. No logs, metrics, or historical learning versions are copied aside merely because their bytes are unique.

Before expiry, the newest retained point must cover every existing current migration-owned input path, and current encrypted configuration and decryptor bytes must match retained recovery copies. Every retained and expiring payload is hashed, current inputs and references are rechecked, symlinks are rejected, and deletion shares the snapshot producer's permanent `.retention.lock`. The ordinary maintenance transaction supplies its own maintenance lock and cooperative work admission. Manual backup-only calls must also coordinate live writers before apply. Default automatic batches consider at most ten older generations; exhausted admission defers expiry rather than weakening protection.

The single mode-0600 `.retention-manifest.json.gz` contains prepared/committed inventories and expiry names, not a second payload tree. Older unpinned versions are permanently expired: that manifest is an audit record, not an undo payload. Incomplete historical snapshots are never retrospectively certified complete. Their extant payloads can be verified for bounded recovery; the newly produced complete snapshot establishes current coverage. Restore by **copying only migration-owned paths**, not overlaying an entire old home, and never edit hardlinked backup bytes in place. Keep explicit pins for any recovery boundary needed during an active migration.

Scheduled retention is called by the managed v10 `SessionCleanup.maintain` helper through PWN's internal cron worker. No native scheduler or systemd installation is needed. Use `PWN::Migrate.prune_backups(dry_run: true)` for a strictly backup-only preview; do not invoke full session maintenance to test backup expiry. When no generation can expire, this preview avoids scanning evidence bodies and reports `evidence_scan: not_needed_no_expiry`; it is not a fresh payload-integrity audit.

An isolated maintenance release may coexist with older interactive clients: run the worker from the release's immutable `lib` load path, verify source/release/live-helper SHA-256 equality, and leave the active gem and clients untouched. The cron helper does not retrofit methods into those clients. A later normal application upgrade is separate from this scoped maintenance deployment.
