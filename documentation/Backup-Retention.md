# Shared recovery backup retention

All PWN-owned recovery producers use `PWN::Backups` and the single
`~/.pwn/backup` store. The limit is **seven total generation folders**, not seven
per producer. Producer payloads and recovery receipts are grouped inside their
transaction's generation. No new adjacent learning, preference, skill or
Terminator `.bak` / `.pwnbak` files are produced.

## Producers

| Producer | Contents |
| --- | --- |
| Migrate | Exact registry-owned state paths, encrypted configuration and decryptor; verified snapshot manifest; no recursive logs/cache/backup copies |
| Learning | Learning rewrites and original evidence-migration index |
| Reward | Preference rewrite recovery |
| SkillReview / SkillConsolidation | Original skill bytes |
| PolicyEvaluation | Pinned routing-policy rollback snapshot |
| Setup | Original Terminator configuration |
| SessionCleanup | Session/layout recovery, dependency removal, continuation retirement and disposable quarantine payloads with their recovery receipts |

Immutable learning evidence, artifacts, evaluation inputs and user-requested
exports are not disposable backup generations. Device read/write backup commands,
GitHub gist exports and Jenkins-to-S3 transfer operate on operator-selected data,
not PWN's internal recovery state.

## Admission, locking and failures

The permanent `.retention.lock` serializes cooperating producers. Maintenance
acquires its maintenance lock, then the Learning writer lock, then the backup
lock. Ordinary backup producers acquire Learning before backups and never acquire
maintenance. Learning reentrancy is bound to the owning PID and thread; an
attempt to acquire Learning underneath an unowned backup transaction is rejected.
Maintenance still defers when the Learning writer is busy.

Before a new folder is admitted, oldest completed generations may be expired
to make room. That includes a capture pin that is not listed in the retention
policy and not named by current evidence. Prepared/interrupted generations,
retention-policy pins and current literal evidence references remain protected.
Malformed reference data fails closed when expiry would be needed. If those
protected folders occupy the seven-folder limit, the next producer fails before
modifying its source. Unknown legacy folders count toward capacity but are not
silently certified or expired.

Transactions publish `prepared` before payload/source changes and `complete`
only after successful return. Exceptions, interrupted/blocked results and failed
receipts leave prepared recovery. Copies are hash-verified and fsynced. Keep the
transaction open through source mutation and receipt publication. Restoring one
store does not undo all children of a maintenance operation.

Use the owning store's recovery API (`SessionCleanup.recover`,
`Learning.rollback_evidence`, skill review rollback or policy rollback) first.
`Backups.reconcile` only acknowledges recovery: it requires the exact generation,
its inspected manifest SHA-256 and explicit confirmation. It retains a pin by
default; `pinned: false` permits normal retention but does not override live
references. It does not restore payloads or declare a failed operation successful.
Never edit shared/hardlinked historical payloads in place; restore by copying.

## Upgrade and legacy relocation

Schema 12 changes the existing retention policy from three to seven, preserving
pins and other policy fields. A second migration is byte-stable. The old
`Migrate.prune_backups` entry point is a compatibility report only; it cannot run
an independent three-generation pruning policy. Retention happens at producer
admission, not via another scheduler.

`Backups.relocate_legacy(paths: ..., dry_run: true)` previews exact recognized
legacy paths. Applying requires `dry_run: false, writers_stopped: true`, owned
non-symlink sources, unchanged verified copies and no references to their old
paths. The shared generation contains an origin mapping before originals are
removed. Unknown, referenced or over-capacity inputs must be resolved explicitly,
not bypassed. Existing cleanup recovery readers remain available for legacy
ledgers. Legacy diagnostic/cache expiry is a separate explicit operation and is
not a new backup producer.

## Deployment boundary

Source changes do not upgrade installed gems, existing clients or immutable cron
releases. Deploy a matched release and restart only explicitly authorized
processes separately. Use only PWN's existing internal cron worker; no systemd,
native scheduler, live provider calls or live backup pruning is required for
fixture verification. Tests must use an isolated HOME and scratch storage.
