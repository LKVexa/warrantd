# Changelog — JY-GRP01-P001 warrantd boundary system

## 0.1.2a1 — 2026-09-23 (security maintenance, partial candidate)

- Bind evaluation to every admitted submission field; prohibit scope substitution.
- Copy record inputs/outputs; verify sequence, digest, schema and Merkle roots.
- Lock graph updates across cooperating local writers; enforce durable request
  uniqueness and publish in-memory append state only after a successful write.
- Recover a valid final record lacking its newline without corrupting the next append.
- Enforce grant actions and validity at signing and consumer verification.
- Reject empty/duplicate check inventories, malformed envelopes, ambiguous JSON,
  noncanonical signed payloads, unknown acceptance modes and malformed CLI input.
- Validate Ed25519 role identities, restrict key roles and snapshot digest paths,
  atomically write key files and remove inherited application secrets from checks.
- Add installable packaging, Apache 2.0 LICENSE, NOTICE and security documentation;
  preserve the MIT donor notice. Use a PEP 440 alpha version to retain partial status.

Validation: 29 inherited tests plus 19 security regression tests pass on
Windows with Python 3.12.14 and cryptography 50.0.1. A changed-suite fixture now
explicitly authorizes its criteria in the grant. See docs/AUDIT.md for limits.

Compatibility: existing valid graph records retain their format. Invalid grant
policies, ambiguous JSON, and metadata substitutions previously accepted are
now rejected. Production isolation remains unimplemented.

## 0.1.1-partial — 2026-09-14 (maintenance candidate, run-0001)
Baseline: 0.1.0-partial (build-0001, product.zip sha256 40ce41b2…6f743).
Compatible defect/security repairs only → patch increment (V-02).

- F1 store: a torn trailing line (crash tail) no longer makes the record
  graph unloadable; it is truncated to the last complete entry.
- F2 store: the Merkle chain is verified at load; a tampered or mid-file
  corrupted graph raises StoreIntegrityError instead of loading silently
  (§10.6 enforced at load).
- F3 mint: §8.5 request-id idempotency is rebuilt from the durable graph,
  so duplicates are rejected across process restarts; evaluation binds to
  the FIRST admitted snapshot (§12.3 across restarts).
- F4 mint: producer field is validated as a plain non-empty string
  identifier; the old substring heuristic falsely rejected legitimate
  producer names containing "approved".
- F5 verify: a validly signed but incomplete statement is rejected with a
  clean Reject naming the missing §9.4 bindings (previously a KeyError
  escaped the verifier).
- F6 verify: the consumer recomputes the trust root's own digest before
  use (§12.12 support); a tampered trust configuration is rejected.

Test alignment: the §10.6 tamper test now asserts the strengthened
load-time refusal. All 22 baseline tests plus 7 new repair tests pass
(29/29), including all twelve §12 boundary demonstrations.

Rollback: build-0001 preserved unchanged. No schema/data migration:
existing records.jsonl graphs load unchanged when untampered.

## 0.1.0-partial — 2026-09-14 (build-0001, first run)
Initial partial candidate covering sections §1–§12 (73 items) from the
12 source carriers.
