# warrantd

**Version 0.1.2a1 — experimental partial implementation**

warrantd admits artifact snapshots, evaluates frozen owner-controlled checks,
records their outcomes, and signs passing artifact warrants with Ed25519.
A separate consumer process verifies the signature, artifact, expected scope,
grant authorization and validity, and revocation policy.

Copyright 2026 **RUSSELL PHILIP SMITHSON**.

## Install and test

Requires Python 3.10 or later. The validated runtime is Python 3.12.14 with
cryptography 50.0.1 on Windows.

```sh
python -m venv .venv
# Activate .venv for your shell before the following commands.
python -m pip install -r requirements.txt
python -m pip install --no-deps .
python -m unittest discover -s tests -t . -v
```

The test fixture in [tests/harness.py](tests/harness.py) demonstrates construction
of separate role identities, criteria, owner approval, an authority grant,
a submission, and the independently configured consumer. Tests generate fresh
keys in temporary directories; no signing keys are distributed.

## Consumer verification

```sh
python -m warrantd.verify artifact.bin envelope.json trust-config.json
# Equivalent installed command:
warrantd-verify artifact.bin envelope.json trust-config.json
```

The trust configuration contains `trust_root`, `authority_grant`,
`authority_grant_digest`, `revocations`, and `expectation`. The expectation
names `repository`, `work_item`, `criteria_digest`, and an acceptance mode:
`automatic` or `approval_required`. Separate approvals are required for the
latter. Deliver trust configuration through an authenticated independent channel.

Output is a JSON acceptance result. Exit codes: 0 accepted, 1 rejected or
unreadable/malformed input, 2 incorrect command arguments.

## Enforced controls

- Evaluation must match every field of the durably admitted submission.
- Stored records are copied at the API boundary and validated by schema,
  sequence, record digest, and Merkle root.
- Local file locking coordinates writers and enforces unique request IDs.
- Owner criteria must contain a non-empty inventory of unique check IDs.
- Grants must permit the signer, repository, criteria, and signing action.
  Both the current time and issuance time must fall within grant validity.
- Malformed envelopes, duplicate JSON keys, non-finite numbers, noncanonical
  signed payloads, and unknown acceptance modes are rejected.
- Check subprocesses receive a restricted environment without inherited
  application secrets. Private key files are written through private temporary
  files; key roles and payload digest paths are validated.

## Security limits

This is **not a production security boundary**. Check scripts are trusted owner
code and run under the signing process's OS identity. A temporary directory
does not isolate filesystem or network access. Check output and process-tree
resources are not yet bounded. Protect storage with OS permissions and Windows
ACLs. Network-filesystem locking is unvalidated.

A Merkle chain without an external checkpoint cannot detect a complete
consistent rewrite or deletion of a complete suffix. Trust-root self-digests do
not authenticate trust configuration. Approvals and revocations depend on
trusted provisioning. See [SECURITY.md](SECURITY.md) for remaining work.

## Provenance and audit

Derived from JY-GRP01-P001, version 0.1.1-partial, maintenance run-0001.
The original inputs aggregate the twelve artifact-acceptance sections.
The provided source snapshot did not contain the source-item documents
referenced by its historical README.

See [CHANGELOG.md](CHANGELOG.md), [docs/AUDIT.md](docs/AUDIT.md), and
[docs/CHECK_RUNS.json](docs/CHECK_RUNS.json) for changes and validation.
Historical check evidence is retained separately.

## License and notice

Original project code and the September 2026 modifications are licensed under
the [Apache License 2.0](LICENSE), copyright **RUSSELL PHILIP SMITHSON**.
The Merkle construction retains its upstream MIT attribution and license.
Read [NOTICE](NOTICE) and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
