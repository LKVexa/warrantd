# Audit: warrantd 0.1.2a1

Date: 2026-09-23. Source: JY-GRP01-P001 / 0.1.1-partial /
run-0001 / product. The original source directory was preserved; changes were
made in a separate delivery workspace.

## Scope and result

Reviewed all seven original Python modules and the inherited tests. Parsed
Python, JSON and packaging metadata; exercised the independent consumer CLI,
artifact signing, persistence, recovery and concurrency. This is a focused
source and regression audit, not a penetration test or production certification.

The baseline passed 29 tests. Fourteen new regression methods reproduced
defects (20 failed assertions and 4 errors, including subtests). Fixes plus
five additional security tests yield 48 passing tests.

| Finding | Repair |
| --- | --- |
| Admitted request ID could be evaluated with substituted metadata | Match all admitted fields |
| Inputs and returned records could mutate frozen criteria | Copy record values across API boundaries |
| Record digest and sequence were not validated | Verify schema, digest, sequence and Merkle root |
| Valid unterminated final row broke the next append | Validate then repair the missing newline |
| Two store handles could overwrite chain assumptions | Local cross-process file locking and reload |
| Failed writes published in-memory records | Publish only after durable append; roll back failed writes |
| Separate mint instances admitted duplicate requests | Enforce uniqueness under the storage lock |
| Grant validity and permitted actions were ignored | Enforce at signing and verification |
| Misspelled approval mode became automatic acceptance | Reject unknown modes |
| Malformed signature blocks raised uncaught exceptions | Validate nested types and return clean rejection |
| Signed duplicate/non-finite/noncanonical JSON was accepted | Strict JSON and byte-preserving canonical checks |
| Empty inventory yielded PASS | Require non-empty, unique check identifiers |
| Arbitrary key roles escaped the key root | Restrict roles; use private atomic key writes |
| Check subprocess inherited application secrets | Restrict the environment to OS/temp settings |

Additional checks cover alternate PEM encodings of the same key, expiry at
signing, CLI parsing errors, snapshot path traversal and concurrent processes.
The existing isolation test now explicitly authorizes its new check suite.

## Validation

- Windows, Python 3.12.14, cryptography 50.0.1: 48/48 tests pass.
- Wheel builds with setuptools 84.0.0.
- Python syntax, JSON, TOML, version alignment and license presence checked.
- Publication source scanned for credential patterns; generated key material,
  caches, environments and build directories excluded.
- Pinned GitHub Actions workflow covers Linux Python 3.10/3.12/3.14 and Windows
  Python 3.12. Remote CI results are separate from these local results.
- No dedicated vulnerability-database scanner was run locally.

## Unresolved design limits

See SECURITY.md. The runner shares the signer's OS identity and has filesystem
and network access. Resource ceilings, signed approval transport, HSM custody,
independent checkpoints, authenticated revocation distribution, retention,
network-filesystem behavior, and large-store performance remain outside this
maintenance release. Full graph verification on access favors correctness
over throughput.

## Reference checks

Dependency metadata was checked against
[cryptography on PyPI](https://pypi.org/project/cryptography/).
DSSE framing was checked against the
[upstream protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md).
Workflow pins resolve to the official
[checkout 6.0.2](https://github.com/actions/checkout/releases/tag/v6.0.2) and
[setup-python 6.2.0](https://github.com/actions/setup-python/releases/tag/v6.2.0)
releases.
