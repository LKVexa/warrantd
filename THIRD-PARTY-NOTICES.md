# Third-party notices — JY-GRP01-P001

## merklecpp (GitHub Junkyard donor — reused fit)

- Donor car: `D:\desktop\GitHub Junkyard\merklecpp` (working-tree clone).
- License: MIT (Microsoft Corporation); full text in
  `warrantd/LICENSE.merklecpp.txt`.
- Reuse: the append-only record graph (`warrantd/store.py`) uses the same
  Merkle scheme proven in job JY-S021-P001 from this donor (SHA-256
  leaves, internal node = sha256(left||right), single-leaf root == leaf,
  odd-node carry-up). This is a recorded fit reuse, not a new pull.

## Host libraries

- `cryptography` (Python, Apache-2.0/BSD dual license) supplies Ed25519
  signing — a build-environment dependency, not a vendored part.

## Negative retrieval results (for the ledger)

No DSSE, in-toto, or sigstore Python donor exists in the yard (searched:
dsse, in-toto, sigstore, attestation, supply chain attestation signing) —
`build-new: DSSE envelope + warrant pipeline (searched: dsse, in-toto,
sigstore, attestation)`.
