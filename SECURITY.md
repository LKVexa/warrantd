# Security boundary

This is an experimental partial implementation. Only trusted owners may
write the record store, configure grants and criteria, or supply check scripts.
Check scripts execute with the signing process's OS identity. A temporary
working directory and an environment allowlist do not provide OS or network
isolation. Do not run untrusted code through these checks.

Protect the complete storage and key directory with OS permissions, including
Windows ACLs. File modes alone do not establish Windows access controls.
Use a local filesystem: cross-host/network-filesystem locking is unvalidated.

Consumers must obtain trust configuration, revocations, and separate approval
records through an authenticated independent channel. A self-digest detects
inconsistent bytes; it does not authenticate a replaced trust configuration.
The local Merkle chain needs an independently stored checkpoint to detect a
complete rewrite or removal of a complete trailing sequence.

Outstanding work includes isolated signer and runner services, HSM integration,
bounded check output/process-tree resource limits, signed approval transport,
revocation distribution, retention policies, and performance testing on large
record stores. No production readiness is claimed.

Please report vulnerabilities privately through the repository's security
advisory feature when available. Do not include private keys in issues.
