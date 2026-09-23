"""Independent consumer verifier (§10.5, §11, §12).

Runs as a SEPARATE PROCESS (CLI) given exactly three inputs plus the
owner-published trust configuration: artifact bytes, DSSE envelope, and
an expectation policy. It resolves the AuthorityGrant from the trust
configuration it already trusts — never from the warrant (§1.2, §10.5) —
and rejects, in order: schema/signature problems (§11.1, §12.7), signer
identities that are not the authorized mint (a producer or unknown key,
§1.3), artifact digest mismatches (§11.2, §12.2), criteria or scope
outside expectations or the grant (§11.3, §12.8), and revoked warrants,
criteria, or grants (§11.4, §12.11). Exit code 0 = ACCEPT, 1 = REJECT.
"""

from __future__ import annotations

import json
import sys

from .canon import digest, strict_loads
from . import dsse
from .keys import load_public, fingerprint, public_identity
from .policy import finite_time, string_list, validate_grant
from .store import DIGEST_PATTERN


class Reject(Exception):
    pass


def verify(artifact: bytes, envelope: dict, trust_config: dict,
           expectation: dict) -> dict:
    try:
        return _verify(artifact, envelope, trust_config, expectation)
    except Reject:
        raise
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError) as exc:
        raise Reject(f"invalid verification input: {exc}") from exc


def _verify(artifact, envelope, trust_config, expectation):
    trust_root = trust_config["trust_root"]
    # §12.12 support: recompute the trust root's own digest so a locally
    # tampered trust configuration is detected before any use (0.1.1).
    body = {k: v for k, v in trust_root.items() if k != "trust_root_digest"}
    if digest(body) != trust_root.get("trust_root_digest"):
        raise Reject("trust root digest mismatch — trust configuration "
                     "tampered or corrupt (§12.12)")
    roles = trust_root["roles"]
    mint_entry = roles.get("mint")
    if not mint_entry:
        raise Reject("trust root names no mint identity")
    identities = []
    for entry in roles.values():
        load_public(entry["public_pem"])
        if entry["key_id"] != fingerprint(entry["public_pem"]):
            raise Reject("trust root key fingerprint mismatch")
        identities.append(public_identity(entry["public_pem"]))
    if len(set(identities)) != len(identities):
        raise Reject("trust root assigns the same key to multiple roles")

    # §11.1 / §12.7: signature must verify against the owner-published
    # mint key; a self-signed (producer-key) or forged envelope fails here.
    try:
        payload = dsse.verify_envelope(envelope,
                                       load_public(mint_entry["public_pem"]),
                                       mint_entry["key_id"])
    except dsse.EnvelopeError as exc:
        raise Reject(f"envelope rejected: {exc}") from exc

    statement = strict_loads(payload.decode())
    if statement.get("schema") != "warrantd/warrant/v1":
        raise Reject("unknown warrant schema version (§9.1)")
    # §9.3/§9.4: a validly signed but incomplete statement is rejected
    # cleanly, never a KeyError escaping the verifier (0.1.1).
    required = ("warrant_id", "attempt_id", "repository", "work_item",
                "artifact_digest", "criteria_digest",
                "authority_grant_digest", "evidence_manifest_digest",
                "outcome_digest", "verdict", "issued_at")
    missing = [f for f in required if f not in statement]
    if missing:
        raise Reject(f"signed statement missing required bindings "
                     f"{missing} (§9.4)")
    for field in required:
        value = statement[field]
        if field == "issued_at":
            if not finite_time(value):
                raise Reject("issued_at must be a finite timestamp")
        elif not isinstance(value, str) or not value:
            raise Reject(f"invalid signed {field}")
        elif field.endswith("_digest") and not DIGEST_PATTERN.fullmatch(value):
            raise Reject(f"invalid signed {field}")
    if statement["verdict"] != "PASS":
        raise Reject("warrant verdict is not PASS")

    # §10.5: resolve the grant from trust config, never from the warrant.
    grant = trust_config["authority_grant"]
    if digest(grant) != trust_config["authority_grant_digest"]:
        raise Reject("trust-config grant digest mismatch")
    if statement.get("authority_grant_digest") != trust_config["authority_grant_digest"]:
        raise Reject("warrant cites a different authority grant than the "
                     "one the consumer trusts (§10.5 circular authorization)")
    if grant["authorized_issuer_keyid"] != mint_entry["key_id"]:
        raise Reject("grant does not authorize this signer (§1.2)")
    validate_grant(grant, mint_entry["key_id"], statement["repository"],
                   statement["criteria_digest"], statement["issued_at"])

    # §12.8 scope: repository and criteria must fall inside the grant.
    if statement["repository"] not in grant["repository_scope"]:
        raise Reject(f"repository {statement['repository']!r} outside grant scope (§12.8)")
    if statement["criteria_digest"] not in grant["permitted_criteria"]:
        raise Reject("criteria version not permitted by the grant (§12.8)")

    # §11.2: recompute the artifact digest from the bytes in hand.
    if digest(artifact) != statement["artifact_digest"]:
        raise Reject("artifact digest mismatch (§11.2)")

    # §11.3: consumer expectations.
    if statement["repository"] != expectation["repository"]:
        raise Reject("warrant repository does not match the consuming gate (§11.3/§12.8 reuse)")
    if statement["work_item"] != expectation["work_item"]:
        raise Reject("warrant work_item does not match the consuming gate (§12.8 reuse)")
    if statement["criteria_digest"] != expectation["criteria_digest"]:
        raise Reject("criteria version does not match consumer expectations (§11.3)")

    # §11.4 / §12.11: revocation.
    revocations = trust_config.get("revocations", [])
    if not string_list(revocations):
        raise Reject("revocations must be a list of identifiers")
    revoked = set(revocations)
    for field in ("warrant_id", "criteria_digest", "authority_grant_digest"):
        if statement.get(field) in revoked:
            raise Reject(f"revoked: {field} (§12.11)")

    # §1.5: a warrant alone is acceptance only in automatic mode.
    mode = expectation.get("acceptance_mode", "automatic")
    if mode not in ("automatic", "approval_required"):
        raise Reject("unknown acceptance mode")
    if mode == "approval_required":
        approvals = expectation.get("approvals", [])
        ok = any(a.get("approves_warrant") == statement["warrant_id"]
                 and a.get("role") == "owner" for a in approvals)
        if not ok:
            raise Reject("acceptance requires a separate Approval record; "
                         "the warrant cannot supply its own authorization (§1.5)")

    return {"accepted": True, "warrant_id": statement["warrant_id"],
            "artifact_digest": statement["artifact_digest"]}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 3:
        print("usage: verify.py <artifact-file> <envelope.json> <trust-config.json>",
              file=sys.stderr)
        return 2
    try:
        with open(argv[0], "rb") as fh:
            artifact = fh.read()
        with open(argv[1], encoding="utf-8") as fh:
            envelope = strict_loads(fh.read())
        with open(argv[2], encoding="utf-8") as fh:
            cfg = strict_loads(fh.read())
        out = verify(artifact, envelope, cfg, cfg["expectation"])
    except (Reject, OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        print(json.dumps({"accepted": False, "reason": str(exc)}))
        return 1
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
