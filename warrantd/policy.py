"""Validation shared by signing and independent verification."""
import math
import time


def finite_time(value):
    return type(value) in (int, float) and math.isfinite(value)


def string_list(value):
    return isinstance(value, list) and all(isinstance(v, str) and v for v in value)


def validate_grant(grant, keyid, repository, criteria, issued_at=None):
    if not isinstance(grant, dict) or grant.get("record_type") != "AuthorityGrant":
        raise ValueError("invalid authority grant")
    if grant.get("authorized_issuer_keyid") != keyid:
        raise ValueError("grant does not authorize this signer (§1.2)")
    for field, expected in (("repository_scope", repository),
                            ("permitted_criteria", criteria),
                            ("permitted_actions", "mint_warrant")):
        values = grant.get(field)
        if not string_list(values) or expected not in values:
            raise ValueError(f"value not permitted by grant {field} (§12.8)")
    validity = grant.get("validity")
    if not isinstance(validity, dict):
        raise ValueError("grant requires validity bounds")
    start, end = validity.get("not_before"), validity.get("not_after")
    now = time.time()
    if not finite_time(start) or not finite_time(end) or not start <= now < end:
        raise ValueError("grant is expired, not yet valid, or has invalid bounds")
    if issued_at is not None and (not finite_time(issued_at)
                                  or not start <= issued_at < end or issued_at > now):
        raise ValueError("warrant issuance is outside the grant validity or in the future")
