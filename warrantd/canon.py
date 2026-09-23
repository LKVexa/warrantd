"""Canonical JSON bytes and digest addressing (shared by every record)."""

from __future__ import annotations

import hashlib
import json

DIGEST_ALG = "sha256"


def canonical_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def strict_loads(data):
    """Reject ambiguous duplicate keys and non-standard JSON constants."""
    def object_pairs(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError(f"duplicate JSON key: {key}")
            obj[key] = value
        return obj

    def invalid_constant(value):
        raise ValueError(f"non-finite JSON number: {value}")

    return json.loads(data, object_pairs_hook=object_pairs,
                      parse_constant=invalid_constant)


def digest(obj_or_bytes) -> str:
    b = obj_or_bytes if isinstance(obj_or_bytes, (bytes, bytearray)) \
        else canonical_bytes(obj_or_bytes)
    return f"{DIGEST_ALG}:{hashlib.sha256(b).hexdigest()}"


def digest_bytes_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()
