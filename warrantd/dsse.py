"""DSSE envelope signing and strict verification (§9).

§9.1 versioned schema + signing format; §9.2 the signature covers the
complete serialized statement via DSSE PAE; §9.3 verifiers parse the
preserved signed bytes strictly — unknown envelope fields, missing
fields, or non-canonical payloads are rejected, and the payload used
after verification is exactly the signed bytes, never a re-serialization.
"""

from __future__ import annotations

import base64
import json

from .canon import canonical_bytes, strict_loads

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

PAYLOAD_TYPE = "application/vnd.warrantd.warrant+json; schema=1"
ENVELOPE_FIELDS = {"payload", "payloadType", "signatures"}
SIGNATURE_FIELDS = {"keyid", "sig"}


class EnvelopeError(Exception):
    pass


def _pae(payload_type: str, payload: bytes) -> bytes:
    return b"DSSEv1 %d %s %d %s" % (len(payload_type.encode()),
                                    payload_type.encode(),
                                    len(payload), payload)


def sign_envelope(payload: bytes, key: Ed25519PrivateKey, keyid: str) -> dict:
    sig = key.sign(_pae(PAYLOAD_TYPE, payload))
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [{"keyid": keyid, "sig": base64.b64encode(sig).decode()}],
    }


def verify_envelope(envelope: dict, pub: Ed25519PublicKey, expect_keyid: str) -> bytes:
    """Strict parse + verify; returns the exact signed payload bytes."""
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
        raise EnvelopeError("envelope fields do not match the v1 schema exactly")
    if envelope["payloadType"] != PAYLOAD_TYPE:
        raise EnvelopeError(f"unsupported payloadType {envelope['payloadType']!r}")
    sigs = envelope["signatures"]
    if not isinstance(sigs, list) or len(sigs) != 1 \
            or not isinstance(sigs[0], dict) or set(sigs[0]) != SIGNATURE_FIELDS:
        raise EnvelopeError("signature block does not match the v1 schema")
    if sigs[0]["keyid"] != expect_keyid:
        raise EnvelopeError("signature keyid is not the expected signer")
    if not isinstance(envelope["payload"], str) or not isinstance(sigs[0]["sig"], str):
        raise EnvelopeError("payload and signature must be base64 strings")
    try:
        payload = base64.b64decode(envelope["payload"], validate=True)
        sig = base64.b64decode(sigs[0]["sig"], validate=True)
    except Exception as exc:
        raise EnvelopeError(f"invalid base64: {exc}") from exc
    try:
        pub.verify(sig, _pae(PAYLOAD_TYPE, payload))
    except InvalidSignature as exc:
        raise EnvelopeError("signature verification failed") from exc
    # payload must be strict JSON (object) — parsed only after verification
    try:
        obj = strict_loads(payload.decode("utf-8"))
        if canonical_bytes(obj) != payload:
            raise ValueError("payload is not canonical warrantd JSON")
    except Exception as exc:
        raise EnvelopeError(f"signed payload is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise EnvelopeError("signed payload is not a JSON object")
    return payload
