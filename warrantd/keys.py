"""Role key identities and the owner-published trust root (§1.1, §1.4).

Four separable roles: criteria owner, producer, mint, consumer. Each role
gets its own Ed25519 identity; the owner publishes a trust root document
naming which key fingerprint holds which role, and which roles a party
may NOT hold (§1.1 separability). The producer key is never authorized to
sign warrants; that restriction is enforced at verification, not by
convention (§1.3, §12.7).
"""

from __future__ import annotations

import os
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

from .canon import digest

ROLES = ("owner", "producer", "mint", "consumer")


def generate_keypair() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_pem(priv: Ed25519PrivateKey) -> str:
    return priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def private_pem(priv: Ed25519PrivateKey) -> str:
    return priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()


def load_public(pem: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("expected an Ed25519 public key")
    return key


def load_private(pem: str) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("expected an Ed25519 private key")
    return key


def fingerprint(pub_pem: str) -> str:
    return digest(pub_pem.encode())


def public_identity(pem: str) -> bytes:
    return load_public(pem).public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)


def make_trust_root(role_pub_pems: dict) -> dict:
    """Owner-published trust root: role -> {key_id, public_pem}, plus the
    §1.1 exclusivity register (which roles each identity may not hold)."""
    entries = {}
    for role, pem in role_pub_pems.items():
        if role not in ROLES:
            raise ValueError(f"unknown role {role}")
        load_public(pem)
        if any(public_identity(e["public_pem"]) == public_identity(pem)
               for e in entries.values()):
            raise ValueError("roles must use distinct key identities")
        entries[role] = {"key_id": fingerprint(pem), "public_pem": pem}
    forbidden = {role: [r for r in ROLES if r != role] for role in entries}
    doc = {"record_type": "TrustRoot", "version": 1,
           "roles": entries, "may_not_hold": forbidden}
    doc["trust_root_digest"] = digest({k: v for k, v in doc.items()
                                       if k != "trust_root_digest"})
    return doc


class KeyStore:
    """Filesystem custody: each role's private key in its own directory.
    The mint's signing key directory is distinct from producer-readable
    space (§2.1/§12.6 slice: the check runner is never handed this path)."""

    def __init__(self, root: str):
        self.root = root
        os.makedirs(root, exist_ok=True)

    def write_private(self, role: str, priv: Ed25519PrivateKey) -> str:
        if role not in ROLES:
            raise ValueError("unknown key role")
        d = os.path.join(self.root, role)
        os.makedirs(d, mode=0o700, exist_ok=True)
        p = os.path.join(d, "private.pem")
        fd, tmp = tempfile.mkstemp(prefix=".private-", dir=d)
        try:
            with os.fdopen(fd, "w", encoding="ascii") as fh:
                fh.write(private_pem(priv))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, p)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return p

    def read_private(self, role: str) -> Ed25519PrivateKey:
        if role not in ROLES:
            raise ValueError("unknown key role")
        with open(os.path.join(self.root, role, "private.pem")) as fh:
            return load_private(fh.read())
