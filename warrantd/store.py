"""Durable digest-addressed records; the storage directory must be trusted.

Locks coordinate cooperating local writers. Merkle roots cannot authenticate
a full rewrite or detect suffix deletion without an external checkpoint.
"""
from __future__ import annotations
from contextlib import contextmanager
import copy
import hashlib
import json
import os
import re
import tempfile
import threading
from .canon import canonical_bytes, digest, strict_loads

RECORD_TYPES = {"TrustRoot", "AuthorityGrant", "Criteria", "Approval", "Submission",
                "ExecutionRecord", "EvidenceManifest", "Outcome", "WarrantEnvelope",
                "Rejection", "Revocation"}
DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _h(b):
    return hashlib.sha256(b).digest()


def _root(leaves):
    level = list(leaves)
    if not level:
        return _h(b"")
    while len(level) > 1:
        nxt = [_h(level[i] + level[i+1]) for i in range(0, len(level)-1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


class StoreIntegrityError(Exception):
    """Records fail schema, digest, sequence, or Merkle verification."""


@contextmanager
def _file_lock(path):
    with open(path, "a+b") as lock:
        lock.seek(0, os.SEEK_END)
        if lock.tell() == 0:
            lock.write(b"0")
            lock.flush()
        lock.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            lock.seek(0)
            if os.name == "nt":
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


class RecordGraph:
    def __init__(self, root_dir):
        self.dir = root_dir
        os.makedirs(root_dir, mode=0o700, exist_ok=True)
        self.path = os.path.join(root_dir, "records.jsonl")
        self._lock = threading.RLock()
        self._records, self._leaves = [], []
        with self._locked():
            self._reload()

    @contextmanager
    def _locked(self):
        with self._lock, _file_lock(self.path + ".lock"):
            yield

    @staticmethod
    def _validate_entry(entry, leaves):
        if not isinstance(entry, dict) or set(entry) != {"record", "record_digest", "seq", "merkle_root"}:
            raise StoreIntegrityError("invalid graph entry schema")
        record = entry["record"]
        if not isinstance(record, dict) or record.get("record_type") not in RECORD_TYPES:
            raise StoreIntegrityError("invalid record type")
        if type(entry["seq"]) is not int or entry["seq"] != len(leaves)+1:
            raise StoreIntegrityError("invalid record sequence")
        if entry["record_digest"] != digest(record):
            raise StoreIntegrityError("record digest mismatch")
        leaves.append(_h(canonical_bytes(record)))
        if entry["merkle_root"] != _root(leaves).hex():
            raise StoreIntegrityError("Merkle root mismatch")

    def _reload(self):
        if not os.path.exists(self.path):
            self._records, self._leaves = [], []
            return
        with open(self.path, "rb") as fh:
            raw = fh.read()
        entries, leaves = [], []
        offset, truncate_at = 0, None
        lines = raw.splitlines(keepends=True)
        for i, line in enumerate(lines):
            try:
                entry = strict_loads(line)
            except json.JSONDecodeError as exc:
                if i == len(lines)-1 and not line.endswith(b"\n"):
                    truncate_at = offset
                    break
                raise StoreIntegrityError(f"invalid JSON at line {i+1}") from exc
            except (ValueError, UnicodeError) as exc:
                raise StoreIntegrityError(f"invalid JSON at line {i+1}") from exc
            try:
                self._validate_entry(entry, leaves)
            except (TypeError, ValueError) as exc:
                raise StoreIntegrityError(f"invalid record at line {i+1}") from exc
            entries.append(entry)
            offset += len(line)
        # Repair only after all complete records have passed verification.
        if truncate_at is not None or (raw and not raw.endswith(b"\n")):
            with open(self.path, "r+b") as fh:
                if truncate_at is not None:
                    fh.truncate(truncate_at)
                else:
                    fh.seek(0, os.SEEK_END)
                    fh.write(b"\n")
                fh.flush()
                os.fsync(fh.fileno())
        self._records, self._leaves = entries, leaves

    def append(self, record, *, unique_field=None):
        record = strict_loads(canonical_bytes(record))
        if not isinstance(record, dict) or record.get("record_type") not in RECORD_TYPES:
            raise ValueError("unknown record type")
        rdigest = digest(record)
        with self._locked():
            self._reload()
            if unique_field and any(
                e["record"]["record_type"] == record["record_type"]
                and e["record"].get(unique_field) == record[unique_field]
                for e in self._records
            ):
                raise ValueError(f"duplicate {unique_field}")
            leaves = self._leaves + [_h(canonical_bytes(record))]
            entry = {"record": record, "record_digest": rdigest,
                     "seq": len(leaves), "merkle_root": _root(leaves).hex()}
            with open(self.path, "a+b") as fh:
                fh.seek(0, os.SEEK_END)
                start = fh.tell()
                try:
                    fh.write(canonical_bytes(entry) + b"\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                except OSError:
                    fh.seek(start)
                    fh.truncate()
                    fh.flush()
                    raise
            self._records.append(entry)
            self._leaves = leaves
        return rdigest

    def get(self, rdigest):
        with self._locked():
            self._reload()
            for entry in self._records:
                if entry["record_digest"] == rdigest:
                    return copy.deepcopy(entry["record"])
        raise KeyError(rdigest)

    def by_type(self, rtype):
        with self._locked():
            self._reload()
            return [copy.deepcopy(e["record"]) for e in self._records
                    if e["record"]["record_type"] == rtype]

    def verify_chain(self):
        try:
            with self._locked():
                self._reload()
            return True
        except StoreIntegrityError:
            return False


class PayloadStore:
    def __init__(self, root_dir):
        self.dir = root_dir
        os.makedirs(root_dir, mode=0o700, exist_ok=True)

    def _path(self, d):
        if not isinstance(d, str) or not DIGEST_PATTERN.fullmatch(d):
            raise ValueError("expected a SHA-256 digest")
        return os.path.join(self.dir, d[7:])

    def snapshot(self, data):
        d = digest(data)
        path = self._path(d)
        if os.path.exists(path):
            self.read(d)
            return d
        fd, tmp = tempfile.mkstemp(prefix=".snapshot-", dir=self.dir)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return d

    def read(self, d):
        with open(self._path(d), "rb") as fh:
            data = fh.read()
        if digest(data) != d:
            raise ValueError("snapshot digest mismatch")
        return data
