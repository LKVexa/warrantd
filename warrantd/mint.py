"""The mint: intake, frozen criteria, fresh-sandbox evaluation, outcome
minting, and DSSE warrant signing (§2-§9).

Slices implemented (partial candidate; the rest is documented BLOCKED):
- §3 criteria freeze: a Criteria record is immutable and digest-addressed;
  it names required checks and the approved check-suite digest; changes
  are new versions; evaluation requires a separate owner Approval record
  that references the criteria digest (never a field inside the warrant).
- §5 submission integrity: manifest with claimed digest; payload
  snapshotted content-addressed before admission; digest mismatch is
  rejected before any evaluation.
- §2.4/§6: each attempt runs the owner-controlled checks in a fresh
  temporary sandbox directory with a wall-clock limit, under the mint
  process identity, with the artifact bytes taken from the snapshot (not
  from the producer's path). The in-process-runner limitation (§2.1 full
  service separation, network isolation) is a recorded limitation, not a
  hidden one.
- §4 check integrity: checks come from the frozen criteria (owner side),
  never from the submitted artifact; the expected-check inventory is
  compared against what actually ran (§4.3); a check the artifact deleted
  or replaced fails the digest comparison (§4.2).
- §7 evidence custody: mint-generated evidence is labeled by origin and
  bound into the warrant through an EvidenceManifest digest (§7.4).
- §8 outcomes: PASS only when every required check ran and passed;
  failures create Rejection records; crashes/timeouts are INDETERMINATE
  and never yield a warrant (§8.4, §12.10); publication happens only
  after the evidence and outcome records are durably appended (§8.6).
- §9 signing: the warrant statement is signed complete via DSSE with the
  mint's key; the §9.4 minimum bindings are all present.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import uuid

from .canon import canonical_bytes, digest
from . import dsse
from .keys import KeyStore, fingerprint
from .store import PayloadStore, RecordGraph, DIGEST_PATTERN
from .policy import validate_grant

CHECK_TIMEOUT_S = 30
MANIFEST_FIELDS = {"record_type", "repository", "work_item", "claimed_digest",
                   "criteria_digest", "request_id", "producer"}


def _validate_manifest(manifest):
    if not isinstance(manifest, dict) or set(manifest) != MANIFEST_FIELDS \
            or manifest["record_type"] != "Submission":
        raise MintError("submission manifest fields do not match the schema (§5.1)")
    if not all(isinstance(v, str) and v.strip() for v in manifest.values()):
        raise MintError("submission fields must be non-empty strings")
    for field in ("claimed_digest", "criteria_digest"):
        if not DIGEST_PATTERN.fullmatch(manifest[field]):
            raise MintError(f"invalid {field}")


class MintError(Exception):
    pass


class Mint:
    def __init__(self, graph: RecordGraph, payloads: PayloadStore,
                 keystore: KeyStore, mint_pub_pem: str, grant_digest: str):
        self.graph = graph
        self.payloads = payloads
        self.keystore = keystore
        self.mint_keyid = fingerprint(mint_pub_pem)
        self.grant_digest = grant_digest
        # §8.5 idempotency must survive restart: rebuild from the durable
        # record graph, not an in-memory set alone (0.1.1).
        self._used_request_ids = {s.get("request_id")
                                  for s in graph.by_type("Submission")}

    # ---------------- intake (§5) -------------------------------------
    def submit(self, manifest: dict, payload: bytes) -> str:
        _validate_manifest(manifest)
        required = {"record_type", "repository", "work_item", "claimed_digest",
                    "criteria_digest", "request_id", "producer"}
        if set(manifest) != required or manifest["record_type"] != "Submission":
            raise MintError("submission manifest fields do not match the schema (§5.1)")
        if not isinstance(manifest.get("producer"), str) or \
                not manifest["producer"].strip():
            # §1.5/§7.3: producer is an identifier only; structured content
            # (dicts/lists that could smuggle approval-shaped records) is
            # rejected. The old substring heuristic falsely rejected
            # legitimate producer names containing "approved" (0.1.1).
            raise MintError("producer must be a plain non-empty string "
                            "identifier (§1.5/§7.3)")
        if manifest["request_id"] in self._used_request_ids:
            raise MintError("duplicate request_id (§8.5 idempotency)")
        actual = digest(payload)
        if actual != manifest["claimed_digest"]:
            raise MintError(
                f"digest mismatch: claimed {manifest['claimed_digest']}, actual {actual} (§5.4)")
        # criteria must resolve from the owner store, not from the producer
        criteria = self.graph.get(manifest["criteria_digest"])
        if criteria.get("record_type") != "Criteria":
            raise MintError("criteria_digest does not resolve to a Criteria record")
        snap = self.payloads.snapshot(payload)          # §5.3 snapshot
        try:
            self.graph.append(dict(manifest, snapshot_digest=snap), unique_field="request_id")
        except ValueError as exc:
            raise MintError(str(exc)) from exc
        self._used_request_ids.add(manifest["request_id"])
        return snap

    # ---------------- evaluation (§2.4, §4, §6) -----------------------
    def _run_checks(self, criteria: dict, snapshot_digest: str, attempt_id: str):
        payload = self.payloads.read(snapshot_digest)   # evaluated bytes = snapshot (§12.3)
        results, observations = [], []
        started = time.time()
        with tempfile.TemporaryDirectory(prefix=f"attempt-{attempt_id[:8]}-") as sandbox:
            artifact_path = os.path.join(sandbox, "artifact.bin")
            with open(artifact_path, "wb") as fh:
                fh.write(payload)
            for check in criteria["required_checks"]:
                cid = check["check_id"]
                kind = check["kind"]
                if kind == "digest_equals":
                    ok = digest(payload) == check["expected_digest"]
                    results.append({"check_id": cid, "ran": True,
                                    "result": "pass" if ok else "fail",
                                    "origin": "mint"})
                elif kind == "max_bytes":
                    ok = len(payload) <= check["limit"]
                    results.append({"check_id": cid, "ran": True,
                                    "result": "pass" if ok else "fail",
                                    "origin": "mint"})
                elif kind == "script":
                    # Owner-controlled script text frozen in the criteria
                    # (§4.1); its digest is re-verified before running
                    # (§4.2) — an artifact cannot replace it.
                    script = check["script"]
                    if digest(script.encode()) != check["script_digest"]:
                        results.append({"check_id": cid, "ran": False,
                                        "result": "error",
                                        "error": "check script digest mismatch (§4.2)",
                                        "origin": "mint"})
                        continue
                    try:
                        proc = subprocess.run(
                            [sys.executable, "-I", "-c", script, artifact_path],
                            capture_output=True, timeout=CHECK_TIMEOUT_S,
                            cwd=sandbox,
                            env={k: v for k, v in os.environ.items()
                                 if k.upper() in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP"}})
                        ok = proc.returncode == 0
                        results.append({"check_id": cid, "ran": True,
                                        "result": "pass" if ok else "fail",
                                        "origin": "mint",
                                        "stdout_digest": digest(proc.stdout),
                                        "stderr_digest": digest(proc.stderr)})
                        observations.append({"check_id": cid,
                                             "stdout": proc.stdout.decode(errors="replace")[:4096],
                                             "origin": "mint"})
                    except subprocess.TimeoutExpired:
                        results.append({"check_id": cid, "ran": True,
                                        "result": "timeout", "origin": "mint"})
                    except Exception as exc:
                        results.append({"check_id": cid, "ran": False,
                                        "result": "error", "error": str(exc),
                                        "origin": "mint"})
                else:
                    results.append({"check_id": cid, "ran": False,
                                    "result": "error",
                                    "error": f"unknown check kind {kind}",
                                    "origin": "mint"})
        return results, observations, started

    # ---------------- attempt → outcome → warrant (§6-§9) -------------
    def evaluate(self, submission_manifest: dict) -> dict:
        _validate_manifest(submission_manifest)
        admitted = [s for s in self.graph.by_type("Submission")
                    if s["request_id"] == submission_manifest["request_id"]]
        if not admitted:
            raise MintError("submission not found in the record graph")
        frozen = {k: admitted[0][k] for k in MANIFEST_FIELDS}
        if frozen != submission_manifest:
            raise MintError("evaluation manifest differs from the admitted submission")
        submission_manifest = frozen
        criteria = self.graph.get(submission_manifest["criteria_digest"])
        checks = criteria.get("required_checks")
        if not isinstance(checks, list) or not checks:
            raise MintError("criteria require a non-empty check inventory")
        ids = [c.get("check_id") if isinstance(c, dict) else None for c in checks]
        if not all(isinstance(cid, str) and cid for cid in ids) or len(set(ids)) != len(ids):
            raise MintError("check identifiers must be non-empty and unique")
        for check in checks:
            kind = check.get("kind")
            if kind == "max_bytes" and (type(check.get("limit")) is not int or check["limit"] < 0):
                raise MintError("max_bytes requires a non-negative integer limit")
            if kind == "digest_equals" and (not isinstance(check.get("expected_digest"), str)
                    or not DIGEST_PATTERN.fullmatch(check["expected_digest"])):
                raise MintError("digest_equals requires a SHA-256 digest")
            if kind == "script" and (not isinstance(check.get("script"), str)
                    or not isinstance(check.get("script_digest"), str)):
                raise MintError("script checks require script text and its digest")
        scope = criteria.get("scope", {})
        if scope.get("repository") != frozen["repository"] or \
                frozen["work_item"] not in scope.get("work_items", []):
            raise MintError("submission is outside criteria scope")
        # §3.5: a separate owner Approval referencing this criteria digest
        approvals = [a for a in self.graph.by_type("Approval")
                     if a.get("approves") == submission_manifest["criteria_digest"]
                     and a.get("role") == "owner"]
        if not approvals:
            raise MintError("no owner Approval record for this criteria version (§3.5)")

        snaps = [s for s in self.graph.by_type("Submission")
                 if s.get("request_id") == submission_manifest["request_id"]]
        if not snaps:
            raise MintError("submission not found in the record graph")
        # §12.3: bind evaluation to the FIRST admitted snapshot for this
        # request_id; duplicates are already rejected durably, and even a
        # forged later Submission row cannot move the evaluated bytes.
        snapshot_digest = snaps[0]["snapshot_digest"]

        attempt_id = str(uuid.uuid4())
        results, observations, started = self._run_checks(
            criteria, snapshot_digest, attempt_id)

        expected = [c["check_id"] for c in criteria["required_checks"]]
        ran = [r["check_id"] for r in results if r["ran"]]
        missing = [c for c in expected if c not in ran]          # §4.3
        any_error = any(r["result"] in ("error", "timeout") for r in results)
        all_pass = not missing and all(r["result"] == "pass" for r in results)

        execution_record = {
            "record_type": "ExecutionRecord", "attempt_id": attempt_id,
            "snapshot_digest": snapshot_digest,
            "criteria_digest": submission_manifest["criteria_digest"],
            "started_at": started, "finished_at": time.time(),
            "expected_checks": expected, "check_results": results,
            "runner": {"python": sys.version.split()[0],
                       "isolation": "fresh tempdir sandbox; in-process runner "
                                    "limitation recorded (§2 full separation BLOCKED)"},
        }
        exec_digest = self.graph.append(execution_record)

        evidence = {
            "record_type": "EvidenceManifest", "attempt_id": attempt_id,
            "entries": [{"kind": "execution_record", "digest": exec_digest,
                         "origin": "mint"}] +
                       [{"kind": "observation", "digest": digest(o),
                         "origin": o["origin"]} for o in observations],
        }
        evidence_digest = self.graph.append(evidence)

        if all_pass:
            status = "PASS"
        elif any_error or missing:
            status = "INDETERMINATE"                       # §8.3, §12.10
        else:
            status = "FAIL"

        outcome = {
            "record_type": "Outcome", "attempt_id": attempt_id,
            "status": status,
            "snapshot_digest": snapshot_digest,
            "criteria_digest": submission_manifest["criteria_digest"],
            "evidence_manifest_digest": evidence_digest,
            "missing_checks": missing,
        }
        outcome_digest = self.graph.append(outcome)        # durable before publish (§8.6)

        if status == "FAIL":
            self.graph.append({"record_type": "Rejection",
                               "attempt_id": attempt_id,
                               "outcome_digest": outcome_digest})
        if status != "PASS":
            return {"attempt_id": attempt_id, "status": status,
                    "outcome_digest": outcome_digest}      # no warrant (§8.4)

        try:
            validate_grant(self.graph.get(self.grant_digest), self.mint_keyid,
                           frozen["repository"], frozen["criteria_digest"])
        except (KeyError, ValueError) as exc:
            raise MintError(f"warrant signing not authorized: {exc}") from exc

        statement = {
            "schema": "warrantd/warrant/v1",               # §9.1
            "warrant_id": str(uuid.uuid4()),
            "attempt_id": attempt_id,
            "repository": submission_manifest["repository"],   # §9.4 bindings
            "work_item": submission_manifest["work_item"],
            "artifact_digest": snapshot_digest,
            "criteria_digest": submission_manifest["criteria_digest"],
            "authority_grant_digest": self.grant_digest,
            "evidence_manifest_digest": evidence_digest,
            "outcome_digest": outcome_digest,
            "verdict": "PASS",
            "issued_at": time.time(),
        }
        payload = canonical_bytes(statement)
        envelope = dsse.sign_envelope(payload,
                                      self.keystore.read_private("mint"),
                                      self.mint_keyid)
        self.graph.append({"record_type": "WarrantEnvelope",
                           "attempt_id": attempt_id, "envelope": envelope})
        return {"attempt_id": attempt_id, "status": "PASS",
                "outcome_digest": outcome_digest, "envelope": envelope}
