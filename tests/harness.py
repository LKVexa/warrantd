"""Golden-path fixture harness (§12.1 baseline used by every §12 test)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

from warrantd.canon import digest
from warrantd.keys import (KeyStore, generate_keypair, make_trust_root,
                           public_pem, fingerprint)
from warrantd.mint import Mint
from warrantd.store import PayloadStore, RecordGraph

GOLDEN = b"GOLDEN-ARTIFACT v1: deterministic bytes, no timestamps.\n"

CHECK_SCRIPT = (
    "import sys\n"
    "data = open(sys.argv[1], 'rb').read()\n"
    "sys.exit(0 if data.startswith(b'GOLDEN-ARTIFACT') else 1)\n"
)


class System:
    """One fully wired warrantd instance in a temp directory."""

    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="warrantd-")
        self.graph = RecordGraph(os.path.join(self.tmp, "graph"))
        self.payloads = PayloadStore(os.path.join(self.tmp, "payloads"))
        self.keys = KeyStore(os.path.join(self.tmp, "keys"))

        self.privs = {r: generate_keypair()
                      for r in ("owner", "producer", "mint", "consumer")}
        self.pubs = {r: public_pem(k) for r, k in self.privs.items()}
        for r, k in self.privs.items():
            self.keys.write_private(r, k)

        self.trust_root = make_trust_root(self.pubs)
        self.graph.append(self.trust_root)

        # §3: frozen criteria + separate owner approval
        self.criteria = {
            "record_type": "Criteria", "version": "1.0.0",
            "scope": {"repository": "repo-alpha", "work_items": ["WI-1"]},
            "required_checks": [
                {"check_id": "C1-digest", "kind": "digest_equals",
                 "expected_digest": digest(GOLDEN)},
                {"check_id": "C2-size", "kind": "max_bytes", "limit": 4096},
                {"check_id": "C3-content", "kind": "script",
                 "script": CHECK_SCRIPT,
                 "script_digest": digest(CHECK_SCRIPT.encode())},
            ],
        }
        self.criteria_digest = digest(self.criteria)
        self.graph.append(self.criteria)
        self.graph.append({"record_type": "Approval", "role": "owner",
                           "approves": self.criteria_digest,
                           "signer_keyid": fingerprint(self.pubs["owner"])})

        # §1.2: protected AuthorityGrant, resolvable independently
        self.grant = {
            "record_type": "AuthorityGrant",
            "authorized_issuer_keyid": fingerprint(self.pubs["mint"]),
            "repository_scope": ["repo-alpha"],
            "permitted_criteria": [self.criteria_digest],
            "permitted_actions": ["mint_warrant"],
            "validity": {"not_before": 0, "not_after": 2**40},
        }
        self.grant_digest = digest(self.grant)
        self.graph.append(self.grant)

        self.mint = Mint(self.graph, self.payloads, self.keys,
                         self.pubs["mint"], self.grant_digest)

    def manifest(self, payload: bytes, request_id: str,
                 repository="repo-alpha", work_item="WI-1",
                 criteria_digest=None) -> dict:
        return {"record_type": "Submission", "repository": repository,
                "work_item": work_item, "claimed_digest": digest(payload),
                "criteria_digest": criteria_digest or self.criteria_digest,
                "request_id": request_id, "producer": "producer-1"}

    def golden_run(self, request_id="req-golden") -> dict:
        m = self.manifest(GOLDEN, request_id)
        self.mint.submit(m, GOLDEN)
        return self.mint.evaluate(m)

    def trust_config(self, expectation=None, revocations=None) -> dict:
        return {
            "trust_root": self.trust_root,
            "authority_grant": self.grant,
            "authority_grant_digest": self.grant_digest,
            "revocations": revocations or [],
            "expectation": expectation or {
                "repository": "repo-alpha", "work_item": "WI-1",
                "criteria_digest": self.criteria_digest,
                "acceptance_mode": "automatic",
            },
        }

    def run_independent_verifier(self, artifact: bytes, envelope: dict,
                                 trust_config: dict):
        """§12.1 'independently configured': a separate OS process given
        only the artifact bytes, the envelope, and the trust config file;
        it has no handle to the mint's objects, keystore, or graph."""
        d = tempfile.mkdtemp(prefix="verifier-")
        art = os.path.join(d, "artifact.bin")
        env = os.path.join(d, "envelope.json")
        cfg = os.path.join(d, "trust.json")
        with open(art, "wb") as fh:
            fh.write(artifact)
        with open(env, "w") as fh:
            json.dump(envelope, fh)
        with open(cfg, "w") as fh:
            json.dump(trust_config, fh)
        pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        proc = subprocess.run(
            [sys.executable, "-m", "warrantd.verify", art, env, cfg],
            capture_output=True, text=True, timeout=30,
            cwd=pkg_root,
            env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": pkg_root})
        out = json.loads(proc.stdout) if proc.stdout.strip() else {}
        return proc.returncode, out
