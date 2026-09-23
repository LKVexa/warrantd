"""Core-section tests (§1-§11 slices)."""

import base64
from pathlib import Path
import unittest

from warrantd.canon import canonical_bytes, digest
from warrantd import dsse
from warrantd.keys import (fingerprint, generate_keypair, make_trust_root,
                           public_pem)
from warrantd.mint import MintError
from warrantd.store import RecordGraph, PayloadStore

from tests.harness import GOLDEN, System


class Section1Authority(unittest.TestCase):
    def test_1_1_four_roles_and_exclusivity(self):
        s = System()
        tr = s.trust_root
        self.assertEqual(set(tr["roles"]), {"owner", "producer", "mint", "consumer"})
        for role, others in tr["may_not_hold"].items():
            self.assertNotIn(role, others)
            self.assertEqual(len(others), 3)

    def test_1_5_warrant_cannot_supply_its_own_authorization(self):
        s = System()
        res = s.golden_run()
        cfg = s.trust_config(expectation={
            "repository": "repo-alpha", "work_item": "WI-1",
            "criteria_digest": s.criteria_digest,
            "acceptance_mode": "approval_required", "approvals": []})
        rc, out = s.run_independent_verifier(GOLDEN, res["envelope"], cfg)
        self.assertEqual(rc, 1)
        self.assertIn("§1.5", out["reason"])
        # a separate owner Approval record satisfies the second condition
        import json
        wid = json.loads(base64.b64decode(res["envelope"]["payload"]))["warrant_id"]
        cfg["expectation"]["approvals"] = [{"role": "owner",
                                           "approves_warrant": wid}]
        rc2, out2 = s.run_independent_verifier(GOLDEN, res["envelope"], cfg)
        self.assertEqual(rc2, 0, out2)


class Section3Criteria(unittest.TestCase):
    def test_3_5_no_owner_approval_no_evaluation(self):
        s = System()
        crit = dict(s.criteria, version="9.9.9")
        cd = digest(crit)
        s.graph.append(crit)                      # frozen but NOT approved
        m = s.manifest(GOLDEN, "req-noappr", criteria_digest=cd)
        s.mint.submit(m, GOLDEN)
        with self.assertRaises(MintError):
            s.mint.evaluate(m)


class Section5Submission(unittest.TestCase):
    def test_5_4_digest_mismatch_rejected(self):
        s = System()
        m = s.manifest(GOLDEN, "req-x")
        with self.assertRaises(MintError):
            s.mint.submit(dict(m, claimed_digest="sha256:" + "0" * 64), GOLDEN)

    def test_8_5_duplicate_request_id_rejected(self):
        s = System()
        m = s.manifest(GOLDEN, "req-dup")
        s.mint.submit(m, GOLDEN)
        with self.assertRaises(MintError):
            s.mint.submit(m, GOLDEN)


class Section9Dsse(unittest.TestCase):
    def test_9_2_signature_covers_complete_statement(self):
        priv = generate_keypair()
        kid = fingerprint(public_pem(priv))
        payload = canonical_bytes({"a": 1})
        env = dsse.sign_envelope(payload, priv, kid)
        self.assertEqual(dsse.verify_envelope(env, priv.public_key(), kid),
                         payload)

    def test_9_3_strict_parsing(self):
        priv = generate_keypair()
        kid = fingerprint(public_pem(priv))
        env = dsse.sign_envelope(canonical_bytes({"a": 1}), priv, kid)
        with self.assertRaises(dsse.EnvelopeError):     # unknown field
            dsse.verify_envelope(dict(env, extra=1), priv.public_key(), kid)
        with self.assertRaises(dsse.EnvelopeError):     # wrong keyid
            dsse.verify_envelope(env, priv.public_key(), "sha256:" + "1" * 64)
        bad = dict(env)
        bad["payload"] = base64.b64encode(b"not json").decode()
        with self.assertRaises(dsse.EnvelopeError):     # sig fails on new payload
            dsse.verify_envelope(bad, priv.public_key(), kid)


class Section10Graph(unittest.TestCase):
    def test_10_1_unknown_record_types_rejected(self):
        import tempfile
        g = RecordGraph(tempfile.mkdtemp())
        with self.assertRaises(ValueError):
            g.append({"record_type": "MadeUpThing"})

    def test_10_6_append_only_chain_detects_tampering(self):
        import json, tempfile, os
        d = tempfile.mkdtemp()
        g = RecordGraph(d)
        g.append({"record_type": "Approval", "role": "owner", "approves": "x"})
        g.append({"record_type": "Revocation", "revokes": "y"})
        self.assertTrue(g.verify_chain())
        # tamper with the first record on disk and reload
        path = os.path.join(d, "records.jsonl")
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        e = json.loads(lines[0])
        e["record"]["approves"] = "z"
        lines[0] = json.dumps(e, sort_keys=True)
        Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
        # 0.1.1 strengthens §10.6: tampering is refused at load itself
        # (StoreIntegrityError), not merely reported by verify_chain().
        from warrantd.store import StoreIntegrityError
        with self.assertRaises(StoreIntegrityError):
            RecordGraph(d)


class SnapshotStore(unittest.TestCase):
    def test_5_3_content_addressed_roundtrip(self):
        import tempfile
        p = PayloadStore(tempfile.mkdtemp())
        d = p.snapshot(GOLDEN)
        self.assertEqual(p.read(d), GOLDEN)


if __name__ == "__main__":
    unittest.main()


class MaintenanceRepairs011(unittest.TestCase):
    """0.1.1-partial repairs: store recovery/verification, durable
    idempotency, producer identifier contract, verifier robustness."""

    def setUp(self):
        import tempfile
        self.t = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.t)

    def test_store_crash_tail_recovered(self):
        import os
        from warrantd.store import RecordGraph
        g = RecordGraph(os.path.join(self.t, "g"))
        g.append({"record_type": "Criteria", "x": 1})
        with open(g.path, "a") as fh:
            fh.write('{"record":{"record_type":"Crit')  # torn tail
        g2 = RecordGraph(os.path.join(self.t, "g"))
        self.assertEqual(len(g2.by_type("Criteria")), 1)
        self.assertTrue(g2.verify_chain())
        g3 = RecordGraph(os.path.join(self.t, "g"))  # clean after truncate
        self.assertEqual(len(g3.by_type("Criteria")), 1)

    def test_store_tamper_detected_at_load(self):
        import os, json
        from warrantd.store import RecordGraph, StoreIntegrityError
        g = RecordGraph(os.path.join(self.t, "g"))
        g.append({"record_type": "Criteria", "x": 1})
        g.append({"record_type": "Approval", "y": 2})
        lines = Path(g.path).read_text(encoding="utf-8").splitlines()
        e0 = json.loads(lines[0]); e0["record"]["x"] = 999
        lines[0] = json.dumps(e0, sort_keys=True, ensure_ascii=False)
        Path(g.path).write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaises(StoreIntegrityError):
            RecordGraph(os.path.join(self.t, "g"))

    def test_store_midfile_corruption_rejected(self):
        import os
        from warrantd.store import RecordGraph, StoreIntegrityError
        g = RecordGraph(os.path.join(self.t, "g"))
        g.append({"record_type": "Criteria", "x": 1})
        g.append({"record_type": "Approval", "y": 2})
        lines = Path(g.path).read_bytes().splitlines(keepends=True)
        lines[0] = b'{"record": BROKEN\n'
        Path(g.path).write_bytes(b"".join(lines))
        with self.assertRaises(StoreIntegrityError):
            RecordGraph(os.path.join(self.t, "g"))

    def _mint(self, graphdir):
        import os
        from warrantd.keys import KeyStore, generate_keypair, public_pem
        from warrantd.store import RecordGraph, PayloadStore
        from warrantd.mint import Mint
        ks = KeyStore(os.path.join(self.t, "ks"))
        mk = generate_keypair(); ks.write_private("mint", mk)
        graph = RecordGraph(os.path.join(self.t, graphdir))
        ps = PayloadStore(os.path.join(self.t, "ps"))
        return graph, ps, ks, public_pem(mk)

    def test_idempotency_survives_restart(self):
        import os
        from warrantd.canon import digest
        from warrantd.mint import Mint, MintError
        from warrantd.store import RecordGraph, PayloadStore
        graph, ps, ks, mpub = self._mint("g")
        crit = {"record_type": "Criteria", "version": 1,
                "required_checks": [{"check_id": "c1", "kind": "max_bytes",
                                     "limit": 100}]}
        cd = graph.append(crit)
        man = {"record_type": "Submission", "repository": "r",
               "work_item": "w", "claimed_digest": digest(b"hello"),
               "criteria_digest": cd, "request_id": "req-1",
               "producer": "acme"}
        Mint(graph, ps, ks, mpub, "g").submit(dict(man), b"hello")
        graph2 = RecordGraph(graph.dir)          # process restart
        m2 = Mint(graph2, ps, ks, mpub, "g")
        with self.assertRaises(MintError):
            m2.submit(dict(man), b"hello")

    def test_producer_name_containing_approved_is_legal(self):
        from warrantd.canon import digest
        from warrantd.mint import Mint, MintError
        graph, ps, ks, mpub = self._mint("g")
        cd = graph.append({"record_type": "Criteria", "version": 1,
                           "required_checks": []})
        man = {"record_type": "Submission", "repository": "r",
               "work_item": "w", "claimed_digest": digest(b"x"),
               "criteria_digest": cd, "request_id": "req-9",
               "producer": "approved-vendors-team"}
        Mint(graph, ps, ks, mpub, "g").submit(dict(man), b"x")  # no raise
        man2 = dict(man, request_id="req-10", producer={"i": "am a dict"})
        with self.assertRaises(MintError):
            Mint(graph, ps, ks, mpub, "g").submit(man2, b"x")

    def test_incomplete_signed_statement_rejected_cleanly(self):
        import json
        from warrantd import dsse, verify as V
        from warrantd.keys import (generate_keypair, public_pem,
                                   make_trust_root, fingerprint)
        from warrantd.canon import digest
        mk = generate_keypair(); mpub = public_pem(mk)
        tr = make_trust_root({"owner": public_pem(generate_keypair()),
                              "producer": public_pem(generate_keypair()),
                              "mint": mpub,
                              "consumer": public_pem(generate_keypair())})
        grant = {"record_type": "AuthorityGrant",
                 "authorized_issuer_keyid": fingerprint(mpub),
                 "repository_scope": ["r"], "permitted_criteria": ["c"]}
        cfg = {"trust_root": tr, "authority_grant": grant,
               "authority_grant_digest": digest(grant)}
        stmt = {"schema": "warrantd/warrant/v1", "verdict": "PASS",
                "authority_grant_digest": digest(grant)}
        env = dsse.sign_envelope(
            json.dumps(stmt, sort_keys=True, separators=(",", ":")).encode(),
            mk, fingerprint(mpub))
        with self.assertRaises(V.Reject) as ctx:
            V.verify(b"x", env, cfg, {"repository": "r", "work_item": "w",
                                      "criteria_digest": "c"})
        self.assertIn("missing required bindings", str(ctx.exception))

    def test_tampered_trust_root_rejected(self):
        import json
        from warrantd import dsse, verify as V
        from warrantd.keys import (generate_keypair, public_pem,
                                   make_trust_root, fingerprint)
        mk = generate_keypair(); mpub = public_pem(mk)
        tr = make_trust_root({"mint": mpub})
        evil = generate_keypair()
        tr["roles"]["mint"]["public_pem"] = public_pem(evil)  # swap, no re-digest
        cfg = {"trust_root": tr, "authority_grant": {},
               "authority_grant_digest": "x"}
        with self.assertRaises(V.Reject) as ctx:
            V.verify(b"x", {"payload": "", "payloadType": "",
                            "signatures": []}, cfg, {})
        self.assertIn("§12.12", str(ctx.exception))
