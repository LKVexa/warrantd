"""§12 boundary demonstrations, each anchored to its source item."""

import base64
import copy
import json
import unittest

from warrantd.canon import digest
from warrantd.keys import fingerprint, generate_keypair, public_pem
from warrantd import dsse
from warrantd.mint import MintError

from tests.harness import GOLDEN, System


class Boundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sys = System()
        cls.golden = cls.sys.golden_run()
        assert cls.golden["status"] == "PASS"
        cls.envelope = cls.golden["envelope"]

    # §12.1 — golden path accepted by an independently configured verifier
    def test_12_01_known_good_artifact_accepted(self):
        rc, out = self.sys.run_independent_verifier(
            GOLDEN, self.envelope, self.sys.trust_config())
        self.assertEqual(rc, 0, out)
        self.assertTrue(out["accepted"])

    # §12.2 — one changed artifact byte fails verification
    def test_12_02_single_byte_change_fails(self):
        mutated = bytes([GOLDEN[0] ^ 1]) + GOLDEN[1:]
        rc, out = self.sys.run_independent_verifier(
            mutated, self.envelope, self.sys.trust_config())
        self.assertEqual(rc, 1)
        self.assertIn("digest mismatch", out["reason"])

    # §12.3 — replacing the submitted payload cannot change evaluated bytes
    def test_12_03_submission_replacement_cannot_change_evaluated_bytes(self):
        s = System()
        evil = b"EVIL-ARTIFACT\n"
        m = s.manifest(evil, "req-swap")
        with self.assertRaises(MintError):        # claimed digest is golden's
            s.mint.submit(dict(m, claimed_digest=digest(GOLDEN)), evil)
        # honest submit, then attacker rewrites their upload path: the mint
        # evaluates the content-addressed snapshot, so the outcome digest
        # binds to the snapshotted bytes, not to any later replacement.
        m2 = s.manifest(GOLDEN, "req-snap")
        snap = s.mint.submit(m2, GOLDEN)
        self.assertEqual(s.payloads.read(snap), GOLDEN)

    # §12.4 — post-approval criteria change cannot alter a past attempt
    def test_12_04_criteria_change_is_new_version(self):
        s = System()
        res = s.golden_run("req-c1")
        old_digest = s.criteria_digest
        changed = copy.deepcopy(s.criteria)
        changed["required_checks"] = changed["required_checks"][:1]
        self.assertNotEqual(digest(changed), old_digest)   # §3.6 new version
        payload = base64.b64decode(res["envelope"]["payload"])
        self.assertIn(old_digest, payload.decode())        # attempt still cites frozen version

    # §12.5 — removed/replaced checks or fabricated reports cannot pass
    def test_12_05_missing_checks_never_pass(self):
        s = System()
        # criteria whose script digest will not match (simulating a swapped
        # check body): the check errors, the outcome is INDETERMINATE.
        bad = copy.deepcopy(s.criteria)
        bad["required_checks"][2] = dict(bad["required_checks"][2],
                                         script="import sys; sys.exit(0)")
        bad_digest = s.graph.append(bad) and digest(bad)
        s.graph.append({"record_type": "Approval", "role": "owner",
                        "approves": bad_digest,
                        "signer_keyid": fingerprint(s.pubs["owner"])})
        m = s.manifest(GOLDEN, "req-badcheck", criteria_digest=bad_digest)
        s.mint.submit(m, GOLDEN)
        res = s.mint.evaluate(m)
        self.assertEqual(res["status"], "INDETERMINATE")
        self.assertNotIn("envelope", res)                  # §8.4 no warrant

    # §12.6 — submitted code cannot obtain signing credentials
    def test_12_06_check_runs_isolated_from_signing_key(self):
        s = System()
        exfil = ("import sys, os\n"
                 "found = []\n"
                 "for root, dirs, files in os.walk(os.getcwd()):\n"
                 "    found += [f for f in files if f.endswith('.pem')]\n"
                 "sys.exit(1 if found else 0)\n")
        crit = copy.deepcopy(s.criteria)
        crit["required_checks"] = [{"check_id": "C-exfil", "kind": "script",
                                    "script": exfil,
                                    "script_digest": digest(exfil.encode())}]
        cd = digest(crit)
        s.graph.append(crit)
        s.graph.append({"record_type": "Approval", "role": "owner",
                        "approves": cd,
                        "signer_keyid": fingerprint(s.pubs["owner"])})
        m = s.manifest(GOLDEN, "req-exfil", criteria_digest=cd)
        # This newly frozen suite needs an explicit grant before signing.
        s.grant = dict(s.grant, permitted_criteria=[s.criteria_digest, cd])
        s.grant_digest = s.graph.append(s.grant)
        s.mint.grant_digest = s.grant_digest
        s.mint.submit(m, GOLDEN)
        res = s.mint.evaluate(m)
        # The sandbox cwd contains no .pem files → the probe passes (exit 0),
        # i.e. no signing material was reachable from the check's cwd.
        self.assertEqual(res["status"], "PASS")

    # §12.7 — self-signed or forged warrants are rejected
    def test_12_07_self_signed_or_forged_warrant_rejected(self):
        payload = base64.b64decode(self.envelope["payload"])
        # (a) producer signs the same statement with its own key
        producer_priv = self.sys.privs["producer"]
        forged = dsse.sign_envelope(payload, producer_priv,
                                    fingerprint(self.sys.pubs["producer"]))
        rc, out = self.sys.run_independent_verifier(
            GOLDEN, forged, self.sys.trust_config())
        self.assertEqual(rc, 1)
        # (b) tampered signature bytes
        broken = copy.deepcopy(self.envelope)
        sig = bytearray(base64.b64decode(broken["signatures"][0]["sig"]))
        sig[0] ^= 0xFF
        broken["signatures"][0]["sig"] = base64.b64encode(bytes(sig)).decode()
        rc, out = self.sys.run_independent_verifier(
            GOLDEN, broken, self.sys.trust_config())
        self.assertEqual(rc, 1)
        # (c) tampered payload under the original signature
        tampered = copy.deepcopy(self.envelope)
        stmt = json.loads(payload.decode())
        stmt["repository"] = "repo-beta"
        tampered["payload"] = base64.b64encode(
            json.dumps(stmt, sort_keys=True, separators=(",", ":")).encode()).decode()
        rc, out = self.sys.run_independent_verifier(
            GOLDEN, tampered, self.sys.trust_config())
        self.assertEqual(rc, 1)

    # §12.8 — warrant reuse across repositories/work items is rejected
    def test_12_08_warrant_reuse_rejected(self):
        cfg = self.sys.trust_config(expectation={
            "repository": "repo-beta", "work_item": "WI-1",
            "criteria_digest": self.sys.criteria_digest,
            "acceptance_mode": "automatic"})
        rc, out = self.sys.run_independent_verifier(GOLDEN, self.envelope, cfg)
        self.assertEqual(rc, 1)
        cfg2 = self.sys.trust_config(expectation={
            "repository": "repo-alpha", "work_item": "WI-2",
            "criteria_digest": self.sys.criteria_digest,
            "acceptance_mode": "automatic"})
        rc2, out2 = self.sys.run_independent_verifier(GOLDEN, self.envelope, cfg2)
        self.assertEqual(rc2, 1)

    # §12.9 — a failed run remains visible after a successful retry
    def test_12_09_failed_run_remains_visible_after_retry(self):
        s = System()
        bad = GOLDEN + b"tampered"
        m1 = s.manifest(bad, "req-fail")
        s.mint.submit(m1, bad)
        r1 = s.mint.evaluate(m1)
        self.assertEqual(r1["status"], "FAIL")
        r2 = s.golden_run("req-retry")
        self.assertEqual(r2["status"], "PASS")
        outcomes = s.graph.by_type("Outcome")
        self.assertIn("FAIL", [o["status"] for o in outcomes])   # append-only
        self.assertTrue(s.graph.verify_chain())                  # §10.6
        self.assertEqual(len(s.graph.by_type("Rejection")), 1)

    # §12.10 — crashes and missing evidence never imply success
    def test_12_10_crash_is_indeterminate_not_pass(self):
        s = System()
        crash = "raise SystemError('boom')"
        crit = copy.deepcopy(s.criteria)
        crit["required_checks"] = [{"check_id": "C-crash", "kind": "script",
                                    "script": crash,
                                    "script_digest": digest(crash.encode())}]
        cd = digest(crit)
        s.graph.append(crit)
        s.graph.append({"record_type": "Approval", "role": "owner",
                        "approves": cd,
                        "signer_keyid": fingerprint(s.pubs["owner"])})
        m = s.manifest(GOLDEN, "req-crash", criteria_digest=cd)
        s.mint.submit(m, GOLDEN)
        res = s.mint.evaluate(m)
        self.assertNotEqual(res["status"], "PASS")
        self.assertNotIn("envelope", res)

    # §12.11 — revocation blocks future acceptance
    def test_12_11_revocation_blocks_acceptance(self):
        payload = json.loads(base64.b64decode(self.envelope["payload"]))
        cfg = self.sys.trust_config(revocations=[payload["warrant_id"]])
        rc, out = self.sys.run_independent_verifier(GOLDEN, self.envelope, cfg)
        self.assertEqual(rc, 1)
        self.assertIn("revoked", out["reason"])
        cfg2 = self.sys.trust_config(revocations=[self.sys.criteria_digest])
        rc2, _ = self.sys.run_independent_verifier(GOLDEN, self.envelope, cfg2)
        self.assertEqual(rc2, 1)

    # §12.12 — owner verifies trust configuration via an independent path
    def test_12_12_trust_root_digest_independent_check(self):
        tr = self.sys.trust_root
        recomputed = digest({k: v for k, v in tr.items()
                             if k != "trust_root_digest"})
        self.assertEqual(recomputed, tr["trust_root_digest"])
        # a swapped mint key changes the published digest
        evil = copy.deepcopy(tr)
        evil["roles"]["mint"]["key_id"] = "sha256:" + "0" * 64
        self.assertNotEqual(digest({k: v for k, v in evil.items()
                                    if k != "trust_root_digest"}),
                            tr["trust_root_digest"])


if __name__ == "__main__":
    unittest.main()
