"""Security regressions from the September 2026 audit."""
import base64
import copy
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from warrantd import dsse
from warrantd.canon import canonical_bytes, digest
from warrantd.keys import KeyStore, generate_keypair, fingerprint, public_pem
from warrantd.mint import Mint, MintError
from warrantd.store import RecordGraph, StoreIntegrityError, PayloadStore
from warrantd.verify import verify, Reject
from tests.harness import System, GOLDEN


class SecurityRegression(unittest.TestCase):
    def test_evaluation_cannot_change_admitted_scope(self):
        s = System()
        m = s.manifest(GOLDEN, "scope")
        s.mint.submit(m, GOLDEN)
        for field, value in (("repository", "repo-beta"), ("work_item", "WI-2"),
                             ("producer", "other"), ("claimed_digest", digest(b"evil"))):
            with self.subTest(field=field), self.assertRaises(MintError):
                s.mint.evaluate(dict(m, **{field: value}))

    def test_criteria_are_immutable_across_input_and_output(self):
        with tempfile.TemporaryDirectory() as d:
            g = RecordGraph(d)
            record = {"record_type": "Criteria", "required_checks": [{"check_id": "a"}]}
            rd = g.append(record)
            record["required_checks"].clear()
            fetched = g.get(rd)
            self.assertEqual(len(fetched["required_checks"]), 1)
            fetched["required_checks"].clear()
            g.by_type("Criteria")[0]["required_checks"].clear()
            self.assertEqual(len(g.get(rd)["required_checks"]), 1)

    def test_record_digest_and_sequence_tampering_rejected(self):
        for field,value in (("record_digest", digest(b"other")), ("seq", 99), ("seq", True)):
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as d:
                g = RecordGraph(d)
                g.append({"record_type": "Criteria"})
                p = Path(g.path)
                entry = json.loads(p.read_text())
                entry[field] = value
                p.write_text(json.dumps(entry) + "\n")
                with self.assertRaises(StoreIntegrityError):
                    RecordGraph(d)

    def test_complete_record_without_newline_survives_next_append(self):
        with tempfile.TemporaryDirectory() as d:
            g = RecordGraph(d)
            g.append({"record_type": "Criteria"})
            p = Path(g.path)
            p.write_bytes(p.read_bytes().rstrip(b"\r\n"))
            RecordGraph(d).append({"record_type": "Approval"})
            self.assertEqual(len(RecordGraph(d).by_type("Approval")), 1)

    def test_two_store_handles_preserve_chain(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = RecordGraph(d), RecordGraph(d)
            a.append({"record_type": "Criteria"})
            b.append({"record_type": "Approval"})
            self.assertTrue(RecordGraph(d).verify_chain())

    def test_failed_append_does_not_publish_record_in_memory(self):
        with tempfile.TemporaryDirectory() as d:
            g = RecordGraph(d)
            with patch("warrantd.store.os.fsync", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    g.append({"record_type": "Criteria"})
            self.assertEqual(g.by_type("Criteria"), [])

    def test_two_mints_cannot_admit_duplicate_request(self):
        s = System()
        other = Mint(s.graph, s.payloads, s.keys, s.pubs["mint"], s.grant_digest)
        m = s.manifest(GOLDEN, "duplicate")
        s.mint.submit(m, GOLDEN)
        with self.assertRaises(MintError):
            other.submit(m, GOLDEN)

    def test_expired_or_unauthorized_grant_rejected(self):
        s = System()
        result = s.golden_run()
        statement = json.loads(base64.b64decode(result["envelope"]["payload"]))
        for changes in ({"validity": {"not_before": 0, "not_after": 1}},
                        {"validity": {"not_before": time.time()+3600, "not_after": 2**40}},
                        {"permitted_actions": []}):
            cfg = copy.deepcopy(s.trust_config())
            cfg["authority_grant"].update(changes)
            cfg["authority_grant_digest"] = digest(cfg["authority_grant"])
            stmt = dict(statement, authority_grant_digest=cfg["authority_grant_digest"])
            env = dsse.sign_envelope(canonical_bytes(stmt), s.privs["mint"], fingerprint(s.pubs["mint"]))
            with self.subTest(changes=changes), self.assertRaises(Reject):
                verify(GOLDEN, env, cfg, cfg["expectation"])

    def test_unknown_acceptance_mode_rejected(self):
        s = System()
        result = s.golden_run()
        cfg = s.trust_config()
        cfg["expectation"]["acceptance_mode"] = "approval_requird"
        with self.assertRaises(Reject):
            verify(GOLDEN, result["envelope"], cfg, cfg["expectation"])

    def test_malformed_envelope_is_clean_rejection(self):
        s = System()
        env = s.golden_run()["envelope"]
        cfg = s.trust_config()
        for signatures in ([None], [17], ["sig"], [{}]):
            bad = dict(env, signatures=signatures)
            with self.subTest(signatures=signatures), self.assertRaises(Reject):
                verify(GOLDEN, bad, cfg, cfg["expectation"])

    def test_duplicate_nonfinite_and_noncanonical_signed_json_rejected(self):
        key = generate_keypair()
        kid = fingerprint(public_pem(key))
        for payload in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{ "a": 1 }'):
            env = dsse.sign_envelope(payload, key, kid)
            with self.subTest(payload=payload), self.assertRaises(dsse.EnvelopeError):
                dsse.verify_envelope(env, key.public_key(), kid)

    def test_empty_check_inventory_cannot_pass(self):
        s = System()
        cd = s.graph.append(dict(s.criteria, required_checks=[]))
        s.graph.append({"record_type": "Approval", "role": "owner", "approves": cd,
                        "signer_keyid": fingerprint(s.pubs["owner"])})
        m = s.manifest(GOLDEN, "empty", criteria_digest=cd)
        s.mint.submit(m, GOLDEN)
        with self.assertRaises(MintError):
            s.mint.evaluate(m)

    def test_unknown_key_role_cannot_escape_root(self):
        with tempfile.TemporaryDirectory() as d:
            ks = KeyStore(str(Path(d)/"keys"))
            with self.assertRaises(ValueError):
                ks.write_private("../outside", generate_keypair())
            self.assertFalse((Path(d)/"outside").exists())

    def test_check_environment_does_not_inherit_secrets(self):
        s = System()
        script = "import os; assert 'WARRANTD_TEST_SECRET' not in os.environ"
        criteria = dict(s.criteria, required_checks=[{"check_id": "env", "kind": "script",
                         "script": script, "script_digest": digest(script.encode())}])
        with patch.dict(os.environ, {"WARRANTD_TEST_SECRET": "test-only"}):
            snapshot = s.payloads.snapshot(GOLDEN)
            results, _, _ = s.mint._run_checks(criteria, snapshot, "env-test")
        self.assertEqual(results[0]["result"], "pass")

    def test_mint_refuses_to_sign_under_expired_grant(self):
        s = System()
        expired = dict(s.grant, validity={"not_before": 0, "not_after": 1})
        s.mint.grant_digest = s.graph.append(expired)
        with self.assertRaises(MintError):
            s.golden_run()
        self.assertEqual(s.graph.by_type("WarrantEnvelope"), [])

    def test_cli_rejects_duplicate_json_and_missing_files(self):
        import contextlib
        import io
        from warrantd.verify import main
        with tempfile.TemporaryDirectory() as d:
            artifact, env, cfg = [Path(d)/n for n in ("artifact", "envelope", "config")]
            artifact.write_bytes(GOLDEN)
            env.write_text('{"payload":1,"payload":2}')
            cfg.write_text('{}')
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(main([str(artifact), str(env), str(cfg)]), 1)
            self.assertFalse(json.loads(out.getvalue())["accepted"])
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(main([str(artifact), str(env), str(cfg)+"-missing"]), 1)

    def test_same_key_with_different_pem_format_is_not_two_roles(self):
        from warrantd.keys import make_trust_root
        pem = public_pem(generate_keypair())
        with self.assertRaises(ValueError):
            make_trust_root({"owner": pem, "mint": pem.replace("\n", "\r\n")})

    def test_payload_digest_cannot_escape_storage_directory(self):
        with tempfile.TemporaryDirectory() as d:
            p = PayloadStore(d)
            with self.assertRaises(ValueError):
                p.read("sha256:../private.pem")

    def test_concurrent_processes_preserve_all_records(self):
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as d:
            code = ("import sys; from warrantd.store import RecordGraph; "
                    "g=RecordGraph(sys.argv[1]); "
                    "[g.append({'record_type':'Criteria','i':i}) for i in range(8)]")
            processes = [subprocess.Popen([sys.executable, "-c", code, d],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
            try:
                for proc in processes:
                    _, err = proc.communicate(timeout=30)
                    self.assertEqual(proc.returncode, 0, err.decode())
            finally:
                for proc in processes:
                    if proc.poll() is None:
                        proc.kill()
                        proc.communicate()
            self.assertEqual(len(RecordGraph(d).by_type("Criteria")), 16)
