import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

import blastradius as br


def by_id(results):
    return {r.id: r for r in results}


class FakeHome(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = os.path.join(self.tmp.name, "home")
        self.project = os.path.join(self.home, "work", "proj")
        os.makedirs(self.project)
        self.ctx = br.Ctx(homes=[self.home], project=self.project, network=False)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel, text="x"):
        path = os.path.join(self.home, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(text)
        return path

    def test_empty_home_has_no_read_exposure(self):
        res = by_id(br.probe_reads(self.ctx))
        self.assertEqual(res["read.ssh_keys"].status, "na")
        self.assertEqual(res["read.cloud"].status, "na")

    def test_ssh_key_detected_and_public_key_ignored(self):
        self.write(".ssh/id_ed25519.pub")
        self.assertEqual(by_id(br.probe_reads(self.ctx))["read.ssh_keys"].status, "na")
        self.write(".ssh/id_ed25519", "SECRET-KEY-MATERIAL")
        r = by_id(br.probe_reads(self.ctx))["read.ssh_keys"]
        self.assertEqual(r.status, "exposed")
        self.assertIn("~/.ssh/id_ed25519", r.detail)
        self.assertNotIn("SECRET-KEY-MATERIAL", r.detail)

    @unittest.skipIf(hasattr(os, "getuid") and os.getuid() == 0, "root ignores file modes")
    def test_unreadable_key_is_protected(self):
        os.chmod(self.write(".ssh/id_rsa"), 0)
        self.assertEqual(by_id(br.probe_reads(self.ctx))["read.ssh_keys"].status, "protected")

    def test_dotenv_example_is_ignored(self):
        open(os.path.join(self.project, ".env.example"), "w").close()
        self.assertEqual(by_id(br.probe_reads(self.ctx))["read.dotenv"].status, "na")
        with open(os.path.join(self.project, ".env"), "w") as fh:
            fh.write("A=1")
        self.assertEqual(by_id(br.probe_reads(self.ctx))["read.dotenv"].status, "exposed")

    def test_write_probes_leave_nothing_behind(self):
        rc = self.write(".bashrc", "export A=1\n")
        os.makedirs(os.path.join(self.home, ".ssh"))
        before = sorted(os.listdir(self.home)), os.stat(rc).st_mtime_ns
        res = by_id(br.probe_writes(self.ctx))
        self.assertEqual(res["write.home"].status, "exposed")
        self.assertEqual(res["write.startup"].status, "exposed")
        self.assertEqual(res["write.ssh"].status, "exposed")
        self.assertEqual((sorted(os.listdir(self.home)), os.stat(rc).st_mtime_ns), before)
        self.assertEqual(os.listdir(os.path.join(self.home, ".ssh")), [])
        with open(rc) as fh:
            self.assertEqual(fh.read(), "export A=1\n")

    @unittest.skipIf(hasattr(os, "getuid") and os.getuid() == 0, "root ignores file modes")
    def test_read_only_home_is_protected(self):
        os.chmod(self.home, 0o555)
        try:
            self.assertEqual(by_id(br.probe_writes(self.ctx))["write.home"].status, "protected")
        finally:
            os.chmod(self.home, 0o755)

    def test_env_secret_names_never_include_values(self):
        os.environ["BR_TEST_API_KEY"] = "super-secret-value"
        try:
            r = by_id(br.probe_env(self.ctx))["env.secrets"]
        finally:
            del os.environ["BR_TEST_API_KEY"]
        self.assertEqual(r.status, "exposed")
        self.assertNotIn("super-secret-value", r.detail)

    def test_no_network_flag_skips_probes(self):
        res = br.probe_network(self.ctx)
        self.assertEqual([r.status for r in res], ["na"])


class Scoring(unittest.TestCase):
    def r(self, sev, status="exposed"):
        return br.Result("x", "c", "t", sev, status)

    def test_clean_is_a(self):
        self.assertEqual(br.score([self.r("critical", "protected")]), (100, "A"))

    def test_one_critical_caps_grade_at_d(self):
        self.assertEqual(br.score([self.r("critical")]), (75, "D"))

    def test_score_floor(self):
        self.assertEqual(br.score([self.r("critical")] * 10), (0, "F"))


class Cli(unittest.TestCase):
    def test_json_output_and_fail_on(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, "h")
            os.makedirs(os.path.join(home, ".ssh"))
            with open(os.path.join(home, ".ssh", "id_rsa"), "w") as fh:
                fh.write("k")
            buf = StringIO()
            with redirect_stdout(buf):
                code = br.main(["--json", "--no-network", "--home", home, "--project", home, "--fail-on", "critical"])
            data = json.loads(buf.getvalue())
            self.assertEqual(code, 1)
            self.assertIn("read.ssh_keys", [r["id"] for r in data["results"] if r["status"] == "exposed"])


if __name__ == "__main__":
    unittest.main()
