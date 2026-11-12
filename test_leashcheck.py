import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

import leashcheck as br


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


MOUNTINFO = """\
500 400 0:50 / / rw,relatime - overlay overlay rw,lowerdir=/x
501 500 0:51 / /proc rw - proc proc rw
502 500 0:52 / /tmp rw - tmpfs tmpfs rw
503 500 8:3 /home/u/proj /proj rw,relatime - ext4 /dev/sda3 rw
504 500 8:3 /var/lib/docker/volumes/box-home/_data /home/agent rw - ext4 /dev/sda3 rw
"""


class Mounts(unittest.TestCase):
    def setUp(self):
        self.orig = br.in_container
        br.in_container = lambda: True

    def tearDown(self):
        br.in_container = self.orig

    def test_longest_mount_point_wins(self):
        self.assertEqual(br.mount_entry("/proj/src", MOUNTINFO), ("ext4", "/home/u/proj"))
        self.assertEqual(br.mount_entry("/projx", MOUNTINFO)[0], "overlay")

    def test_private_versus_host_backed(self):
        self.assertTrue(br.sandbox_private("/etc", MOUNTINFO))          # image layer
        self.assertTrue(br.sandbox_private("/tmp/x", MOUNTINFO))        # tmpfs
        self.assertTrue(br.sandbox_private("/home/agent", MOUNTINFO))   # named volume
        self.assertFalse(br.sandbox_private("/proj", MOUNTINFO))        # host bind mount

    def test_never_private_outside_a_container(self):
        br.in_container = lambda: False
        self.assertFalse(br.sandbox_private("/etc", MOUNTINFO))


class NetworkInContainer(unittest.TestCase):
    """Runs the whole network probe with every connection attempt stubbed out."""

    def setUp(self):
        self.saved = {n: getattr(br, n) for n in ("in_container", "tcp_open", "proxy_connect",
                                                  "udp_dns_works", "default_gateway")}
        self.getaddrinfo = br.socket.getaddrinfo
        br.in_container = lambda: True
        br.proxy_connect = lambda *a: None
        br.udp_dns_works = lambda *a: False
        br.default_gateway = lambda: "172.17.0.1"

        def no_dns(*a, **k):
            raise OSError("blocked")
        br.socket.getaddrinfo = no_dns

    def tearDown(self):
        for name, value in self.saved.items():
            setattr(br, name, value)
        br.socket.getaddrinfo = self.getaddrinfo

    def run_probe(self, reachable):
        br.tcp_open = lambda host, port, timeout: (host, port) in reachable
        return by_id(br.probe_network(br.Ctx(homes=["/nonexistent"], project="/nonexistent")))

    def test_everything_blocked(self):
        res = self.run_probe(set())
        self.assertEqual(res["net.outbound"].status, "protected")
        self.assertEqual(res["net.host_gateway"].status, "protected")

    def test_host_service_behind_gateway_is_reported(self):
        r = self.run_probe({("172.17.0.1", 5432), ("172.17.0.1", 22)})["net.host_gateway"]
        self.assertEqual(r.status, "exposed")
        self.assertIn("postgres (5432)", r.detail)
        self.assertIn("ssh (22)", r.detail)

    def test_failed_probe_is_flagged_as_incomplete(self):
        results = [br.Result("probe_network", "Errors", "probe_network", "low", "na", "probe failed")]
        env = {"user": "u", "uid": 1, "os": "linux", "container": True, "seccomp": "off",
               "no_new_privs": False, "project": "/p"}
        self.assertIn("INCOMPLETE", br.render(results, env, color=False))


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
