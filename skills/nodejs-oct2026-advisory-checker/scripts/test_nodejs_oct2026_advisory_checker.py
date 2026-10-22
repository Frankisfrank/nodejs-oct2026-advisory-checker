"""Offline tests: no Docker daemon, network requests or vulnerability payloads."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import signal
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch, Mock

spec = importlib.util.spec_from_file_location("nodejs_oct2026_advisory_checker", Path(__file__).with_name("nodejs_oct2026_advisory_checker.py"))
n = importlib.util.module_from_spec(spec)
spec.loader.exec_module(n)


def binary(version):
    return b"\x7fELF\x00https://nodejs.org/download/release/node.js/v" + version.encode() + b"/node.tar.xz\x00"


def tar_body(data=b"example", kind=None, link=""):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        member = tarfile.TarInfo("node")
        if kind is not None:
            member.type, member.linkname = kind, link
        else:
            member.size = len(data)
        archive.addfile(member, io.BytesIO(data) if kind is None else None)
    return stream.getvalue()


class Rules(unittest.TestCase):
    def test_release_boundaries(self):
        for old, fixed, newer in [("22.23.3", "22.23.4", "22.24.0"),
                                  ("24.22.0", "24.22.1", "24.23.0"),
                                  ("26.12.0", "26.12.1", "26.13.0")]:
            with self.subTest(fixed=fixed):
                self.assertEqual(n.classify(old)[:2], ("vulnerable_by_version", fixed))
                self.assertEqual(n.classify(fixed)[0], "patched_by_version")
                self.assertEqual(n.classify(newer)[0], "patched_by_version")

    def test_numeric_comparison(self):
        self.assertEqual(n.classify("24.9.99")[0], "vulnerable_by_version")
        self.assertEqual(n.classify("v24.22.1+vendor")[0], "patched_by_version")

    def test_unsupported_is_not_patched(self):
        for version in ("16.20.2", "20.19.2", "23.11.0", "25.6.1"):
            self.assertEqual(n.classify(version)[0], "unsupported")

    def test_unverifiable_versions(self):
        for version in (None, "", "24.22", "26.12.1-rc.1", "24.22.1-distro1", "27.0.0", "garbage"):
            self.assertEqual(n.classify(version)[0], "unknown")

    def test_unknown_prevents_success(self):
        self.assertEqual(n.summarize([n.finding("one", "24.22.1"), n.finding("two")]), ("unknown", 3))
        self.assertEqual(n.summarize([]), ("unknown", 3))

    def test_known_risk_wins_but_unknown_is_retained(self):
        rows = [n.finding("risk", "24.21.0"), n.finding("blocked")]
        self.assertEqual(n.summarize(rows), ("vulnerable_by_version", 1))
        self.assertEqual(rows[1]["patch_status"], "unknown")


class StaticScan(unittest.TestCase):
    def test_unique_embedded_marker(self):
        self.assertEqual(n.embedded_version(binary("24.21.0")), ("24.21.0", None))
        self.assertEqual(n.embedded_version(binary("24.21.0") * 2), ("24.21.0", None))

    def test_ambiguous_missing_and_prerelease_markers(self):
        for data in (binary("24.21.0") + binary("24.22.1"), b"\x7fELF24.22.1", binary("24.22.1-rc.1")):
            self.assertIsNone(n.embedded_version(data)[0])

    def test_script_is_never_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node = root / "node"
            marker = root / "executed"
            node.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\n# node.js/v24.22.1/\n")
            node.chmod(0o755)
            rows, count = n.scan_root(root)
            self.assertEqual(count, 1)
            self.assertEqual(rows[0]["patch_status"], "unknown")
            self.assertFalse(marker.exists())

    def test_scan_does_not_follow_file_or_directory_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside"
            outside.mkdir()
            (outside / "node").write_bytes(binary("24.22.1"))
            inside = root / "inside"
            inside.mkdir()
            (inside / "linked_dir").symlink_to(outside, target_is_directory=True)
            (inside / "node").symlink_to(outside / "node")
            rows, count = n.scan_root(inside)
            self.assertEqual(len(rows), 2)
            self.assertTrue(all(row["patch_status"] == "unknown" for row in rows))
            self.assertEqual(count, 1)
            self.assertEqual(n.inspect_file(inside / "node")["patch_status"], "unknown")

    def test_directory_link_is_reported_without_hiding_known_versions(self):
        for version, expected_code in (("24.22.1", 3), ("24.21.0", 1)):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                outside, inside = root / "outside", root / "inside"
                outside.mkdir()
                inside.mkdir()
                (outside / "node").write_bytes(binary("24.21.0"))
                (inside / "node").write_bytes(binary(version))
                link = inside / "old-runtime"
                link.symlink_to(outside, target_is_directory=True)
                output = io.StringIO()
                with patch.object(n, "inspect_file", wraps=n.inspect_file) as inspect, contextlib.redirect_stdout(output):
                    code = n.main(["--scan", str(inside), "--json"])
                report = json.loads(output.getvalue())
                self.assertEqual(code, expected_code)
                self.assertEqual(report["exit_code"], expected_code)
                self.assertTrue(any(row["target"] == str(link) and row["patch_status"] == "unknown" for row in report["results"]))
                self.assertTrue(any(row["node_version"] == version for row in report["results"]))
                inspect.assert_called_once_with(inside / "node")

    def test_fifo_is_not_opened_as_a_blocking_stream(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "node"
            os.mkfifo(path)
            self.assertEqual(n.inspect_file(path)["patch_status"], "unknown")

    def test_scan_missing_empty_and_access_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(n.scan_root(Path(directory) / "missing")[0][0]["patch_status"], "unknown")
            self.assertEqual(n.scan_root(directory)[0][0]["patch_status"], "unknown")
        with patch.object(n.os, "scandir", side_effect=PermissionError(13, "denied", "/")):
            self.assertIn("errno 13", n.scan_root("/")[0][0]["reason"])


class ExecutableProbe(unittest.TestCase):
    def probe(self, body, timeout=1):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture"
            path.write_text("#!/bin/sh\n" + body)
            path.chmod(0o700)
            with patch.object(n.os, "geteuid", return_value=501):
                return n.local_probe(str(path), timeout)

    def test_query_clears_startup_environment(self):
        with patch.object(n.subprocess, "Popen", wraps=subprocess.Popen) as run:
            row = self.probe("printf 'v25.6.1\\n'\n")
        self.assertEqual(row["patch_status"], "unsupported")
        args, kwargs = run.call_args
        self.assertEqual(args[0][1:], ["--version"])
        self.assertEqual(kwargs["env"], {"PATH": os.defpath})
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertTrue(kwargs["start_new_session"])

    def test_timeout_and_bad_output_are_unknown(self):
        started = time.monotonic()
        row = self.probe("sleep 5\n", 0.05)
        self.assertIn("timed out", row["reason"])
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(self.probe("printf 'unexpected banner'\n")["patch_status"], "unknown")

    def test_stdout_and_stderr_are_bounded_during_read(self):
        for redirect in ("", " >&2"):
            row = self.probe("i=0; while [ $i -lt 2000 ]; do printf '12345678'" + redirect + "; i=$((i+1)); done\n")
            self.assertIn("stdout/stderr limit", row["reason"])
            self.assertEqual(row["patch_status"], "unknown")

    def test_root_execution_is_refused_before_spawn(self):
        with patch.object(n.os, "geteuid", return_value=0), patch.object(n.subprocess, "Popen") as spawn:
            self.assertIn("refused as root", n.local_probe("/trusted/node", 1)["reason"])
            spawn.assert_not_called()

    def test_child_holding_pipes_is_stopped_on_timeout(self):
        # Harmless child would create a marker unless the probe kills its process group.
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "child-survived"
            row = self.probe("(sleep 0.4; touch '" + str(marker) + "') &\nexit 0\n", 0.05)
            self.assertIn("timed out", row["reason"])
            time.sleep(0.5)
            self.assertFalse(marker.exists())

    def test_exec_gate_rejects_before_any_selected_mode_runs(self):
        for args in (["--local"], ["--node", "/trusted/node"],
                     ["--allow-exec", "--node-version", "24.22.1"],
                     ["--allow-exec", "--node", "relative/node"]):
            with self.subTest(args=args), patch.object(n, "local_probe") as probe, patch.object(n, "scan_root") as scan, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    n.main(args + ["--scan", "/unused"])
                self.assertEqual(raised.exception.code, 2)
                probe.assert_not_called()
                scan.assert_not_called()

    def test_explicit_opt_in_allows_selected_probe(self):
        with patch.object(n.os, "geteuid", return_value=501), patch.object(n, "local_probe", return_value=n.finding("test", "24.22.1")) as probe, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(n.main(["--allow-exec", "--node", "/trusted/node"]), 0)
        probe.assert_called_once_with("/trusted/node", 10)


class DockerRead(unittest.TestCase):
    def connection(self, body, status=200):
        conn = Mock()
        response = io.BytesIO(body)
        response.status = status
        conn.getresponse.return_value = response
        return conn

    def test_archive_is_read_with_get_without_extracting(self):
        conn = self.connection(tar_body(binary("22.23.4")))
        with patch.object(n, "UnixConnection", return_value=conn), patch.object(tarfile.TarFile, "extractall", side_effect=AssertionError("must not extract")):
            data, error = n.Docker("/local.sock", 1).file("a" * 64, "/usr/bin/node")
        self.assertEqual(n.embedded_version(data)[0], "22.23.4")
        self.assertIsNone(error)
        self.assertEqual(conn.request.call_args.args, ("GET", "/containers/" + "a" * 64 + "/archive?path=%2Fusr%2Fbin%2Fnode"))
        conn.close.assert_called_once()

    def test_archive_directory_and_oversize_are_unknown(self):
        for body in (tar_body(kind=tarfile.DIRTYPE), tar_body(b"12345")):
            with patch.object(n, "UnixConnection", return_value=self.connection(body)), patch.object(n, "MAX_BYTES", 4):
                data, error = n.Docker("/local.sock", 1).file("a" * 64, "/usr/bin/node")
                self.assertIsNone(data)
                self.assertTrue(error)

    def test_symlink_is_followed_only_inside_container(self):
        first = self.connection(tar_body(kind=tarfile.SYMTYPE, link="../lib/node"))
        second = self.connection(tar_body(binary("26.7.0")))
        with patch.object(n, "UnixConnection", side_effect=[first, second]):
            data, error = n.Docker("/local.sock", 1).file("a" * 64, "/usr/bin/node")
        self.assertEqual(n.embedded_version(data)[0], "26.7.0")
        self.assertIn("path=%2Fusr%2Flib%2Fnode", second.request.call_args.args[1])
        self.assertIsNone(error)

    def test_archive_missing_error_and_link_loop(self):
        for status, expected_error in ((404, False), (500, True)):
            with patch.object(n, "UnixConnection", return_value=self.connection(b"", status)):
                data, error = n.Docker("/local.sock", 1).file("a" * 64, "/usr/bin/node")
            self.assertIsNone(data)
            self.assertEqual(bool(error), expected_error)
        with patch.object(n, "UnixConnection") as conn:
            self.assertIsNotNone(n.Docker("/local.sock", 1).file("a" * 64, "/usr/bin/node", 5)[1])
            conn.assert_not_called()

    def test_metadata_cannot_prove_patched_runtime(self):
        client = Mock()
        client.json.return_value = {"Name": "/test", "Config": {"Image": "example", "Env": ["SECRET=must-not-leak", "NODE_VERSION=24.22.1"]}, "State": {"Status": "exited"}}
        client.file.return_value = (None, None)
        row = n.inspect_container(client, {"Id": "a" * 64})
        self.assertEqual(row["patch_status"], "unknown")
        self.assertEqual(row["metadata_patch_status"], "patched_by_version")
        self.assertNotIn("must-not-leak", json.dumps(row))
        self.assertNotIn("SECRET", json.dumps(row))

    def test_patched_first_binary_does_not_hide_a_second_old_binary(self):
        client = Mock()
        client.json.return_value = {"Name": "/test", "Config": {}, "State": {"Status": "running"}}
        client.file.side_effect = [(binary("24.22.1"), None), (binary("22.23.2"), None), (None, None)]
        row = n.inspect_container(client, {"Id": "a" * 64})
        self.assertEqual(row["patch_status"], "vulnerable_by_version")
        self.assertEqual(row["node_version"], "22.23.2")
        self.assertEqual(len(row["binary_observations"]), 2)

    def test_failed_other_binary_path_prevents_patched_result(self):
        client = Mock()
        client.json.return_value = {"Name": "/test", "Config": {}, "State": {"Status": "running"}}
        client.file.side_effect = [(binary("24.22.1"), None), (None, "HTTP 500"), (None, None)]
        row = n.inspect_container(client, {"Id": "a" * 64})
        self.assertEqual(row["patch_status"], "unknown")
        self.assertTrue(row["read_errors"])

    def test_preflight_failure_is_unknown_and_does_not_continue(self):
        with patch.object(n.Docker, "json", side_effect=OSError("not reachable")) as get:
            self.assertEqual(n.docker_scan("/absent.sock", 1)[0]["patch_status"], "unknown")
            self.assertEqual(get.call_count, 1)

    def test_malformed_container_does_not_crash_scan(self):
        with patch.object(n.Docker, "json", side_effect=[{"Version": "29.1.3"}, [None]]):
            self.assertEqual(n.docker_scan("/local.sock", 1)[0]["patch_status"], "unknown")


class CLI(unittest.TestCase):
    def test_json_contract(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = n.main(["--node-version", "24.22.1", "--json"])
        report = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(report["compromise_status"], "not_assessed")
        self.assertEqual(report["rules_as_of"], "2026-10-22")
        self.assertTrue(report["limitations"])

    def test_remote_socket_rejected_before_executing_any_node(self):
        with patch.object(n, "local_probe") as probe, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                n.main(["--local", "--docker", "--docker-socket", "tcp://host:2375"])
            self.assertEqual(raised.exception.code, 2)
            probe.assert_not_called()

    def test_terminal_control_characters_are_escaped(self):
        row = n.finding("name\x1b[31m", "24.21.0")
        output = io.StringIO()
        with patch.object(n, "scan_root", return_value=([row], 1)), contextlib.redirect_stdout(output):
            n.main(["--scan", "/example"])
        self.assertNotIn("\x1b", output.getvalue())
        self.assertIn("\\x1b", output.getvalue())


class ResourceBudgets(unittest.TestCase):
    def test_entry_limit_streams_and_stops_before_later_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for i in range(10):
                (root / ("unused-" + str(i))).touch()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = n.main(["--scan", directory, "--max-entries", "2", "--json"])
            report = json.loads(output.getvalue())
            self.assertEqual(code, 3)
            self.assertEqual(report["resource_limits"]["entries"], 3)
            self.assertIn("entry limit", report["resource_limits"]["limit_reached"])

    def test_time_limit_interrupts_blocked_scan_and_restores_timer(self):
        output = io.StringIO()
        previous = n.signal.getsignal(n.signal.SIGALRM)
        started = time.monotonic()
        with patch.object(n.os, "scandir", side_effect=lambda path: time.sleep(2)), contextlib.redirect_stdout(output):
            code = n.main(["--scan", "/", "--max-seconds", "0.02", "--json"])
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(code, 3)
        self.assertIn("time limit", json.loads(output.getvalue())["resource_limits"]["limit_reached"])
        self.assertEqual(n.signal.getsignal(n.signal.SIGALRM), previous)
        self.assertEqual(n.signal.getitimer(n.signal.ITIMER_REAL), (0, 0))

    def test_byte_limit_stops_cumulative_reads(self):
        with n.ScanBudget(byte_limit=4) as budget:
            n.account(byte_count=3)
            n.account(byte_count=2)
            self.fail("must stop at the byte budget")
        self.assertIn("read limit", budget.limit)

    def test_invalid_limits_fail_before_work(self):
        for option, value in (("--max-seconds", "nan"), ("--max-seconds", "inf"),
                              ("--max-seconds", "0"), ("--max-entries", "0"),
                              ("--max-entries", "100001")):
            with patch.object(n, "scan_root") as scan, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    n.main(["--scan", "/unused", option, value])
                self.assertEqual(raised.exception.code, 2)
                scan.assert_not_called()


class ResourceReviewRegressions(unittest.TestCase):
    def test_static_read_is_clamped_to_remaining_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "node"
            path.write_bytes(binary("24.22.1"))
            with n.ScanBudget(byte_limit=4) as budget:
                n.inspect_file(path)
                self.fail("must stop before classifying a partial binary")
            self.assertEqual(budget.bytes_read, 5)

    def test_binary_shrinking_during_read_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "node"
            path.write_bytes(binary("24.22.1"))
            original = os.fstat
            def truncate_after_stat(fd):
                info = original(fd)
                path.write_bytes(b"")
                return info
            with patch.object(n.os, "fstat", side_effect=truncate_after_stat):
                row = n.inspect_file(path)
            self.assertEqual(row["patch_status"], "unknown")
            self.assertIn("size changed", row["reason"])

    def test_container_entry_limit_retains_earlier_risk(self):
        rows = [{"Id": "a" * 64}, {"Id": "b" * 64}]
        output = io.StringIO()
        with patch.object(n.Docker, "json", side_effect=[{"Version": "fixture"}, rows]), patch.object(n, "inspect_container", return_value=n.finding("first", "24.21.0")) as inspect, contextlib.redirect_stdout(output):
            code = n.main(["--docker", "--max-entries", "1", "--json"])
        report = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        inspect.assert_called_once()
        self.assertEqual({r["patch_status"] for r in report["results"]}, {"vulnerable_by_version", "unknown"})

    def test_global_deadline_stops_probe_and_its_child(self):
        with tempfile.TemporaryDirectory() as directory:
            marker, script = Path(directory) / "survived", Path(directory) / "fixture"
            script.write_text("#!/bin/sh\n(sleep 0.4; touch '" + str(marker) + "') &\nwait\n")
            script.chmod(0o700)
            output = io.StringIO()
            with patch.object(n.os, "geteuid", return_value=501), contextlib.redirect_stdout(output):
                code = n.main(["--allow-exec", "--node", str(script), "--max-seconds", "0.1", "--json"])
            self.assertEqual(code, 3)
            self.assertIn("time limit", json.loads(output.getvalue())["resource_limits"]["limit_reached"])
            time.sleep(0.5)
            self.assertFalse(marker.exists())


class StoppedBudget(unittest.TestCase):
    def test_exhausted_budget_cannot_start_another_docker_request(self):
        for method in (lambda client: client.json("/version"),
                       lambda client: client.file("a" * 64, "/usr/bin/node")):
            with patch.object(n, "UnixConnection") as connection:
                with n.ScanBudget() as budget:
                    budget.limit = "Scan entry limit reached"
                    method(n.Docker("/fixture.sock", 1))
                    self.fail("must stop before connecting")
                connection.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
