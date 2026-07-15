import os
import sys
import tempfile
import threading
import time
import textwrap
import unittest
from contextlib import contextmanager
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import ssh_totp
import totp_askpass
import debug_proxy_win

CONFIG_V3_PATH = SCRIPT_DIR / "lib" / "config_v3.py"
_config_spec = __import__("importlib.util").util.spec_from_file_location("config_v3_for_test", CONFIG_V3_PATH)
config_v3 = __import__("importlib.util").util.module_from_spec(_config_spec)
_config_spec.loader.exec_module(config_v3)


class SSHTOTPRegressionTests(unittest.TestCase):
    @contextmanager
    def patched_attr(self, obj, name, value):
        old_value = getattr(obj, name)
        setattr(obj, name, value)
        try:
            yield
        finally:
            setattr(obj, name, old_value)

    def write_config(self, content: str) -> str:
        handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
        self.addCleanup(lambda: os.path.exists(handle.name) and os.unlink(handle.name))
        handle.write(textwrap.dedent(content).strip() + "\n")
        handle.close()
        return handle.name

    @contextmanager
    def patched_environ(self, **updates):
        original = {key: os.environ.get(key) for key in updates}
        try:
            for key, value in updates.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
            yield
        finally:
            for key, value in original.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_direct_x_aliases_resolve_totp_case_sensitively(self):
        config = self.write_config(
            """
            # ===== X =====
            # totp_secret: SECRETX
            # totp_prompt: otp
            # totp_master: yes
            Host X
                HostName 61.50.130.61
                User zpzeng
                Port 50001

            # ===== x =====
            # totp_secret: SECRETLOWER
            # totp_prompt: otp
            Host x
                HostName 192.168.235.200
                User zpzeng
            """
        )

        upper = ssh_totp.resolve_totp_for_args(["X"], config)
        lower = ssh_totp.resolve_totp_for_args(["x"], config)

        self.assertEqual(upper["alias"], "X")
        self.assertEqual(upper["secret"], "SECRETX")
        self.assertFalse(upper["via_proxy"])
        self.assertTrue(upper["master"])
        self.assertEqual(lower["alias"], "x")
        self.assertEqual(lower["secret"], "SECRETLOWER")
        self.assertFalse(lower["via_proxy"])
        self.assertFalse(lower["master"])

    def test_debug_proxy_command_resolves_jump_alias_totp(self):
        config = self.write_config(
            """
            Host debug
                HostName f102.hn.org
                User zpzeng
                ProxyCommand C:/Users/YOU/.ssh/ssh_otp/debug_proxy.cmd %h %p

            Host f101
                HostName f101.hn.org
                User zpzeng
                ProxyCommand C:/Users/YOU/.ssh/ssh_otp/debug_proxy.cmd %h %p

            # ===== x =====
            # totp_secret: SECRETLOWER
            # totp_prompt: otp
            Host x
                HostName 192.168.235.200
                User zpzeng
            """
        )

        debug = ssh_totp.resolve_totp_for_args(["debug"], config)
        f101 = ssh_totp.resolve_totp_for_args(["f101"], config)
        self.assertEqual(debug["alias"], "x")
        self.assertTrue(debug["via_proxy"])
        self.assertEqual(f101["alias"], "x")
        self.assertTrue(f101["via_proxy"])

    def test_socks_proxy_defaults_to_lowercase_jump_alias(self):
        config = self.write_config(
            """
            Host debug
                HostName f102.hn.org
                ProxyCommand C:/Users/YOU/.ssh/ssh_otp/sshotp.cmd --socks %h %p

            # totp_secret: SECRETX
            Host X
                HostName 61.50.130.61

            # totp_secret: SECRETLOWER
            Host x
                HostName 192.168.235.200
            """
        )

        with self.patched_environ(SSH_TOTP_JUMP_ALIAS=None):
            resolved = ssh_totp.resolve_totp_for_args(["debug"], config)

        self.assertEqual(resolved["alias"], "x")
        self.assertEqual(resolved["secret"], "SECRETLOWER")

    def test_socks_proxy_honors_explicit_jump_alias_override(self):
        config = self.write_config(
            """
            Host debug
                HostName f102.hn.org
                ProxyCommand C:/Users/YOU/.ssh/ssh_otp/sshotp.cmd --socks %h %p

            # totp_secret: SECRETX
            Host X
                HostName 61.50.130.61

            # totp_secret: SECRETLOWER
            Host x
                HostName 192.168.235.200
            """
        )

        with self.patched_environ(SSH_TOTP_JUMP_ALIAS="X"):
            resolved = ssh_totp.resolve_totp_for_args(["debug"], config)

        self.assertEqual(resolved["alias"], "X")
        self.assertEqual(resolved["secret"], "SECRETX")

    def test_config_loader_inherits_debug_proxy_jump_totp(self):
        config = self.write_config(
            """
            Host debug
                HostName f102.hn.org
                User zpzeng
                ProxyCommand C:/Users/YOU/.ssh/ssh_otp/debug_proxy.cmd %h %p

            # ===== x =====
            # totp_secret: SECRETLOWER
            # totp_prompt: otp
            Host x
                HostName 192.168.235.200
                User zpzeng
            """
        )

        params = config_v3.SSHConfigLoaderV3(config).get_connection_params("debug")

        self.assertEqual(params["totp_secret"], "SECRETLOWER")
        self.assertEqual(params["totp_prompt"], "otp")

    def test_config_loader_defaults_socks_proxy_to_lowercase_jump_alias(self):
        config = self.write_config(
            """
            Host debug
                HostName f102.hn.org
                ProxyCommand C:/Users/YOU/.ssh/ssh_otp/sshotp.cmd --socks %h %p

            # totp_secret: SECRETX
            Host X
                HostName 61.50.130.61

            # totp_secret: SECRETLOWER
            Host x
                HostName 192.168.235.200
            """
        )

        with self.patched_environ(SSH_TOTP_JUMP_ALIAS=None):
            params = config_v3.SSHConfigLoaderV3(config).get_connection_params("debug")

        self.assertEqual(params["totp_secret"], "SECRETLOWER")

    def test_debug_proxy_uses_wildcard_prompt_for_jump_otp(self):
        calls = []
        resolved_args = []
        old_call = debug_proxy_win.subprocess.call
        old_resolve = debug_proxy_win.ssh_totp.resolve_totp_for_args
        self.addCleanup(lambda: setattr(debug_proxy_win.subprocess, "call", old_call))
        self.addCleanup(lambda: setattr(debug_proxy_win.ssh_totp, "resolve_totp_for_args", old_resolve))

        def fake_resolve(args, config_file):
            resolved_args.append(args)
            return {"alias": "x", "secret": "SECRETLOWER", "prompt": "otp|verification"}

        def fake_call(args, env):
            calls.append((args, env))
            return 0

        debug_proxy_win.ssh_totp.resolve_totp_for_args = fake_resolve
        debug_proxy_win.subprocess.call = fake_call

        with self.patched_environ(SSH_TOTP_JUMP_ALIAS=None):
            self.assertEqual(debug_proxy_win.main(["f102.hn.org", "22"]), 0)
        self.assertEqual(resolved_args, [["x"]])
        self.assertEqual(calls[0][1]["SSH_TOTP_PROMPT_PATTERN"], ".*")
        self.assertEqual(calls[0][1]["SSH_TOTP_REAL_SSH"], r"C:\Windows\System32\OpenSSH\ssh.exe")
        self.assertIn("NumberOfPasswordPrompts=3", " ".join(calls[0][0]))

    def test_askpass_rejects_non_totp_prompts(self):
        with self.assertRaisesRegex(ValueError, "Unsupported SSH prompt"):
            totp_askpass.generate_response("Password:", "JBSWY3DPEHPK3PXP", "otp|verification")

    def test_main_normalizes_batchmode_for_totp_targets(self):
        calls = []

        def fake_resolve(args, config_path=None):
            return {"alias": "x", "secret": "SECRETLOWER", "prompt": "otp"}

        def fake_call(args, env):
            calls.append((args, env))
            return 0

        with self.patched_attr(ssh_totp, "resolve_totp_for_args", fake_resolve):
            with self.patched_attr(ssh_totp, "_real_ssh_executable", lambda: "real-ssh"):
                with self.patched_attr(ssh_totp.subprocess, "call", fake_call):
                    self.assertEqual(
                        ssh_totp.main([
                            "-v",
                            "-o", "BatchMode=yes",
                            "-o", "ServerAliveInterval=15",
                            "x",
                            "true",
                        ]),
                        0,
                    )

        flattened = " ".join(calls[0][0])
        self.assertIn("batchmode=no", flattened)
        self.assertIn("kbdinteractiveauthentication=yes", flattened)
        self.assertIn("numberofpasswordprompts=3", flattened)
        self.assertNotIn("BatchMode=yes", flattened)

    def test_askpass_waits_before_reusing_totp_counter(self):
        secret = "JBSWY3DPEHPK3PXP"
        clock = {"now": 100.0}
        sleeps = []

        def fake_time():
            return clock["now"]

        def fake_sleep(seconds):
            sleeps.append(seconds)
            clock["now"] += seconds

        with tempfile.TemporaryDirectory() as state_dir:
            old_state_dir = os.environ.get("SSH_TOTP_STATE_DIR")
            os.environ["SSH_TOTP_STATE_DIR"] = state_dir
            self.addCleanup(lambda: os.environ.pop("SSH_TOTP_STATE_DIR", None))
            if old_state_dir is not None:
                self.addCleanup(lambda: os.environ.__setitem__("SSH_TOTP_STATE_DIR", old_state_dir))

            with self.patched_attr(totp_askpass.time, "time", fake_time):
                with self.patched_attr(totp_askpass.time, "sleep", fake_sleep):
                    first = totp_askpass.generate_response("otp", secret, "otp")
                    second = totp_askpass.generate_response("otp", secret, "otp")

        self.assertNotEqual(first, second)
        self.assertEqual(len(sleeps), 1)
        self.assertGreaterEqual(sleeps[0], 20)


    def test_native_proxyjump_resolves_gateway_totp(self):
        config = self.write_config(
            """
            # ===== X =====
            # totp_secret: SECRETX
            # totp_prompt: oath
            Host X
                HostName 61.50.130.61
                User zpzeng
                Port 50001

            Host debug
                HostName f102.hn.org
                User zpzeng
                ProxyJump X

            Host f???
                HostName %h.hn.org
                User zpzeng
                ProxyJump X
            """
        )
        self.assertEqual(ssh_totp.resolve_totp_for_args(["debug"], config)["secret"], "SECRETX")
        # glob Host pattern f??? must match f102 and follow ProxyJump to X
        self.assertEqual(ssh_totp.resolve_totp_for_args(["f102"], config)["alias"], "X")

    def test_proxyjump_hop_with_user_and_port(self):
        config = self.write_config(
            """
            # totp_secret: SECRETX
            # totp_prompt: oath
            Host X
                HostName 61.50.130.61
                User zpzeng
                Port 50001
            Host node
                HostName 10.0.0.5
                ProxyJump zpzeng@X:50001
            """
        )
        self.assertEqual(ssh_totp.resolve_totp_for_args(["node"], config)["alias"], "X")

    def test_multiplex_args_added_and_respects_caller(self):
        joined = " ".join(ssh_totp.multiplex_args(["x", "true"]))
        self.assertIn("ControlMaster=auto", joined)
        self.assertIn("ControlPath=", joined)
        self.assertIn("ControlPersist=", joined)
        self.assertNotIn("ControlMaster", " ".join(ssh_totp.multiplex_args(["-M", "x"])))
        self.assertNotIn("ControlPath", " ".join(ssh_totp.multiplex_args(["-o", "ControlPath=/tmp/s", "x"])))

    def test_run_wrapper_uses_askpass_without_multiplex_for_regular_master_command(self):
        calls = []

        def fake_resolve(args, config_path=None):
            return {"alias": "x", "secret": "SECRETLOWER", "prompt": "otp", "master": True}

        def fake_call(args, env):
            calls.append((args, env))
            return 0

        with self.patched_attr(ssh_totp, "resolve_totp_for_args", fake_resolve):
            with self.patched_attr(ssh_totp, "_real_ssh_executable", lambda: "REAL-SSH"):
                with self.patched_attr(ssh_totp.subprocess, "call", fake_call):
                    self.assertEqual(ssh_totp.run_wrapper(["x", "true"]), 0)

        argv, env = calls[0]
        joined = " ".join(argv)
        self.assertEqual(argv[0], "REAL-SSH")
        self.assertIn("batchmode=no", joined)
        self.assertNotIn("ControlMaster", joined)
        self.assertNotIn("ControlPath", joined)
        self.assertEqual(env["SSH_TOTP_SECRET"], "SECRETLOWER")
        self.assertEqual(env["SSH_ASKPASS_REQUIRE"], "force")
        self.assertTrue(env["SSH_ASKPASS"].endswith(("totp_askpass.cmd", "totp_askpass.py")))

    def test_run_wrapper_opens_socks_for_otp_master(self):
        calls = []

        def fake_resolve(args, config_path=None):
            return {"alias": "X", "secret": "SECRETX", "prompt": "otp", "master": True}

        def fake_call(args, env):
            calls.append((args, env))
            return 0

        old_socks = os.environ.get("SSH_OTP_SOCKS")
        os.environ["SSH_OTP_SOCKS"] = "127.0.0.1:7070"
        self.addCleanup(lambda: os.environ.pop("SSH_OTP_SOCKS", None))
        if old_socks is not None:
            self.addCleanup(lambda: os.environ.__setitem__("SSH_OTP_SOCKS", old_socks))

        with self.patched_attr(ssh_totp, "resolve_totp_for_args", fake_resolve):
            with self.patched_attr(ssh_totp, "_real_ssh_executable", lambda: "REAL-SSH"):
                with self.patched_attr(ssh_totp.subprocess, "call", fake_call):
                    self.assertEqual(ssh_totp.run_wrapper(["-MNf", "X"]), 0)

        argv, _env = calls[0]
        self.assertIn("-D", argv)
        self.assertIn("127.0.0.1:7070", argv)
        self.assertIn("ExitOnForwardFailure=yes", argv)

    def test_run_wrapper_uses_askpass_without_multiplex_for_direct_non_master(self):
        calls = []

        def fake_resolve(args, config_path=None):
            return {"alias": "x", "secret": "SECRETLOWER", "prompt": "otp", "master": False}

        def fake_call(args, env):
            calls.append((args, env))
            return 0

        with self.patched_attr(ssh_totp, "resolve_totp_for_args", fake_resolve):
            with self.patched_attr(ssh_totp, "_real_ssh_executable", lambda: "REAL-SSH"):
                with self.patched_attr(ssh_totp.subprocess, "call", fake_call):
                    self.assertEqual(ssh_totp.run_wrapper(["x", "true"]), 0)

        argv, env = calls[0]
        self.assertEqual(argv[0], "REAL-SSH")
        joined = " ".join(argv)
        self.assertIn("batchmode=no", joined)
        self.assertNotIn("ControlMaster", joined)
        self.assertNotIn("ControlPath", joined)
        self.assertEqual(env["SSH_TOTP_SECRET"], "SECRETLOWER")

    def test_proxycommand_socks_resolves_gateway_totp(self):
        config = self.write_config(
            """
            Host debug
                HostName f102.hn.org
                User zpzeng
                ProxyCommand C:/Users/YOU/.ssh/ssh_otp/sshotp.cmd --socks %h %p

            # ===== x =====
            # totp_secret: SECRETLOWER
            # totp_prompt: otp
            # totp_master: yes
            Host x
                HostName 192.168.235.200
                User zpzeng
            """
        )

        self.assertEqual(ssh_totp.resolve_totp_for_args(["debug"], config)["alias"], "x")

    def test_run_wrapper_leaves_non_totp_targets_transparent(self):
        calls = []

        def fake_resolve(args, config_path=None):
            return None

        def fake_call(args, env):
            calls.append((args, env))
            return 0

        with self.patched_attr(ssh_totp, "resolve_totp_for_args", fake_resolve):
            with self.patched_attr(ssh_totp, "_real_ssh_executable", lambda: "REAL-SSH"):
                with self.patched_attr(ssh_totp, "_plain_ssh_executable", lambda: "PLAIN-SSH"):
                    with self.patched_attr(ssh_totp.subprocess, "call", fake_call):
                        self.assertEqual(ssh_totp.run_wrapper(["ty", "true"]), 0)

        argv, env = calls[0]
        self.assertEqual(argv, ["PLAIN-SSH", "ty", "true"])
        joined = " ".join(argv)
        self.assertNotIn("ControlMaster", joined)
        self.assertNotIn("ControlPath", joined)
        self.assertNotIn("ControlPersist", joined)
        self.assertNotIn("SSH_ASKPASS", env)
        self.assertNotIn("SSH_TOTP_SECRET", env)

    def test_run_wrapper_leaves_socks_proxy_targets_transparent(self):
        calls = []

        def fake_resolve(args, config_path=None):
            return {"alias": "X", "secret": "SECRETX", "prompt": "otp", "via_proxy": True}

        def fake_call(args, env):
            calls.append((args, env))
            return 0

        with self.patched_attr(ssh_totp, "resolve_totp_for_args", fake_resolve):
            with self.patched_attr(ssh_totp, "_real_ssh_executable", lambda: "REAL-SSH"):
                with self.patched_attr(ssh_totp, "_plain_ssh_executable", lambda: "PLAIN-SSH"):
                    with self.patched_attr(ssh_totp.subprocess, "call", fake_call):
                        self.assertEqual(ssh_totp.run_wrapper(["f101", "true"]), 0)

        argv, env = calls[0]
        self.assertEqual(argv, ["PLAIN-SSH", "f101", "true"])
        joined = " ".join(argv)
        self.assertNotIn("ControlMaster", joined)
        self.assertNotIn("ControlPath", joined)
        self.assertNotIn("ControlPersist", joined)
        self.assertNotIn("SSH_ASKPASS", env)
        self.assertNotIn("SSH_TOTP_SECRET", env)

    def test_ensure_socks_connection_reuses_running_listener(self):
        import socket

        fake_socket = object()
        starts = []

        with self.patched_attr(socket, "create_connection", lambda *_args, **_kwargs: fake_socket):
            with self.patched_attr(ssh_totp, "run_wrapper", lambda argv: starts.append(argv) or 0):
                result = ssh_totp._ensure_socks_connection("127.0.0.1:7070")

        self.assertIs(result, fake_socket)
        self.assertEqual(starts, [])

    def test_connect_socks_restores_blocking_mode_after_probe(self):
        import socket

        timeouts = []

        class FakeSocket:
            def settimeout(self, value):
                timeouts.append(value)

        fake_socket = FakeSocket()
        with self.patched_attr(socket, "create_connection", lambda *_args, **_kwargs: fake_socket):
            result = ssh_totp._connect_socks("127.0.0.1:7070", timeout=0.5)

        self.assertIs(result, fake_socket)
        self.assertEqual(timeouts, [None])

    def test_ensure_socks_connection_starts_default_gateway(self):
        import socket

        fake_socket = object()
        started = threading.Event()
        starts = []

        def fake_connect(*_args, **_kwargs):
            if not started.is_set():
                raise ConnectionRefusedError("listener absent")
            return fake_socket

        def fake_run(argv):
            starts.append(argv)
            started.set()
            return 0

        with tempfile.TemporaryDirectory() as state_dir:
            with self.patched_environ(SSH_TOTP_STATE_DIR=state_dir, SSH_TOTP_JUMP_ALIAS=None):
                with self.patched_attr(socket, "create_connection", fake_connect):
                    with self.patched_attr(ssh_totp, "run_wrapper", fake_run):
                        result = ssh_totp._ensure_socks_connection("127.0.0.1:7070")

        self.assertIs(result, fake_socket)
        self.assertEqual(starts, [["-MNf", "-D", "127.0.0.1:7070", "x"]])

    def test_ensure_socks_connection_reports_gateway_start_failure(self):
        import socket

        def missing_listener(*_args, **_kwargs):
            raise ConnectionRefusedError("listener absent")

        with tempfile.TemporaryDirectory() as state_dir:
            with self.patched_environ(SSH_TOTP_STATE_DIR=state_dir):
                with self.patched_attr(socket, "create_connection", missing_listener):
                    with self.patched_attr(ssh_totp, "run_wrapper", lambda _argv: 23):
                        with self.assertRaisesRegex(RuntimeError, "automatic gateway start failed.*23"):
                            ssh_totp._ensure_socks_connection("127.0.0.1:7070")

    def test_concurrent_socks_connections_start_gateway_once(self):
        import socket

        fake_socket = object()
        started = threading.Event()
        first_checks = threading.Barrier(2)
        local = threading.local()
        starts = []
        start_guard = threading.Lock()

        def fake_connect(*_args, **_kwargs):
            if started.is_set():
                return fake_socket
            if not getattr(local, "did_initial_check", False):
                local.did_initial_check = True
                first_checks.wait(timeout=2)
            raise ConnectionRefusedError("listener absent")

        def fake_run(argv):
            with start_guard:
                starts.append(argv)
            started.set()
            return 0

        results = []
        errors = []

        def worker():
            try:
                results.append(ssh_totp._ensure_socks_connection("127.0.0.1:7070"))
            except Exception as exc:
                errors.append(exc)

        with tempfile.TemporaryDirectory() as state_dir:
            with self.patched_environ(SSH_TOTP_STATE_DIR=state_dir):
                with self.patched_attr(socket, "create_connection", fake_connect):
                    with self.patched_attr(ssh_totp, "run_wrapper", fake_run):
                        threads = [threading.Thread(target=worker) for _ in range(2)]
                        for thread in threads:
                            thread.start()
                        for thread in threads:
                            thread.join(timeout=3)

        self.assertFalse(errors)
        self.assertEqual(results, [fake_socket, fake_socket])
        self.assertEqual(len(starts), 1)

    def test_socks_relay_drains_client_disconnect_after_remote_eof(self):
        import socket

        sent = []
        writes = []
        closed = []
        shutdowns = []

        class FakeFile:
            def __init__(self, fd):
                self.fd = fd

            def fileno(self):
                return self.fd

        class FakeSocket:
            def __init__(self):
                self.recv_chunks = [
                    b"\x05\x00",
                    b"\x05\x00\x00\x01",
                    b"\x00\x00\x00\x00\x00\x00",
                    b"",
                ]

            def sendall(self, data):
                sent.append(data)

            def recv(self, _size):
                return self.recv_chunks.pop(0)

            def shutdown(self, how):
                shutdowns.append(how)

            def close(self):
                pass

        reads = [b"client-disconnect", b""]
        read_started = threading.Event()

        def fake_read(_fd, _size):
            read_started.set()
            if reads:
                time.sleep(0.05)
                return reads.pop(0)
            return b""

        def fake_write(_fd, data):
            writes.append(data)
            return len(data)

        fake_socket = FakeSocket()

        with self.patched_attr(socket, "create_connection", lambda *_args, **_kwargs: fake_socket):
            with self.patched_attr(ssh_totp.sys, "stdin", FakeFile(100)):
                with self.patched_attr(ssh_totp.sys, "stdout", FakeFile(200)):
                    with self.patched_attr(ssh_totp.os, "read", fake_read):
                        with self.patched_attr(ssh_totp.os, "write", fake_write):
                            with self.patched_attr(ssh_totp.os, "close", lambda fd: closed.append(fd)):
                                start = time.monotonic()
                                self.assertEqual(ssh_totp._socks_relay("f101.hn.org", "22"), 0)
                                elapsed = time.monotonic() - start

        self.assertTrue(read_started.is_set())
        self.assertGreaterEqual(elapsed, 0.04)
        self.assertIn(b"client-disconnect", sent)
        self.assertIn(200, closed)
        self.assertEqual(writes, [])
        self.assertTrue(shutdowns)

    def test_run_wrapper_prunes_stale_control_socket_for_direct_totp(self):
        calls = []
        removed = []

        def fake_resolve(args, config_path=None):
            return {"alias": "x", "secret": "SECRETLOWER", "prompt": "otp", "via_proxy": False, "master": True}

        def fake_run(args, **kwargs):
            if "-G" in args:
                return __import__("subprocess").CompletedProcess(args, 0, "controlpath C:/tmp/ssh-otp-stale\n", "")
            if "-O" in args:
                return __import__("subprocess").CompletedProcess(args, 255, "", "stale\n")
            raise AssertionError(args)

        def fake_call(args, env):
            calls.append((args, env))
            return 0

        with self.patched_attr(ssh_totp, "resolve_totp_for_args", fake_resolve):
            with self.patched_attr(ssh_totp, "_real_ssh_executable", lambda: "REAL-SSH"):
                with self.patched_attr(ssh_totp.subprocess, "run", fake_run):
                    with self.patched_attr(ssh_totp.subprocess, "call", fake_call):
                        with self.patched_attr(ssh_totp.os.path, "exists", lambda path: path == "C:/tmp/ssh-otp-stale"):
                            with self.patched_attr(ssh_totp.os, "unlink", lambda path: removed.append(path)):
                                self.assertEqual(ssh_totp.run_wrapper(["-MNf", "x"]), 0)

        self.assertEqual(removed, ["C:/tmp/ssh-otp-stale"])
        self.assertEqual(calls[0][0][0], "REAL-SSH")

    def test_real_ssh_discovery_override_and_never_self(self):
        old = os.environ.get("SSH_TOTP_REAL_SSH")

        def restore():
            if old is None:
                os.environ.pop("SSH_TOTP_REAL_SSH", None)
            else:
                os.environ["SSH_TOTP_REAL_SSH"] = old

        self.addCleanup(restore)

        os.environ["SSH_TOTP_REAL_SSH"] = sys.executable
        self.assertEqual(ssh_totp._real_ssh_executable(), sys.executable)

        os.environ.pop("SSH_TOTP_REAL_SSH", None)
        try:
            found = ssh_totp._real_ssh_executable()
        except FileNotFoundError:
            self.skipTest("no ssh on this machine")
        # discovered ssh must never live inside our package (that would recurse)
        self.assertFalse(ssh_totp._under_dir(found, str(SCRIPT_DIR)))


if __name__ == "__main__":
    unittest.main()
