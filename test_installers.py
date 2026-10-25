import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import configure_ssh


VALID_SECRET = "JBSWY3DPEHPK3PXP"


class ConfigureSSHTests(unittest.TestCase):
    def run_configure(self, args, secret=VALID_SECRET):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with patch.dict(os.environ, {"SSH_TOTP_SECRET": secret}, clear=False):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = configure_ssh.main([*args, "--non-interactive"])
        return result, stdout.getvalue(), stderr.getvalue()

    def test_windows_config_is_generated_and_updated_idempotently(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / ".ssh" / "config"
            config.parent.mkdir(parents=True)
            config.write_text("Host existing\n    HostName existing.example\n", encoding="utf-8")
            wrapper_dir = root / "ssh otp"
            args = [
                "--config", str(config),
                "--wrapper-dir", str(wrapper_dir),
                "--platform", "windows",
                "--jump-host", "gateway.example.com",
                "--jump-user", "alice",
                "--jump-port", "50001",
                "--host", "compute=compute.internal,alice,2222",
            ]

            first, first_out, first_err = self.run_configure(args)
            self.assertEqual(first, 0, first_err)
            content = config.read_text(encoding="utf-8")
            self.assertTrue(content.startswith(configure_ssh.BLOCK_BEGIN))
            self.assertIn("Host x", content)
            self.assertIn("Host compute", content)
            self.assertIn("Port 2222", content)
            self.assertRegex(content, r'ProxyCommand ".*ssh otp/sshotp\.cmd" --gateway x --socks %h %p')
            self.assertIn("Host existing", content)
            self.assertNotIn(VALID_SECRET, first_out)
            backups = list(config.parent.glob("config.bak-ssh-otp-*"))
            self.assertEqual(len(backups), 1)

            second, second_out, second_err = self.run_configure(args)
            self.assertEqual(second, 0, second_err)
            self.assertIn("unchanged", second_out)
            self.assertEqual(config.read_text(encoding="utf-8").count(configure_ssh.BLOCK_BEGIN), 1)
            self.assertEqual(len(list(config.parent.glob("config.bak-ssh-otp-*"))), 1)

    def test_posix_config_uses_posix_launcher(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "config"
            result, output, error = self.run_configure([
                "--config", str(config),
                "--wrapper-dir", str(root / "ssh_otp"),
                "--platform", "posix",
                "--jump-host", "gateway.example.com",
                "--jump-user", "alice",
                "--host", "compute=compute.internal",
            ])
            self.assertEqual(result, 0, error)
            content = config.read_text(encoding="utf-8")
            self.assertIn("/sshotp --gateway x --socks %h %p", content)
            self.assertNotIn("sshotp.cmd", content)
            self.assertNotIn(VALID_SECRET, output)

    def test_multiline_secret_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = Path(temp_dir) / "config"
            result, output, error = self.run_configure(
                [
                    "--config", str(config),
                    "--jump-host", "gateway.example.com",
                    "--jump-user", "alice",
                ],
                secret=f"{VALID_SECRET}\n{VALID_SECRET}",
            )
            self.assertEqual(result, 2)
            self.assertIn("single line", error)
            self.assertFalse(config.exists())

    def test_two_gateways_are_both_kept(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "config"
            args = [
                "--config", str(config),
                "--wrapper-dir", str(root / "ssh_otp"),
                "--platform", "posix",
                "--jump-host", "internal.example.com",
                "--jump-user", "alice",
                "--base", "X=public.example.com,alice,50001",
                "--host", "compute=compute.internal,alice,22@X",
            ]
            first, out, err = self.run_configure(args)
            self.assertEqual(first, 0, err)
            content = config.read_text(encoding="utf-8")
            self.assertIn("Host x", content)
            self.assertIn("Host X", content)
            self.assertIn("HostName public.example.com", content)
            self.assertIn("Port 50001", content)
            self.assertEqual(content.count("# totp_master: yes"), 2)
            self.assertIn("--gateway X --socks %h %p", content)

            second, out2, err2 = self.run_configure(args)
            self.assertEqual(second, 0, err2)
            self.assertIn("unchanged", out2)
            self.assertEqual(config.read_text(encoding="utf-8"), content)

    def test_host_with_unknown_base_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "config"
            result, output, error = self.run_configure([
                "--config", str(config),
                "--jump-host", "gateway.example.com",
                "--jump-user", "alice",
                "--host", "compute=compute.internal@missing",
            ])
            self.assertEqual(result, 2)
            self.assertIn("unknown base", error)
            self.assertFalse(config.exists())

    def test_host_alias_that_already_exists_warns_about_shadowing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "config"
            config.write_text(
                "Host compute\n    HostName direct.example.com\n", encoding="utf-8"
            )
            result, output, error = self.run_configure([
                "--config", str(config),
                "--jump-host", "gateway.example.com",
                "--jump-user", "alice",
                "--host", "compute=compute.internal",
            ])
            self.assertEqual(result, 0, error)
            self.assertIn("already exist outside the managed block", error)
            self.assertIn("compute", error)
            self.assertNotIn(VALID_SECRET, output)

    def test_dry_run_redacts_secret_and_does_not_write(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = Path(temp_dir) / "config"
            result, output, error = self.run_configure([
                "--config", str(config),
                "--jump-host", "gateway.example.com",
                "--jump-user", "alice",
                "--dry-run",
            ])
            self.assertEqual(result, 0, error)
            self.assertIn("# totp_secret: <redacted>", output)
            self.assertNotIn(VALID_SECRET, output)
            self.assertFalse(config.exists())

    def test_invalid_secret_is_rejected_without_writing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = Path(temp_dir) / "config"
            result, _output, error = self.run_configure([
                "--config", str(config),
                "--jump-host", "gateway.example.com",
                "--jump-user", "alice",
            ], secret="not-base32!")
            self.assertEqual(result, 2)
            self.assertIn("Base32", error)
            self.assertFalse(config.exists())


class InstallerPortabilityTests(unittest.TestCase):
    def test_windows_launchers_have_no_machine_specific_python_path(self):
        launchers = [
            "configure.cmd",
            "debug_proxy.cmd",
            "find_python.cmd",
            "sshotp.cmd",
            "totp_askpass.cmd",
        ]
        combined = "\n".join((SCRIPT_DIR / name).read_text(encoding="utf-8") for name in launchers)
        self.assertNotIn("C:\\Users\\", combined)
        self.assertIn("SSH_TOTP_PYTHON", combined)

        otpctl = (SCRIPT_DIR / "otpctl.cmd").read_text(encoding="utf-8")
        self.assertIn('set "HOSTS=x"', otpctl)
        self.assertNotIn('set "HOSTS=X"', otpctl)

        install_ps1 = (SCRIPT_DIR / "install.ps1").read_text(encoding="utf-8")
        install_sh = (SCRIPT_DIR / "install.sh").read_text(encoding="utf-8")
        self.assertIn("$gitCommand", install_ps1)
        self.assertIn("git_command=", install_sh)

    @unittest.skipUnless(os.name == "nt", "Windows launcher test runs on Windows")
    def test_windows_configure_launcher_discovers_python(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = Path(temp_dir) / "config"
            env = os.environ.copy()
            env.pop("SSH_TOTP_PYTHON", None)
            env["SSH_TOTP_SECRET"] = VALID_SECRET
            completed = subprocess.run(
                [
                    "cmd.exe", "/d", "/c", str(SCRIPT_DIR / "configure.cmd"),
                    "--config", str(config),
                    "--jump-host", "gateway.example.com",
                    "--jump-user", "alice",
                    "--non-interactive",
                    "--dry-run",
                ],
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("# totp_secret: <redacted>", completed.stdout)
            self.assertNotIn(VALID_SECRET, completed.stdout)
            self.assertFalse(config.exists())

    @unittest.skipUnless(os.name == "nt", "PowerShell installer test runs on Windows")
    def test_windows_installer_is_idempotent_in_isolated_profile(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            profile = root / "profile.ps1"
            home = root / "home"
            command = [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-File", str(SCRIPT_DIR / "install.ps1"),
                "-HomeDir", str(home),
                "-ProfilePath", str(profile),
                "-SkipGitConfig",
            ]
            for _ in range(2):
                completed = subprocess.run(command, capture_output=True, text=True, timeout=30)
                self.assertEqual(completed.returncode, 0, completed.stderr)
            content = profile.read_text(encoding="utf-8-sig")
            self.assertEqual(content.count("# >>> ssh-otp >>>"), 1)
            self.assertIn("SSH_TOTP_PYTHON", content)
            self.assertIn("param([string[]]$Hosts=@('x'))", content)
            self.assertTrue((home / ".ssh" / "cm").is_dir())

    def test_posix_scripts_parse_with_available_sh(self):
        shell = shutil.which("sh")
        if not shell:
            self.skipTest("POSIX sh is not available on this machine")
        for name in ("configure", "install.sh", "shellrc.sh", "sshotp"):
            completed = subprocess.run(
                [shell, "-n", str(SCRIPT_DIR / name)],
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(completed.returncode, 0, f"{name}: {completed.stderr}")

        shellrc = (SCRIPT_DIR / "shellrc.sh").read_text(encoding="utf-8")
        self.assertIn("otp_up()", shellrc)
        self.assertIn("alias otp-up=otp_up", shellrc)


if __name__ == "__main__":
    unittest.main()
