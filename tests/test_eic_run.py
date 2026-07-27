#!/usr/bin/env python3

import os
import subprocess
import sys
import syslog
import unittest
from unittest.mock import patch, MagicMock


class TestEicRunNormalExecution(unittest.TestCase):
    """Test that successful child execution propagates exit code 0."""

    @patch('subprocess.run')
    def test_normal_exit_zero(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout=b'')

        with self.assertRaises(SystemExit) as ctx:
            runpy_exec('testuser')

        self.assertEqual(ctx.exception.code, 0)
        mock_run.assert_called_once()

    @patch('subprocess.run')
    def test_stdout_written_on_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout=b'ssh-rsa AAAA...\n')

        with patch('sys.stdout.buffer.write') as mock_write:
            with self.assertRaises(SystemExit) as ctx:
                runpy_exec('testuser')

        self.assertEqual(ctx.exception.code, 0)
        mock_write.assert_called_once_with(b'ssh-rsa AAAA...\n')

    @patch('subprocess.run')
    def test_exit_code_propagation_nonzero(self, mock_run):
        """Non-zero child exit code should be propagated."""
        mock_run.return_value = MagicMock(returncode=1, stdout=b'')

        with self.assertRaises(SystemExit) as ctx:
            runpy_exec('testuser')

        self.assertEqual(ctx.exception.code, 1)

    @patch('subprocess.run')
    def test_exit_code_255_propagation(self, mock_run):
        """Exit code 255 from child should be propagated."""
        mock_run.return_value = MagicMock(returncode=255, stdout=b'')

        with self.assertRaises(SystemExit) as ctx:
            runpy_exec('testuser')

        self.assertEqual(ctx.exception.code, 255)


class TestEicRunTimeout(unittest.TestCase):
    """Test timeout handling."""

    @patch('syslog.syslog')
    @patch('subprocess.run', side_effect=subprocess.TimeoutExpired(cmd='test', timeout=5))
    def test_timeout_exits_124(self, mock_run, mock_syslog):
        """Timeout should exit 124 and not leak partial stdout to sshd."""
        with self.assertRaises(SystemExit) as ctx:
            runpy_exec('testuser')

        self.assertEqual(ctx.exception.code, 124)
        mock_syslog.assert_any_call(
            syslog.LOG_AUTHPRIV | syslog.LOG_INFO,
            "EC2 Instance Connect timed out.",
        )

    @patch('subprocess.run')
    def test_timeout_value_is_5(self, mock_run):
        """Timeout should be 5 seconds."""
        mock_run.return_value = MagicMock(returncode=0, stdout=b'')

        with self.assertRaises(SystemExit):
            runpy_exec('testuser')

        _args, kwargs = mock_run.call_args
        self.assertEqual(kwargs.get('timeout'), 5)
        self.assertTrue(kwargs.get('capture_output'))


class TestEicRunUsernameValidation(unittest.TestCase):
    """Username format is validated at the AuthorizedKeysCommand entry point."""

    @patch('syslog.syslog')
    @patch('subprocess.run')
    def test_invalid_username_exits_1(self, mock_run, _mock_syslog):
        with self.assertRaises(SystemExit) as ctx:
            runpy_exec('../etc/passwd')

        self.assertEqual(ctx.exception.code, 1)
        mock_run.assert_not_called()

    @patch('syslog.syslog')
    @patch('subprocess.run')
    def test_valid_username_runs_child(self, mock_run, _mock_syslog):
        mock_run.return_value = MagicMock(returncode=0, stdout=b'')

        with self.assertRaises(SystemExit) as ctx:
            runpy_exec('ec2-user')

        self.assertEqual(ctx.exception.code, 0)
        mock_run.assert_called_once()

    @patch('syslog.syslog')
    def test_missing_username_exits_1(self, _mock_syslog):
        import runpy
        script = _eic_run_script()
        with patch.object(sys, 'argv', ['eic_run.py']):
            with self.assertRaises(SystemExit) as ctx:
                runpy.run_path(script, run_name='__main__')
        self.assertEqual(ctx.exception.code, 1)


class TestEicRunArgumentPassing(unittest.TestCase):
    """Test that arguments are forwarded to the child process."""

    @patch('subprocess.run')
    def test_username_forwarded(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout=b'')

        with self.assertRaises(SystemExit):
            runpy_exec('ec2-user')

        cmd = mock_run.call_args[0][0]
        self.assertIn('ec2-user', cmd)

    @patch('subprocess.run')
    def test_extra_args_forwarded(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout=b'')

        with self.assertRaises(SystemExit):
            runpy_exec('testuser', 'SHA256:extraarg')

        cmd = mock_run.call_args[0][0]
        self.assertIn('testuser', cmd)
        self.assertIn('SHA256:extraarg', cmd)

    @patch('subprocess.run')
    def test_command_uses_module_invocation(self, mock_run):
        """Child command should be [sys.executable, -m, ec2_instance_connect_rhel.eic_curl, ...]."""
        mock_run.return_value = MagicMock(returncode=0, stdout=b'')

        with self.assertRaises(SystemExit):
            runpy_exec('testuser')

        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[0], sys.executable)
        self.assertEqual(cmd[1], '-m')
        self.assertEqual(cmd[2], 'ec2_instance_connect_rhel.eic_curl')


# ---------------------------------------------------------------------------
# Helper: run the real eic_run.py __main__ block via runpy
# ---------------------------------------------------------------------------
def _eic_run_script():
    """Return the absolute path to eic_run.py inside the installed package."""
    import ec2_instance_connect_rhel.eic_run as mod
    return os.path.abspath(mod.__file__)


def runpy_exec(*args):
    """Execute eic_run.py's __main__ block with the given CLI arguments.

    This uses runpy.run_path so that the real production code is exercised
    (the module's ``if __name__ == "__main__"`` block) instead of a copy.
    """
    import runpy
    script = _eic_run_script()
    with patch.object(sys, 'argv', ['eic_run.py'] + list(args)):
        runpy.run_path(script, run_name='__main__')


if __name__ == '__main__':
    unittest.main()
