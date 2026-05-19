#!/usr/bin/env python3

import os
import subprocess
import sys
import unittest
from unittest.mock import patch, MagicMock


class TestEicRunNormalExecution(unittest.TestCase):
    """Test that successful child execution propagates exit code 0."""

    @patch('subprocess.run')
    @patch('os.path.isfile', return_value=True)
    def test_normal_exit_zero(self, mock_isfile, mock_run):
        mock_run.return_value = MagicMock(returncode=0)

        with self.assertRaises(SystemExit) as ctx:
            runpy_exec('testuser')

        self.assertEqual(ctx.exception.code, 0)
        mock_run.assert_called_once()

    @patch('subprocess.run')
    @patch('os.path.isfile', return_value=True)
    def test_exit_code_propagation_nonzero(self, mock_isfile, mock_run):
        """Non-zero child exit code should be propagated."""
        mock_run.return_value = MagicMock(returncode=1)

        with self.assertRaises(SystemExit) as ctx:
            runpy_exec('testuser')

        self.assertEqual(ctx.exception.code, 1)

    @patch('subprocess.run')
    @patch('os.path.isfile', return_value=True)
    def test_exit_code_255_propagation(self, mock_isfile, mock_run):
        """Exit code 255 from child should be propagated."""
        mock_run.return_value = MagicMock(returncode=255)

        with self.assertRaises(SystemExit) as ctx:
            runpy_exec('testuser')

        self.assertEqual(ctx.exception.code, 255)


class TestEicRunTimeout(unittest.TestCase):
    """Test timeout handling."""

    @patch('subprocess.run', side_effect=subprocess.TimeoutExpired(cmd='test', timeout=15))
    @patch('os.path.isfile', return_value=True)
    def test_timeout_exits_zero(self, mock_isfile, mock_run):
        """Timeout should exit 0 (fail-open for SSH auth)."""
        with self.assertRaises(SystemExit) as ctx:
            runpy_exec('testuser')

        self.assertEqual(ctx.exception.code, 0)

    @patch('subprocess.run')
    @patch('os.path.isfile', return_value=True)
    def test_timeout_value_is_15(self, mock_isfile, mock_run):
        """Production timeout should be 15 seconds, not 5."""
        mock_run.return_value = MagicMock(returncode=0)

        with self.assertRaises(SystemExit):
            runpy_exec('testuser')

        _args, kwargs = mock_run.call_args
        self.assertEqual(kwargs.get('timeout', _args[1] if len(_args) > 1 else None), 15,
                         "Timeout must be 15 seconds to match production eic_run.py")


class TestEicRunScriptNotFound(unittest.TestCase):
    """Test behaviour when eic_curl.py is missing."""

    @patch('os.path.isfile', return_value=False)
    @patch('sys.stderr', new_callable=MagicMock)
    def test_missing_script_exits_127(self, mock_stderr, mock_isfile):
        with self.assertRaises(SystemExit) as ctx:
            runpy_exec('testuser')

        self.assertEqual(ctx.exception.code, 127)


class TestEicRunArgumentPassing(unittest.TestCase):
    """Test that arguments are forwarded to the child process."""

    @patch('subprocess.run')
    @patch('os.path.isfile', return_value=True)
    def test_username_forwarded(self, mock_isfile, mock_run):
        mock_run.return_value = MagicMock(returncode=0)

        with self.assertRaises(SystemExit):
            runpy_exec('ec2-user')

        cmd = mock_run.call_args[0][0]
        self.assertIn('ec2-user', cmd)

    @patch('subprocess.run')
    @patch('os.path.isfile', return_value=True)
    def test_extra_args_forwarded(self, mock_isfile, mock_run):
        mock_run.return_value = MagicMock(returncode=0)

        with self.assertRaises(SystemExit):
            runpy_exec('testuser', 'SHA256:extraarg')

        cmd = mock_run.call_args[0][0]
        self.assertIn('testuser', cmd)
        self.assertIn('SHA256:extraarg', cmd)

    @patch('subprocess.run')
    @patch('os.path.isfile', return_value=True)
    def test_command_starts_with_python_and_eic_curl(self, mock_isfile, mock_run):
        """Child command should be [sys.executable, .../eic_curl.py, ...]."""
        mock_run.return_value = MagicMock(returncode=0)

        with self.assertRaises(SystemExit):
            runpy_exec('testuser')

        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[0], sys.executable)
        self.assertTrue(cmd[1].endswith('eic_curl.py'))


# ---------------------------------------------------------------------------
# Helper: run the real eic_run.py __main__ block via runpy
# ---------------------------------------------------------------------------
def runpy_exec(*args):
    """Execute eic_run.py's __main__ block with the given CLI arguments.

    This uses runpy.run_path so that the real production code is exercised
    (the module's ``if __name__ == "__main__"`` block) instead of a copy.
    """
    import runpy
    script = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'eic_run.py')
    with patch.object(sys, 'argv', ['eic_run.py'] + list(args)):
        runpy.run_path(script, run_name='__main__')


if __name__ == '__main__':
    unittest.main()
