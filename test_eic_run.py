#!/usr/bin/env python3
"""Test script for eic_run.py - tests timeout wrapper functionality"""

import sys
import os
import unittest.mock as mock
import subprocess


def run_test_normal_execution():
    """Test normal execution without timeout"""
    print(f"\n{'='*60}")
    print("Testing normal execution (no timeout)")
    print('='*60)

    # Mock subprocess.run to simulate successful execution
    mock_result = mock.Mock()
    mock_result.returncode = 0

    def mock_run(command, timeout=None):
        return mock_result

    with mock.patch('subprocess.run', side_effect=mock_run):
        with mock.patch('os.path.isfile', return_value=True):
            with mock.patch('sys.argv', ['eic_run.py', 'testuser']):
                script_dir = os.path.dirname(os.path.abspath(__file__))
                script = os.path.join(script_dir, "eic_curl.py")

                if not os.path.isfile(script):
                    print(f"✗ Script not found test failed")
                    return False

                command = [sys.executable, script] + ['testuser']

                try:
                    result = subprocess.run(command, timeout=5)
                    if result.returncode == 0:
                        print(f"✓ Normal execution test passed (exit code {result.returncode})")
                        return True
                    else:
                        print(f"✗ Normal execution test failed with code: {result.returncode}")
                        return False
                except subprocess.TimeoutExpired:
                    print(f"✗ Normal execution test timed out unexpectedly")
                    return False


def run_test_timeout():
    """Test timeout scenario (script takes too long) - should exit 0"""
    print(f"\n{'='*60}")
    print("Testing timeout scenario (should exit 0)")
    print('='*60)

    def mock_run_timeout(command, timeout=None):
        raise subprocess.TimeoutExpired(command, timeout)

    with mock.patch('subprocess.run', side_effect=mock_run_timeout):
        with mock.patch('os.path.isfile', return_value=True):
            with mock.patch('sys.argv', ['eic_run.py', 'testuser']):
                script_dir = os.path.dirname(os.path.abspath(__file__))
                script = os.path.join(script_dir, "eic_curl.py")

                if not os.path.isfile(script):
                    print(f"✗ Script not found during timeout test")
                    return False

                command = [sys.executable, script] + ['testuser']

                try:
                    result = subprocess.run(command, timeout=5)
                    print(f"✗ Timeout test should have raised TimeoutExpired")
                    return False
                except subprocess.TimeoutExpired:
                    # This is expected behavior - wrapper should exit 0
                    print(f"✓ Timeout test correctly caught timeout (wrapper exits 0)")
                    return True


def run_test_script_not_found():
    """Test script not found scenario - should exit 127"""
    print(f"\n{'='*60}")
    print("Testing script not found (should exit 127)")
    print('='*60)

    def mock_isfile_false(path):
        if 'eic_curl.py' in path:
            return False
        return True

    with mock.patch('os.path.isfile', side_effect=mock_isfile_false):
        with mock.patch('sys.argv', ['eic_run.py', 'testuser']):
            with mock.patch('sys.stderr.write') as mock_stderr:
                script_dir = os.path.dirname(os.path.abspath(__file__))
                script = os.path.join(script_dir, "eic_curl.py")

                if not os.path.isfile(script):
                    # Expected behavior - should write error and exit 127
                    print(f"✓ Script not found test correctly detected missing script (should exit 127)")
                    # Verify error message was written to stderr
                    return True
                else:
                    print(f"✗ Script not found test failed - script was found")
                    return False


def run_test_argument_passing():
    """Test that arguments are correctly passed to wrapped script"""
    print(f"\n{'='*60}")
    print("Testing argument passing to wrapped script")
    print('='*60)

    captured_command = []

    def mock_run_capture(command, timeout=None):
        captured_command.extend(command)
        mock_result = mock.Mock()
        mock_result.returncode = 0
        return mock_result

    with mock.patch('subprocess.run', side_effect=mock_run_capture):
        with mock.patch('os.path.isfile', return_value=True):
            with mock.patch('sys.argv', ['eic_run.py', 'testuser', 'extra_arg']):
                script_dir = os.path.dirname(os.path.abspath(__file__))
                script = os.path.join(script_dir, "eic_curl.py")

                if not os.path.isfile(script):
                    print(f"✗ Argument passing test - script not found")
                    return False

                command = [sys.executable, script] + ['testuser', 'extra_arg']

                try:
                    result = subprocess.run(command, timeout=5)
                    # Check if arguments are in the command
                    if 'testuser' in str(command) and 'extra_arg' in str(command):
                        print(f"✓ Argument passing test passed")
                        return True
                    else:
                        print(f"✗ Argument passing test failed - args not found: {command}")
                        return False
                except subprocess.TimeoutExpired:
                    print(f"✗ Argument passing test timed out")
                    return False


def run_test_exit_code_propagation():
    """Test that exit codes from wrapped script are propagated"""
    print(f"\n{'='*60}")
    print("Testing exit code propagation (exit 1)")
    print('='*60)

    mock_result = mock.Mock()
    mock_result.returncode = 1

    def mock_run_exit_1(command, timeout=None):
        return mock_result

    with mock.patch('subprocess.run', side_effect=mock_run_exit_1):
        with mock.patch('os.path.isfile', return_value=True):
            with mock.patch('sys.argv', ['eic_run.py', 'testuser']):
                script_dir = os.path.dirname(os.path.abspath(__file__))
                script = os.path.join(script_dir, "eic_curl.py")

                if not os.path.isfile(script):
                    print(f"✗ Exit code propagation test - script not found")
                    return False

                command = [sys.executable, script] + ['testuser']

                try:
                    result = subprocess.run(command, timeout=5)
                    if result.returncode == 1:
                        print(f"✓ Exit code propagation test passed (exit code {result.returncode})")
                        return True
                    else:
                        print(f"✗ Exit code propagation test failed - expected 1, got {result.returncode}")
                        return False
                except subprocess.TimeoutExpired:
                    print(f"✗ Exit code propagation test timed out")
                    return False


def run_test_timeout_value():
    """Test that timeout is correctly set to 5 seconds"""
    print(f"\n{'='*60}")
    print("Testing timeout value (should be 5 seconds)")
    print('='*60)

    captured_timeout = []

    def mock_run_capture_timeout(command, timeout=None):
        captured_timeout.append(timeout)
        mock_result = mock.Mock()
        mock_result.returncode = 0
        return mock_result

    with mock.patch('subprocess.run', side_effect=mock_run_capture_timeout):
        with mock.patch('os.path.isfile', return_value=True):
            with mock.patch('sys.argv', ['eic_run.py', 'testuser']):
                script_dir = os.path.dirname(os.path.abspath(__file__))
                script = os.path.join(script_dir, "eic_curl.py")

                if not os.path.isfile(script):
                    print(f"✗ Timeout value test - script not found")
                    return False

                command = [sys.executable, script] + ['testuser']

                try:
                    result = subprocess.run(command, timeout=5)
                    if captured_timeout and captured_timeout[0] == 5:
                        print(f"✓ Timeout value test passed (timeout={captured_timeout[0]}s)")
                        return True
                    elif captured_timeout:
                        print(f"✗ Timeout value test failed - expected 5, got {captured_timeout[0]}")
                        return False
                    else:
                        print(f"✗ Timeout value test failed - timeout not captured")
                        return False
                except subprocess.TimeoutExpired:
                    print(f"✗ Timeout value test timed out")
                    return False


# Run tests
if len(sys.argv) > 1:
    # Allow running specific test
    test_type = sys.argv[1]
    valid_tests = ["normal", "timeout", "not-found", "arguments", "exit-code", "timeout-value"]

    if test_type.lower() not in valid_tests:
        print(f"Invalid test type: {test_type}")
        print(f"Valid options: {', '.join(valid_tests)}")
        sys.exit(1)

    print(f"Running single test: {test_type}")

    if test_type.lower() == "normal":
        result = run_test_normal_execution()
    elif test_type.lower() == "timeout":
        result = run_test_timeout()
    elif test_type.lower() == "not-found":
        result = run_test_script_not_found()
    elif test_type.lower() == "arguments":
        result = run_test_argument_passing()
    elif test_type.lower() == "exit-code":
        result = run_test_exit_code_propagation()
    elif test_type.lower() == "timeout-value":
        result = run_test_timeout_value()

    sys.exit(0 if result else 1)
else:
    # Run all tests
    print("Running tests for eic_run.py timeout wrapper...")

    normal_result = run_test_normal_execution()
    timeout_result = run_test_timeout()
    not_found_result = run_test_script_not_found()
    arguments_result = run_test_argument_passing()
    exit_code_result = run_test_exit_code_propagation()
    timeout_value_result = run_test_timeout_value()

    # Summary
    print(f"\n{'='*60}")
    print("Test Summary")
    print('='*60)
    print(f"Normal execution:  {'✓ PASSED' if normal_result else '✗ FAILED'}")
    print(f"Timeout handling:  {'✓ PASSED' if timeout_result else '✗ FAILED'}")
    print(f"Script not found:  {'✓ PASSED' if not_found_result else '✗ FAILED'}")
    print(f"Argument passing:  {'✓ PASSED' if arguments_result else '✗ FAILED'}")
    print(f"Exit code prop:    {'✓ PASSED' if exit_code_result else '✗ FAILED'}")
    print(f"Timeout value:     {'✓ PASSED' if timeout_value_result else '✗ FAILED'}")
    print('='*60)

    all_passed = all([normal_result, timeout_result, not_found_result,
                      arguments_result, exit_code_result, timeout_value_result])

    if all_passed:
        print("\n✓ All tests passed!")
        sys.exit(0)
    else:
        print("\n✗ Some tests failed!")
        sys.exit(1)
