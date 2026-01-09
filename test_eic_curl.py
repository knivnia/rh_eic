#!/usr/bin/env python3
"""Test script for eic_curl.py - mocks IMDS calls for local testing"""

import sys
import unittest.mock as mock

# Create mock IMDS responses
def mock_urlopen(request, timeout=None):
    """Mock urlopen to simulate IMDS responses"""
    class MockResponse:
        def __init__(self, data):
            self.data = data

        def read(self):
            return self.data.encode('utf-8')

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    url = request.get_full_url() if hasattr(request, 'get_full_url') else str(request)

    # Mock token endpoint
    if 'api/token' in url:
        return MockResponse('mock-token-12345')

    # Mock instance-id endpoint
    if 'instance-id' in url:
        return MockResponse('i-1234567890abcdef0')

    # Mock active-keys endpoint (HEAD request returns empty response with 200 status)
    if 'active-keys' in url:
        return MockResponse('')

    return MockResponse('mock-data')


def mock_getpwnam(username):
    """Mock pwd.getpwnam to simulate user exists"""
    class MockPwdEntry:
        pw_name = username
        pw_passwd = 'x'
        pw_uid = 1000
        pw_gid = 1000
        pw_gecos = 'Test User'
        pw_dir = f'/home/{username}'
        pw_shell = '/bin/bash'
    return MockPwdEntry()


def run_test_invalid(instance_type):
    """Run test for invalid instance (mismatched ID or bad UUID)"""
    print(f"\n{'='*60}")
    print(f"Testing {instance_type} instance type (INVALID - should fail)")
    print('='*60)

    def mock_isfile_nitro_invalid(path):
        if 'hypervisor/uuid' in path:
            return False
        if 'board_asset_tag' in path:
            return True
        return False

    def mock_isfile_xen_invalid(path):
        if 'hypervisor/uuid' in path:
            return True
        if 'board_asset_tag' in path:
            return False
        return False

    def mock_open_nitro_invalid(path, mode='r'):
        class MockFile:
            def read(self):
                if 'board_asset_tag' in path:
                    return 'i-WRONGWRONGWRONG'  # Mismatched ID
                return ''

            def strip(self):
                return self.read().strip()

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        return MockFile()

    def mock_open_xen_invalid(path, mode='r'):
        class MockFile:
            def read(self):
                if 'hypervisor/uuid' in path:
                    return 'not-ec2-uuid-12345'  # Doesn't start with ec2
                return ''

            def strip(self):
                return self.read().strip()

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        return MockFile()

    if instance_type == "Nitro":
        mock_isfile_func = mock_isfile_nitro_invalid
        mock_open_func = mock_open_nitro_invalid
    else:
        mock_isfile_func = mock_isfile_xen_invalid
        mock_open_func = mock_open_xen_invalid

    with mock.patch('urllib.request.urlopen', side_effect=mock_urlopen):
        with mock.patch('os.path.isfile', side_effect=mock_isfile_func):
            with mock.patch('builtins.open', side_effect=mock_open_func):
                with mock.patch('pwd.getpwnam', side_effect=mock_getpwnam):
                    with mock.patch('sys.argv', ['eic_curl.py', 'testuser']):
                        import importlib
                        if 'eic_curl' in sys.modules:
                            importlib.reload(sys.modules['eic_curl'])
                            eic_curl = sys.modules['eic_curl']
                        else:
                            import eic_curl

                        try:
                            eic_curl.main()
                            print(f"\n✗ {instance_type} invalid test should have failed but didn't!")
                            return False
                        except SystemExit as e:
                            if e.code == 0:
                                print(f"\n✓ {instance_type} invalid test correctly rejected (exit 0)")
                                return True
                            else:
                                print(f"\n✗ {instance_type} invalid test failed with unexpected code: {e.code}")
                                return False


def run_test_user_not_exists():
    """Run test when user doesn't exist"""
    print(f"\n{'='*60}")
    print(f"Testing non-existent user (should exit 0)")
    print('='*60)

    def mock_getpwnam_fail(username):
        raise KeyError(f"User {username} not found")

    with mock.patch('pwd.getpwnam', side_effect=mock_getpwnam_fail):
        with mock.patch('sys.argv', ['eic_curl.py', 'nonexistentuser']):
            import importlib
            if 'eic_curl' in sys.modules:
                importlib.reload(sys.modules['eic_curl'])
                eic_curl = sys.modules['eic_curl']
            else:
                import eic_curl

            try:
                eic_curl.main()
                print(f"\n✗ User-not-exists test should have exited!")
                return False
            except SystemExit as e:
                if e.code == 0:
                    print(f"\n✓ User-not-exists test correctly exited (exit 0)")
                    return True
                else:
                    print(f"\n✗ User-not-exists test failed with unexpected code: {e.code}")
                    return False


def run_test_no_active_keys():
    """Run test when no active keys exist (HTTP 404)"""
    print(f"\n{'='*60}")
    print(f"Testing no active keys (HTTP 404 - should exit 0)")
    print('='*60)

    def mock_urlopen_no_keys(request, timeout=None):
        """Mock urlopen that returns 404 for active-keys"""
        from urllib.error import HTTPError

        url = request.get_full_url() if hasattr(request, 'get_full_url') else str(request)

        # Mock token endpoint
        if 'api/token' in url:
            class MockResponse:
                def read(self):
                    return b'mock-token-12345'
                def __enter__(self):
                    return self
                def __exit__(self, *args):
                    pass
            return MockResponse()

        # Mock instance-id endpoint
        if 'instance-id' in url:
            class MockResponse:
                def read(self):
                    return b'i-1234567890abcdef0'
                def __enter__(self):
                    return self
                def __exit__(self, *args):
                    pass
            return MockResponse()

        # Mock active-keys endpoint - return 404
        if 'active-keys' in url:
            raise HTTPError(url, 404, 'Not Found', {}, None)

        class MockResponse:
            def read(self):
                return b'mock-data'
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
        return MockResponse()

    def mock_isfile_nitro(path):
        if 'hypervisor/uuid' in path:
            return False
        if 'board_asset_tag' in path:
            return True
        return False

    def mock_open_nitro(path, mode='r'):
        class MockFile:
            def read(self):
                if 'board_asset_tag' in path:
                    return 'i-1234567890abcdef0'
                return ''
            def strip(self):
                return self.read().strip()
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
        return MockFile()

    with mock.patch('urllib.request.urlopen', side_effect=mock_urlopen_no_keys):
        with mock.patch('os.path.isfile', side_effect=mock_isfile_nitro):
            with mock.patch('builtins.open', side_effect=mock_open_nitro):
                with mock.patch('pwd.getpwnam', side_effect=mock_getpwnam):
                    with mock.patch('sys.argv', ['eic_curl.py', 'testuser']):
                        import importlib
                        if 'eic_curl' in sys.modules:
                            importlib.reload(sys.modules['eic_curl'])
                            eic_curl = sys.modules['eic_curl']
                        else:
                            import eic_curl

                        try:
                            eic_curl.main()
                            print(f"\n✗ No-keys test should have exited!")
                            return False
                        except SystemExit as e:
                            if e.code == 0:
                                print(f"\n✓ No-keys test correctly exited (exit 0)")
                                return True
                            else:
                                print(f"\n✗ No-keys test failed with unexpected code: {e.code}")
                                return False


def run_test_no_files():
    """Run test when no EC2 verification files exist (not an EC2 instance)"""
    print(f"\n{'='*60}")
    print(f"Testing non-EC2 instance (no files - should fail)")
    print('='*60)

    def mock_isfile_none(path):
        return False  # No files exist

    def mock_open_none(path, mode='r'):
        raise IOError("File not found")

    with mock.patch('urllib.request.urlopen', side_effect=mock_urlopen):
        with mock.patch('os.path.isfile', side_effect=mock_isfile_none):
            with mock.patch('builtins.open', side_effect=mock_open_none):
                with mock.patch('pwd.getpwnam', side_effect=mock_getpwnam):
                    with mock.patch('sys.argv', ['eic_curl.py', 'testuser']):
                        import importlib
                        if 'eic_curl' in sys.modules:
                            importlib.reload(sys.modules['eic_curl'])
                            eic_curl = sys.modules['eic_curl']
                        else:
                            import eic_curl

                        try:
                            eic_curl.main()
                            print(f"\n✗ No-files test should have failed but didn't!")
                            return False
                        except SystemExit as e:
                            if e.code == 0:
                                print(f"\n✓ No-files test correctly rejected (exit 0)")
                                return True
                            else:
                                print(f"\n✗ No-files test failed with unexpected code: {e.code}")
                                return False


def run_test(instance_type):
    """Run test for a specific instance type"""
    print(f"\n{'='*60}")
    print(f"Testing {instance_type} instance type")
    print('='*60)

    # Mock file system checks
    def mock_isfile_nitro(path):
        """Mock os.path.isfile for Nitro instance"""
        if 'hypervisor/uuid' in path:
            return False  # Nitro: no Xen file
        if 'board_asset_tag' in path:
            return True  # Nitro: board_asset_tag exists
        return False

    def mock_isfile_xen(path):
        """Mock os.path.isfile for Xen instance"""
        if 'hypervisor/uuid' in path:
            return True  # Xen: hypervisor/uuid exists
        if 'board_asset_tag' in path:
            return False  # Xen: no board_asset_tag
        return False

    def mock_open_nitro(path, mode='r'):
        """Mock open() for Nitro instance"""
        class MockFile:
            def read(self):
                if 'board_asset_tag' in path:
                    return 'i-1234567890abcdef0'
                return ''

            def strip(self):
                return self.read().strip()

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        return MockFile()

    def mock_open_xen(path, mode='r'):
        """Mock open() for Xen instance"""
        class MockFile:
            def read(self):
                if 'hypervisor/uuid' in path:
                    return 'ec2abcdef-1234-5678-90ab-cdef12345678'
                return ''

            def strip(self):
                return self.read().strip()

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        return MockFile()

    # Select mocks based on instance type
    if instance_type == "Nitro":
        mock_isfile_func = mock_isfile_nitro
        mock_open_func = mock_open_nitro
    else:  # Xen
        mock_isfile_func = mock_isfile_xen
        mock_open_func = mock_open_xen

    # Apply all patches
    with mock.patch('urllib.request.urlopen', side_effect=mock_urlopen):
        with mock.patch('os.path.isfile', side_effect=mock_isfile_func):
            with mock.patch('builtins.open', side_effect=mock_open_func):
                with mock.patch('pwd.getpwnam', side_effect=mock_getpwnam):
                    with mock.patch('sys.argv', ['eic_curl.py', 'testuser']):
                        # Import fresh copy of module
                        import importlib
                        if 'eic_curl' in sys.modules:
                            importlib.reload(sys.modules['eic_curl'])
                            eic_curl = sys.modules['eic_curl']
                        else:
                            import eic_curl

                        try:
                            eic_curl.main()
                            print(f"\n✓ {instance_type} test completed successfully!")
                            return True
                        except SystemExit as e:
                            if e.code == 0:
                                print(f"\n✓ {instance_type} test completed (exit code {e.code})")
                                return True
                            else:
                                print(f"\n✗ {instance_type} test failed with exit code: {e.code}")
                                return False


# Run tests for both instance types
if len(sys.argv) > 1:
    # Allow running specific test
    test_type = sys.argv[1]
    valid_tests = ["nitro", "xen", "nitro-invalid", "xen-invalid", "no-files", "user-not-exists", "no-active-keys"]

    if test_type.lower() not in valid_tests:
        print(f"Invalid test type: {test_type}")
        print(f"Valid options: {', '.join(valid_tests)}")
        sys.exit(1)

    print(f"Running single test: {test_type}")

    if test_type.lower() == "nitro":
        result = run_test("Nitro")
    elif test_type.lower() == "xen":
        result = run_test("Xen")
    elif test_type.lower() == "nitro-invalid":
        result = run_test_invalid("Nitro")
    elif test_type.lower() == "xen-invalid":
        result = run_test_invalid("Xen")
    elif test_type.lower() == "no-files":
        result = run_test_no_files()
    elif test_type.lower() == "user-not-exists":
        result = run_test_user_not_exists()
    elif test_type.lower() == "no-active-keys":
        result = run_test_no_active_keys()

    sys.exit(0 if result else 1)
else:
    # Run all tests
    print("Running tests with mocked IMDS and EC2 instance files...")

    nitro_result = run_test("Nitro")
    xen_result = run_test("Xen")
    nitro_invalid_result = run_test_invalid("Nitro")
    xen_invalid_result = run_test_invalid("Xen")
    no_files_result = run_test_no_files()
    user_not_exists_result = run_test_user_not_exists()
    no_active_keys_result = run_test_no_active_keys()

    # Summary
    print(f"\n{'='*60}")
    print("Test Summary")
    print('='*60)
    print(f"Nitro valid:       {'✓ PASSED' if nitro_result else '✗ FAILED'}")
    print(f"Xen valid:         {'✓ PASSED' if xen_result else '✗ FAILED'}")
    print(f"Nitro invalid:     {'✓ PASSED' if nitro_invalid_result else '✗ FAILED'}")
    print(f"Xen invalid:       {'✓ PASSED' if xen_invalid_result else '✗ FAILED'}")
    print(f"No files:          {'✓ PASSED' if no_files_result else '✗ FAILED'}")
    print(f"User not exists:   {'✓ PASSED' if user_not_exists_result else '✗ FAILED'}")
    print(f"No active keys:    {'✓ PASSED' if no_active_keys_result else '✗ FAILED'}")
    print('='*60)

    all_passed = all([nitro_result, xen_result, nitro_invalid_result, xen_invalid_result, no_files_result, user_not_exists_result, no_active_keys_result])

    if all_passed:
        print("\n✓ All tests passed!")
        sys.exit(0)
    else:
        print("\n✗ Some tests failed!")
        sys.exit(1)
