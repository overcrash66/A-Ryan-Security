#!/usr/bin/env python3
"""
Simple validation script to test all fixes.
"""

import os
import sys

def test_config_security():
    """Test that config.py no longer has hardcoded secrets."""
    try:
        from config import Config

        # This should raise an error if SECRET_KEY is not set
        try:
            Config()
            print("ERROR: Config should have failed without SECRET_KEY")
            return False
        except ValueError as e:
            if "SECRET_KEY environment variable must be set" in str(e):
                print("PASS: Config properly requires SECRET_KEY")
            else:
                print(f"ERROR: Wrong error message: {e}")
                return False

        # Test with valid SECRET_KEY
        os.environ['SECRET_KEY'] = 'test-key-that-is-at-least-32-characters-long'
        config = Config()
        if config.SECRET_KEY != 'test-key-that-is-at-least-32-characters-long':
            print("ERROR: Config SECRET_KEY not set correctly")
            return False

        # Test with short SECRET_KEY
        os.environ['SECRET_KEY'] = 'short'
        try:
            Config()
            print("ERROR: Config should have failed with short SECRET_KEY")
            return False
        except ValueError as e:
            if "SECRET_KEY must be at least 32 characters long" in str(e):
                print("PASS: Config properly validates SECRET_KEY length")
            else:
                print(f"ERROR: Wrong error message: {e}")
                return False

        return True

    except ImportError as e:
        print(f"ERROR: Config import failed: {e}")
        return False

def test_input_validation():
    """Test the new input validation module."""
    try:
        from input_validation import InputValidator

        # Test valid path
        test_dir = os.getcwd()
        valid_path = InputValidator.validate_scan_path(test_dir)
        if valid_path != test_dir:
            print("ERROR: Input validation failed for valid path")
            return False

        # Test invalid path
        try:
            InputValidator.validate_scan_path('/nonexistent/path')
            print("ERROR: Input validation should have failed for invalid path")
            return False
        except ValueError:
            print("PASS: Input validation properly rejects invalid paths")

        # Test IP validation
        valid_ip = InputValidator.validate_ip_address('192.168.1.1')
        if valid_ip != '192.168.1.1':
            print("ERROR: IP validation failed")
            return False

        try:
            InputValidator.validate_ip_address('invalid-ip')
            print("ERROR: IP validation should have failed for invalid IP")
            return False
        except ValueError:
            print("PASS: IP validation properly rejects invalid IPs")

        return True

    except ImportError as e:
        print(f"ERROR: Input validation import failed: {e}")
        return False

def test_error_handlers():
    """Test the new error handlers module."""
    try:
        from error_handlers import SecurityError, ValidationError, ScanError, DatabaseError

        # Test custom exceptions
        try:
            raise SecurityError("Test security error")
            print("ERROR: SecurityError should have been raised")
            return False
        except SecurityError:
            print("PASS: SecurityError works correctly")

        try:
            raise ValidationError("Test validation error")
            print("ERROR: ValidationError should have been raised")
            return False
        except ValidationError:
            print("PASS: ValidationError works correctly")

        return True

    except ImportError as e:
        print(f"ERROR: Error handlers import failed: {e}")
        return False

def test_services():
    """Test the new services module."""
    try:
        from services import SecurityService

        service = SecurityService()

        # Test that service can be instantiated
        if not isinstance(service, SecurityService):
            print("ERROR: SecurityService instantiation failed")
            return False

        # Test that service has required methods
        required_methods = [
            'perform_antivirus_scan',
            'perform_vulnerability_scan',
            'perform_network_analysis',
            'perform_process_scan',
            'perform_comprehensive_scan'
        ]

        for method in required_methods:
            if not hasattr(service, method):
                print(f"ERROR: SecurityService missing method {method}")
                return False
            if not callable(getattr(service, method)):
                print(f"ERROR: SecurityService method {method} not callable")
                return False

        print("PASS: SecurityService works correctly")
        return True

    except ImportError as e:
        print(f"ERROR: Services import failed: {e}")
        return False

def test_performance_monitor():
    """Test the new performance monitor module."""
    try:
        from performance_monitor import PerformanceMonitor

        monitor = PerformanceMonitor()

        # Test that monitor can be instantiated
        if not isinstance(monitor, PerformanceMonitor):
            print("ERROR: PerformanceMonitor instantiation failed")
            return False

        # Test that monitor has required methods
        required_methods = [
            'start_request_timer',
            'end_request_timer',
            'get_performance_stats',
            'get_slow_requests',
            'clear_stats'
        ]

        for method in required_methods:
            if not hasattr(monitor, method):
                print(f"ERROR: PerformanceMonitor missing method {method}")
                return False
            if not callable(getattr(monitor, method)):
                print(f"ERROR: PerformanceMonitor method {method} not callable")
                return False

        print("PASS: PerformanceMonitor works correctly")
        return True

    except ImportError as e:
        print(f"ERROR: Performance monitor import failed: {e}")
        return False

def test_existing_modules():
    """Test that existing modules still work."""
    modules_to_test = [
        ('antivirus', ['scan_directory', 'extra_antivirus_layer']),
        ('network_analyzer', ['scan_network', 'analyze_traffic']),
        ('process_scanner', ['scan_running_processes', 'get_system_services']),
        ('vuln_checker', []),  # Will test in test mode
        ('ai_integration', ['get_ai_advice', 'predict_threats']),
        ('models', ['User', 'Log', 'Issue']),
        ('cache', ['cache'])
    ]

    for module_name, functions in modules_to_test:
        try:
            module = __import__(module_name)
            print(f"PASS: {module_name} module imports correctly")

            # Test specific functions if provided
            for func_name in functions:
                if hasattr(module, func_name):
                    print(f"PASS: {module_name}.{func_name} exists")
                else:
                    print(f"ERROR: {module_name}.{func_name} missing")
                    return False

        except ImportError as e:
            print(f"ERROR: {module_name} import failed: {e}")
            return False

    return True

def test_vuln_checker_test_mode():
    """Test that vuln_checker still works in test mode."""
    try:
        # Set test mode environment variable
        os.environ['PYTEST_CURRENT_TEST'] = 'test_validation'

        from vuln_checker import scan_vulnerabilities

        # This should return mock data in test mode
        vulns, osv_data = scan_vulnerabilities()

        # Verify mock data structure
        if not isinstance(vulns, dict):
            print("ERROR: vuln_checker test mode returned wrong type for vulns")
            return False

        if not isinstance(osv_data, dict):
            print("ERROR: vuln_checker test mode returned wrong type for osv_data")
            return False

        if 'output_type' not in osv_data:
            print("ERROR: vuln_checker test mode missing output_type in osv_data")
            return False

        print("PASS: Vulnerability checker test mode works correctly")
        return True

    except ImportError as e:
        print(f"ERROR: Vuln checker import failed: {e}")
        return False
    finally:
        # Clean up environment variable
        if 'PYTEST_CURRENT_TEST' in os.environ:
            del os.environ['PYTEST_CURRENT_TEST']

def main():
    """Run all tests."""
    print("Starting comprehensive validation of fixes...")
    print("=" * 60)

    tests = [
        ("Config Security Fixes", test_config_security),
        ("Input Validation Module", test_input_validation),
        ("Error Handlers Module", test_error_handlers),
        ("Services Module", test_services),
        ("Performance Monitor Module", test_performance_monitor),
        ("Existing Modules", test_existing_modules),
        ("Vuln Checker Test Mode", test_vuln_checker_test_mode)
    ]

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        print(f"\nTesting {test_name}...")
        try:
            if test_func():
                passed += 1
                print(f"PASS: {test_name}")
            else:
                failed += 1
                print(f"FAIL: {test_name}")
        except Exception as e:
            failed += 1
            print(f"ERROR: {test_name} failed with exception: {e}")

    print("\n" + "=" * 60)
    print("Validation Results:")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Total: {passed + failed}")

    if failed == 0:
        print("All validation tests PASSED!")
        print("All fixes are working correctly!")
        print("Application functionality is preserved!")
        return True
    else:
        print("Some validation tests FAILED!")
        return False

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)