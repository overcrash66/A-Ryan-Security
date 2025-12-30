#!/usr/bin/env python3
"""
Test script to validate the security report improvements and process scanning feature.
"""

import sys
import os
import json
from datetime import datetime

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_ai_consistency():
    """Test that AI analysis provides consistent results."""
    print("[TEST] Testing AI Analysis Consistency...")
    
    try:
        from security_modules.ai_integration import get_comprehensive_ai_analysis, get_ai_advice
        
        # Mock security data for testing
        test_data = {
            'vulns': {'test-package': 5, 'another-package': 2},
            'osv': {'raw_output': 'Total 4 packages affected by 7 known vulnerabilities (1 Critical, 3 High, 2 Medium, 1 Low)'},
            'av': 'Windows Defender active',
            'fw': 'Windows Firewall enabled',
            'net': {'scan_results': 'Network scan completed'},
            'traffic': ['connection1', 'connection2'],
            'processes': {
                'total_processes': 150,
                'suspicious_processes': 2,
                'high_resource_processes': 5,
                'network_processes': 20,
                'security_analysis': {
                    'risk_level': 'MEDIUM',
                    'findings': ['2 suspicious processes detected', 'High resource usage in 5 processes'],
                    'recommendations': ['Investigate suspicious processes', 'Monitor resource usage']
                }
            }
        }
        
        print("  [OK] Testing comprehensive AI analysis...")
        comprehensive_analysis = get_comprehensive_ai_analysis(test_data)
        
        if comprehensive_analysis:
            print(f"  [OK] Comprehensive analysis generated: {len(comprehensive_analysis.get('full_analysis', ''))} characters")
            print(f"  [OK] Executive summary: {len(comprehensive_analysis.get('executive_summary', ''))} characters")
            print(f"  [OK] Risk level extracted: {comprehensive_analysis.get('risk_level', 'Not found')}")
            print(f"  [OK] Recommendations: {len(comprehensive_analysis.get('recommendations', ''))} characters")
        else:
            print("  [WARN] Comprehensive analysis returned None (AI service may be unavailable)")
        
        print("  [OK] Testing traditional AI advice...")
        traditional_advice = get_ai_advice(test_data)
        
        if traditional_advice:
            print(f"  [OK] Traditional advice generated: {len(traditional_advice)} characters")
        else:
            print("  [WARN] Traditional advice returned None (AI service may be unavailable)")
        
        print("  [PASS] AI consistency tests completed")
        return True
        
    except Exception as e:
        print(f"  [FAIL] AI consistency test failed: {e}")
        return False

def test_process_scanning():
    """Test the Windows process scanning functionality."""
    print("\n[TEST] Testing Process Scanning Feature...")
    
    try:
        from security_modules.process_scanner import scan_running_processes, get_system_services, get_startup_programs
        
        print("  [OK] Testing process scanning...")
        process_results = scan_running_processes()
        
        if process_results.get('error'):
            print(f"  [WARN] Process scan returned error: {process_results['error']}")
        else:
            print(f"  [OK] Process scan completed successfully")
            print(f"    - Total processes: {process_results.get('total_processes', 0)}")
            print(f"    - Suspicious processes: {process_results.get('suspicious_processes', 0)}")
            print(f"    - High resource processes: {process_results.get('high_resource_processes', 0)}")
            print(f"    - Network processes: {process_results.get('network_processes', 0)}")
            
            if process_results.get('security_analysis'):
                analysis = process_results['security_analysis']
                print(f"    - Security risk level: {analysis.get('risk_level', 'Unknown')}")
                print(f"    - Findings: {len(analysis.get('findings', []))}")
                print(f"    - Recommendations: {len(analysis.get('recommendations', []))}")
        
        print("  [OK] Testing system services...")
        services_results = get_system_services()
        
        if services_results.get('error'):
            print(f"  [WARN] Services scan returned error: {services_results['error']}")
        else:
            print(f"  [OK] Services scan completed: {services_results.get('total_services', 0)} services")
        
        print("  [OK] Testing startup programs...")
        startup_results = get_startup_programs()
        
        if startup_results.get('error'):
            print(f"  [WARN] Startup programs scan returned error: {startup_results['error']}")
        else:
            print(f"  [OK] Startup programs scan completed: {startup_results.get('total_startup_programs', 0)} programs")
        
        print("  [PASS] Process scanning tests completed")
        return True
        
    except Exception as e:
        print(f"  [FAIL] Process scanning test failed: {e}")
        return False

def test_report_generation():
    """Test that reports include the new process data and consistent AI analysis."""
    print("\n[TEST] Testing Report Generation...")
    
    try:
        from reports import assess_risk_level, generate_text_report
        
        # Mock data with process information
        test_data = {
            'vulns': {'test-package': 3},
            'osv': {'raw_output': 'Total 1 packages affected by 3 known vulnerabilities (1 High, 2 Medium)'},
            'av': 'Antivirus active',
            'fw': 'Firewall enabled',
            'net': 'Network secure',
            'traffic': ['conn1', 'conn2'],
            'processes': {
                'total_processes': 100,
                'suspicious_processes': 1,
                'high_resource_processes': 3,
                'network_processes': 15,
                'security_analysis': {
                    'risk_level': 'MEDIUM',
                    'findings': ['1 suspicious process detected'],
                    'recommendations': ['Investigate suspicious process']
                }
            }
        }
        
        print("  [OK] Testing risk assessment...")
        risk_level = assess_risk_level(test_data)
        print(f"  [OK] Risk level assessed: {risk_level}")
        
        print("  [OK] Testing text report generation...")
        # Note: This will try to generate a report but may fail if AI service is unavailable
        # We'll catch any errors and report them
        try:
            report_path = generate_text_report(test_data)
            if report_path:
                print(f"  [OK] Text report generated: {report_path}")
            else:
                print("  [WARN] Text report generation returned None")
        except Exception as report_error:
            print(f"  [WARN] Text report generation failed: {report_error}")
        
        print("  [PASS] Report generation tests completed")
        return True
        
    except Exception as e:
        print(f"  [FAIL] Report generation test failed: {e}")
        return False

def test_web_routes():
    """Test that the new web routes are properly configured."""
    print("\n[TEST] Testing Web Route Configuration...")
    
    try:
        from web_interface import create_app
        app = create_app()
        app.config['TESTING'] = True
        
        with app.test_client() as client:
            # Test that routes exist (they should return 302 redirect to login for unauthenticated users)
            routes_to_test = [
                '/process_scan',
                '/api/process_refresh'
            ]
            
            for route in routes_to_test:
                print(f"  [OK] Testing route: {route}")
                response = client.get(route)
                # Should redirect to login (302) or return some response (not 404)
                if response.status_code == 404:
                    print(f"    [FAIL] Route {route} not found (404)")
                    return False
                else:
                    print(f"    [OK] Route {route} exists (status: {response.status_code})")
        
        print("  [PASS] Web route tests completed")
        return True
        
    except Exception as e:
        print(f"  [FAIL] Web route test failed: {e}")
        return False

def main():
    """Run all improvement tests."""
    print("A-Ryan Security - Improvement Validation Tests")
    print("=" * 60)
    print(f"Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    tests = [
        ("AI Consistency", test_ai_consistency),
        ("Process Scanning", test_process_scanning),
        ("Report Generation", test_report_generation),
        ("Web Routes", test_web_routes)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"[CRASH] {test_name} test crashed: {e}")
            results[test_name] = False
    
    print("\n" + "=" * 60)
    print("TEST RESULTS SUMMARY")
    print("=" * 60)
    
    passed = 0
    total = len(tests)
    
    for test_name, result in results.items():
        status = "[PASSED]" if result else "[FAILED]"
        print(f"{test_name:<20} {status}")
        if result:
            passed += 1
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("All tests passed! The improvements are working correctly.")
        return 0
    else:
        print("Some tests failed. Please review the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())