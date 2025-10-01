"""
Performance Testing Script for A-Ryan Security Application
Tests page load times, API response times, and overall performance metrics
"""

import time
import requests
import statistics
from datetime import datetime
import json
import sys
import os

class PerformanceTester:
    def __init__(self, base_url='http://localhost:5000'):
        self.base_url = base_url
        self.session = requests.Session()
        self.results = {}
        
    def login(self, username='admin', password='SecurePass123!'):
        """Login to get session for authenticated requests"""
        try:
            # Get login page first
            login_page = self.session.get(f'{self.base_url}/login')
            
            # Extract CSRF token (simplified)
            csrf_token = 'test-token'  # In real implementation, parse from HTML
            
            # Perform login
            login_data = {
                'username': username,
                'password': password,
                'csrf_token': csrf_token
            }
            
            response = self.session.post(f'{self.base_url}/login', data=login_data)
            return response.status_code == 302  # Redirect on success
            
        except Exception as e:
            print(f"Login failed: {e}")
            return False
    
    def measure_page_load(self, endpoint, iterations=5):
        """Measure page load time for a specific endpoint"""
        times = []
        
        for i in range(iterations):
            start_time = time.time()
            try:
                response = self.session.get(f'{self.base_url}{endpoint}')
                end_time = time.time()
                
                if response.status_code == 200:
                    load_time = (end_time - start_time) * 1000  # Convert to ms
                    times.append(load_time)
                    print(f"  Iteration {i+1}: {load_time:.2f}ms")
                else:
                    print(f"  Iteration {i+1}: Failed (Status: {response.status_code})")
                    
            except Exception as e:
                print(f"  Iteration {i+1}: Error - {e}")
            
            # Small delay between requests
            time.sleep(0.5)
        
        if times:
            return {
                'avg': statistics.mean(times),
                'min': min(times),
                'max': max(times),
                'median': statistics.median(times),
                'count': len(times)
            }
        return None
    
    def measure_api_performance(self, endpoint, iterations=3):
        """Measure API response time"""
        times = []
        
        for i in range(iterations):
            start_time = time.time()
            try:
                response = self.session.get(f'{self.base_url}{endpoint}')
                end_time = time.time()
                
                if response.status_code == 200:
                    response_time = (end_time - start_time) * 1000
                    times.append(response_time)
                    print(f"  API {endpoint} - Iteration {i+1}: {response_time:.2f}ms")
                else:
                    print(f"  API {endpoint} - Iteration {i+1}: Failed (Status: {response.status_code})")
                    
            except Exception as e:
                print(f"  API {endpoint} - Iteration {i+1}: Error - {e}")
            
            time.sleep(0.2)
        
        if times:
            return {
                'avg': statistics.mean(times),
                'min': min(times),
                'max': max(times),
                'median': statistics.median(times),
                'count': len(times)
            }
        return None
    
    def run_comprehensive_test(self):
        """Run comprehensive performance tests"""
        print("🚀 Starting A-Ryan Security Performance Tests")
        print("=" * 50)
        
        # Test login
        print("\n1. Testing Authentication...")
        if not self.login():
            print("❌ Login failed - cannot continue tests")
            return
        print("✅ Login successful")
        
        # Test page load times
        print("\n2. Testing Page Load Performance...")
        pages = [
            ('/', 'Dashboard'),
            ('/status', 'Status Page'),
            ('/history', 'History Page'),
            ('/process_scan', 'Process Scan'),
            ('/report', 'Reports'),
            ('/whois', 'Whois Lookup')
        ]
        
        page_results = {}
        for endpoint, name in pages:
            print(f"\n  Testing {name} ({endpoint}):")
            result = self.measure_page_load(endpoint)
            if result:
                page_results[name] = result
                print(f"    Average: {result['avg']:.2f}ms")
                print(f"    Range: {result['min']:.2f}ms - {result['max']:.2f}ms")
                
                # Performance assessment
                if result['avg'] < 1000:
                    print("    ✅ Excellent performance")
                elif result['avg'] < 2000:
                    print("    ⚠️ Good performance")
                elif result['avg'] < 3000:
                    print("    ⚠️ Acceptable performance")
                else:
                    print("    ❌ Poor performance - needs optimization")
        
        # Test API performance
        print("\n3. Testing API Performance...")
        api_endpoints = [
            '/api/status/batch',
            '/api/history/batch',
            '/api/status/av',
            '/api/status/fw',
            '/api/whois/8.8.8.8'
        ]
        
        api_results = {}
        for endpoint in api_endpoints:
            print(f"\n  Testing API {endpoint}:")
            result = self.measure_api_performance(endpoint)
            if result:
                api_results[endpoint] = result
                print(f"    Average: {result['avg']:.2f}ms")
                
                # API performance assessment
                if result['avg'] < 500:
                    print("    ✅ Excellent API performance")
                elif result['avg'] < 1000:
                    print("    ⚠️ Good API performance")
                elif result['avg'] < 2000:
                    print("    ⚠️ Acceptable API performance")
                else:
                    print("    ❌ Poor API performance - needs optimization")
        
        # Generate performance report
        self.generate_report(page_results, api_results)
    
    def generate_report(self, page_results, api_results):
        """Generate performance test report"""
        print("\n" + "=" * 50)
        print("📊 PERFORMANCE TEST REPORT")
        print("=" * 50)
        
        # Overall assessment
        all_page_times = [result['avg'] for result in page_results.values()]
        all_api_times = [result['avg'] for result in api_results.values()]
        
        if all_page_times:
            avg_page_time = statistics.mean(all_page_times)
            print(f"\n📈 Overall Page Performance:")
            print(f"   Average Load Time: {avg_page_time:.2f}ms")
            
            if avg_page_time < 1500:
                print("   ✅ Overall performance: EXCELLENT")
            elif avg_page_time < 2500:
                print("   ⚠️ Overall performance: GOOD")
            elif avg_page_time < 4000:
                print("   ⚠️ Overall performance: ACCEPTABLE")
            else:
                print("   ❌ Overall performance: NEEDS IMPROVEMENT")
        
        if all_api_times:
            avg_api_time = statistics.mean(all_api_times)
            print(f"\n🔌 Overall API Performance:")
            print(f"   Average Response Time: {avg_api_time:.2f}ms")
            
            if avg_api_time < 800:
                print("   ✅ API performance: EXCELLENT")
            elif avg_api_time < 1500:
                print("   ⚠️ API performance: GOOD")
            else:
                print("   ❌ API performance: NEEDS IMPROVEMENT")
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        
        slow_pages = [name for name, result in page_results.items() if result['avg'] > 3000]
        if slow_pages:
            print(f"   🔧 Optimize slow pages: {', '.join(slow_pages)}")
        
        slow_apis = [endpoint for endpoint, result in api_results.items() if result['avg'] > 2000]
        if slow_apis:
            print(f"   🔧 Optimize slow APIs: {', '.join(slow_apis)}")
        
        if not slow_pages and not slow_apis:
            print("   ✅ All pages and APIs performing well!")
        
        # Save results to file
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'page_results': page_results,
            'api_results': api_results,
            'summary': {
                'avg_page_time': statistics.mean(all_page_times) if all_page_times else 0,
                'avg_api_time': statistics.mean(all_api_times) if all_api_times else 0
            }
        }
        
        with open('performance_report.json', 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: performance_report.json")

def main():
    """Main function to run performance tests"""
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    else:
        base_url = 'http://localhost:5000'
    
    print(f"🎯 Testing A-Ryan Security Application at: {base_url}")
    
    tester = PerformanceTester(base_url)
    tester.run_comprehensive_test()

if __name__ == '__main__':
    main()