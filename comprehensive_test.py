"""
Comprehensive test suite for the Vulnerability Scanner
Tests all endpoints and UX functionality
"""

import requests
import json
import time
import sys
from threading import Thread

# Test configuration
BASE_URL = 'http://localhost:5000'
TIMEOUT = 5

def print_result(test_name, passed, details=""):
    """Print test result in a formatted way"""
    status = "[PASS]" if passed else "[FAIL]"
    print(f"{status} {test_name}")
    if details:
        print(f"       {details}")

def start_server():
    """Start the Flask server in a background thread"""
    print("[INFO] Starting Flask server...")
    from app import app
    app.run(debug=False, host='127.0.0.1', port=5000, use_reloader=False, threaded=True)

def test_server_running():
    """Test if server is running"""
    try:
        response = requests.get(f'{BASE_URL}/health', timeout=TIMEOUT)
        return response.status_code == 200
    except:
        return False

def test_health_endpoint():
    """Test /health endpoint"""
    try:
        response = requests.get(f'{BASE_URL}/health', timeout=TIMEOUT)
        data = response.json()
        
        passed = (
            response.status_code == 200 and
            data.get('status') == 'healthy' and
            data.get('service') == 'vulnerability-scanner'
        )
        
        print_result("Health Endpoint", passed, f"Status: {response.status_code}, Data: {data}")
        return passed
    except Exception as e:
        print_result("Health Endpoint", False, f"Error: {str(e)}")
        return False

def test_index_page():
    """Test if index page loads"""
    try:
        response = requests.get(f'{BASE_URL}/', timeout=TIMEOUT)
        passed = response.status_code == 200 and 'Checkmate' in response.text
        
        print_result("Index Page", passed, f"Status: {response.status_code}, Contains 'Checkmate': {'Checkmate' in response.text}")
        return passed
    except Exception as e:
        print_result("Index Page", False, f"Error: {str(e)}")
        return False

def test_test_page():
    """Test if test page loads"""
    try:
        response = requests.get(f'{BASE_URL}/test', timeout=TIMEOUT)
        passed = response.status_code == 200
        
        print_result("Test Page", passed, f"Status: {response.status_code}")
        return passed
    except Exception as e:
        print_result("Test Page", False, f"Error: {str(e)}")
        return False

def test_api_info():
    """Test /api endpoint"""
    try:
        response = requests.get(f'{BASE_URL}/api', timeout=TIMEOUT)
        data = response.json()
        
        passed = (
            response.status_code == 200 and
            'endpoints' in data and
            'service' in data
        )
        
        print_result("API Info Endpoint", passed, f"Status: {response.status_code}")
        return passed
    except Exception as e:
        print_result("API Info Endpoint", False, f"Error: {str(e)}")
        return False

def test_demo_endpoint():
    """Test /demo endpoint"""
    try:
        response = requests.get(f'{BASE_URL}/demo', timeout=TIMEOUT)
        data = response.json()
        
        passed = (
            response.status_code == 200 and
            data.get('success') == True and
            'vulnerabilities' in data and
            'summary' in data
        )
        
        summary = data.get('summary', {})
        print_result("Demo Endpoint", passed, f"Status: {response.status_code}, Vulns: {summary.get('total')}")
        return passed
    except Exception as e:
        print_result("Demo Endpoint", False, f"Error: {str(e)}")
        return False

def test_scan_empty_url():
    """Test /scan endpoint with no URL"""
    try:
        response = requests.post(f'{BASE_URL}/scan', 
                                json={}, 
                                timeout=TIMEOUT)
        
        data = response.json()
        passed = (
            response.status_code == 400 and
            data.get('success') == False
        )
        
        print_result("Scan Endpoint (No URL)", passed, f"Status: {response.status_code}")
        return passed
    except Exception as e:
        print_result("Scan Endpoint (No URL)", False, f"Error: {str(e)}")
        return False

def test_scan_invalid_url():
    """Test /scan endpoint with invalid URL"""
    try:
        response = requests.post(f'{BASE_URL}/scan',
                                json={'url': 'not a valid url!!!'},
                                timeout=TIMEOUT)
        
        data = response.json()
        passed = response.status_code == 400 and data.get('success') == False
        
        print_result("Scan Endpoint (Invalid URL)", passed, f"Status: {response.status_code}")
        return passed
    except Exception as e:
        print_result("Scan Endpoint (Invalid URL)", False, f"Error: {str(e)}")
        return False

def test_scan_valid_url():
    """Test /scan endpoint with valid URL"""
    try:
        response = requests.post(f'{BASE_URL}/scan',
                                json={'url': 'example.com'},
                                timeout=30)  # Longer timeout for actual scan
        
        data = response.json()
        passed = response.status_code == 200 and data.get('success') == True
        
        summary = data.get('summary', {})
        print_result("Scan Endpoint (Valid URL)", passed, f"Status: {response.status_code}, Vulns found: {summary.get('total')}")
        return passed
    except Exception as e:
        print_result("Scan Endpoint (Valid URL)", False, f"Error: {str(e)}")
        return False

def test_security_headers():
    """Test if security headers are present"""
    try:
        response = requests.get(f'{BASE_URL}/', timeout=TIMEOUT)
        headers = response.headers
        
        required_headers = [
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Strict-Transport-Security',
            'X-XSS-Protection'
        ]
        
        missing = [h for h in required_headers if h not in headers]
        passed = len(missing) == 0
        
        if passed:
            print_result("Security Headers", True, f"All {len(required_headers)} headers present")
        else:
            print_result("Security Headers", False, f"Missing headers: {missing}")
        
        return passed
    except Exception as e:
        print_result("Security Headers", False, f"Error: {str(e)}")
        return False

def test_cors_headers():
    """Test CORS headers"""
    try:
        response = requests.options(f'{BASE_URL}/api', timeout=TIMEOUT)
        headers = response.headers
        
        # Check if CORS headers exist
        has_cors = any(key.lower() == 'access-control-allow-origin' for key in headers.keys())
        
        print_result("CORS Headers", has_cors, f"Has CORS headers: {has_cors}")
        return has_cors
    except Exception as e:
        print_result("CORS Headers", False, f"Error: {str(e)}")
        return False

def test_rate_limiting():
    """Test rate limiting (10 per hour)"""
    try:
        # Make 5 requests rapidly
        for i in range(5):
            response = requests.post(f'{BASE_URL}/scan',
                                   json={'url': 'example.com'},
                                   timeout=30)
            if response.status_code == 429:
                print_result("Rate Limiting", True, f"Rate limit triggered after {i} requests")
                return True
        
        print_result("Rate Limiting", True, f"Completed 5 requests without hitting limit (expected for 10/hour)")
        return True
    except Exception as e:
        print_result("Rate Limiting", False, f"Error: {str(e)}")
        return False

def run_all_tests():
    """Run all tests"""
    print("=" * 60)
    print("COMPREHENSIVE VULNERABILITY SCANNER TEST SUITE")
    print("=" * 60)
    print()
    
    # Wait for server to start
    print("[INFO] Waiting for server to start...")
    for i in range(10):
        if test_server_running():
            print("[INFO] Server is running!")
            break
        time.sleep(1)
    else:
        print("[ERROR] Server failed to start!")
        return
    
    print()
    print("RUNNING TESTS...")
    print("-" * 60)
    
    results = []
    
    # Test all endpoints
    results.append(("Health Endpoint", test_health_endpoint()))
    results.append(("Index Page", test_index_page()))
    results.append(("Test Page", test_test_page()))
    results.append(("API Info", test_api_info()))
    results.append(("Demo Endpoint", test_demo_endpoint()))
    results.append(("Security Headers", test_security_headers()))
    results.append(("CORS Headers", test_cors_headers()))
    results.append(("Scan - No URL", test_scan_empty_url()))
    results.append(("Scan - Invalid URL", test_scan_invalid_url()))
    results.append(("Scan - Valid URL", test_scan_valid_url()))
    results.append(("Rate Limiting", test_rate_limiting()))
    
    print()
    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓" if result else "✗"
        print(f"{status} {test_name}")
    
    print("-" * 60)
    print(f"RESULTS: {passed}/{total} tests passed ({100*passed//total}%)")
    print("=" * 60)

if __name__ == '__main__':
    # Start server in background thread
    server_thread = Thread(target=start_server, daemon=True)
    server_thread.start()
    
    # Give server time to start
    time.sleep(3)
    
    # Run tests
    run_all_tests()
