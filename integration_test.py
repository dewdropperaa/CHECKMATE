#!/usr/bin/env python3
"""
Comprehensive integration test for Vulnerability Scanner
Tests Flask app, security headers, and scan functionality
"""

import requests
import json
import time
import sys

BASE_URL = "http://localhost:5000"

def test_headers():
    """Test security headers"""
    print("\n" + "="*60)
    print("SECURITY HEADERS TEST")
    print("="*60)
    
    try:
        r = requests.get(f"{BASE_URL}/", timeout=5)
        
        required_headers = {
            'Content-Security-Policy': 'CSP',
            'X-Frame-Options': 'X-Frame-Options',
            'X-Content-Type-Options': 'X-Content-Type-Options',
            'Strict-Transport-Security': 'HSTS',
            'X-XSS-Protection': 'X-XSS-Protection',
            'Referrer-Policy': 'Referrer-Policy',
            'Permissions-Policy': 'Permissions-Policy'
        }
        
        all_present = True
        for header, label in required_headers.items():
            is_present = header in r.headers
            status = "✓" if is_present else "✗"
            print(f"{status} {label}: {'PRESENT' if is_present else 'MISSING'}")
            if not is_present:
                all_present = False
        
        print("="*60)
        return all_present
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def test_endpoints():
    """Test API endpoints"""
    print("\n" + "="*60)
    print("API ENDPOINTS TEST")
    print("="*60)
    
    tests = [
        ('GET', '/health', None, 'Health Check'),
        ('GET', '/api', None, 'API Info'),
        ('GET', '/demo', None, 'Demo Results'),
        ('GET', '/', None, 'Frontend'),
        ('POST', '/scan', {'url': 'httpbin.org'}, 'Scan Endpoint'),
    ]
    
    all_pass = True
    for method, path, data, label in tests:
        try:
            if method == 'GET':
                r = requests.get(f"{BASE_URL}{path}", timeout=10)
            else:
                r = requests.post(f"{BASE_URL}{path}", json=data, timeout=30)
            
            is_success = r.status_code < 400
            status = "✓" if is_success else "✗"
            print(f"{status} {label} ({method} {path}): {r.status_code}")
            
            if not is_success:
                all_pass = False
                try:
                    print(f"  Response: {r.json()}")
                except:
                    print(f"  Response: {r.text[:100]}")
        except Exception as e:
            print(f"✗ {label} ({method} {path}): ERROR - {str(e)[:50]}")
            all_pass = False
    
    print("="*60)
    return all_pass

def test_scan_functionality():
    """Test the actual scan functionality"""
    print("\n" + "="*60)
    print("SCAN FUNCTIONALITY TEST")
    print("="*60)
    
    try:
        print("Scanning httpbin.org...")
        r = requests.post(
            f"{BASE_URL}/scan",
            json={'url': 'httpbin.org'},
            timeout=60
        )
        
        if r.status_code != 200:
            print(f"✗ Scan failed with status {r.status_code}")
            return False
        
        data = r.json()
        
        required_fields = ['success', 'url', 'vulnerabilities', 'summary', 'scan_time']
        missing_fields = [f for f in required_fields if f not in data]
        
        if missing_fields:
            print(f"✗ Missing fields: {missing_fields}")
            return False
        
        print(f"✓ Scan completed successfully")
        print(f"  URL: {data['url']}")
        print(f"  Vulnerabilities found: {data['summary']['total']}")
        print(f"  Severity breakdown:")
        print(f"    - Critical: {data['summary'].get('critical', 0)}")
        print(f"    - Warning: {data['summary'].get('warning', 0)}")
        print(f"    - Info: {data['summary'].get('info', 0)}")
        print(f"  Scan time: {data['scan_time']:.2f}s")
        
        # Show first 3 vulnerabilities
        if data['vulnerabilities']:
            print(f"\n  Sample vulnerabilities:")
            for vuln in data['vulnerabilities'][:3]:
                print(f"    - {vuln['type']} ({vuln['severity']})")
        
        print("="*60)
        return True
    except Exception as e:
        print(f"✗ Scan test failed: {e}")
        print("="*60)
        return False

def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("VULNERABILITY SCANNER - INTEGRATION TEST SUITE")
    print("="*70)
    
    # Check if server is running
    print("\nChecking if server is running on http://localhost:5000...")
    max_retries = 5
    for i in range(max_retries):
        try:
            requests.get(f"{BASE_URL}/health", timeout=2)
            print("✓ Server is running")
            break
        except:
            if i < max_retries - 1:
                print(f"  Waiting... ({i+1}/{max_retries})")
                time.sleep(2)
            else:
                print("✗ Server is not responding")
                return False
    
    # Run tests
    headers_ok = test_headers()
    endpoints_ok = test_endpoints()
    scan_ok = test_scan_functionality()
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    all_pass = headers_ok and endpoints_ok and scan_ok
    
    results = {
        'Security Headers': headers_ok,
        'API Endpoints': endpoints_ok,
        'Scan Functionality': scan_ok,
        'Overall': all_pass
    }
    
    for test_name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print("="*70 + "\n")
    
    return 0 if all_pass else 1

if __name__ == '__main__':
    sys.exit(main())
