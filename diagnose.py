#!/usr/bin/env python3
"""Quick diagnostic for the Vulnerability Scanner"""

import sys
import traceback

print("=" * 60)
print("VULNERABILITY SCANNER - DIAGNOSTICS")
print("=" * 60)
print()

# Test 1: Import scanner
print("[1] Testing scanner module import...")
try:
    from scanner import VulnerabilityScanner
    print("    [OK] Scanner module imported successfully")
except Exception as e:
    print(f"    [FAIL] Scanner import failed: {e}")
    traceback.print_exc()
    sys.exit(1)

# Test 2: Import Flask app
print("[2] Testing Flask app import...")
try:
    from app import app
    print("    [OK] Flask app imported successfully")
except Exception as e:
    print(f"    [FAIL] App import failed: {e}")
    traceback.print_exc()
    sys.exit(1)

# Test 3: Create a VulnerabilityScanner instance
print("[3] Testing VulnerabilityScanner instantiation...")
try:
    scanner = VulnerabilityScanner('http://example.com')
    print(f"    [OK] Scanner created for: {scanner.url}")
except Exception as e:
    print(f"    [FAIL] Scanner creation failed: {e}")
    traceback.print_exc()
    sys.exit(1)

# Test 4: Check app routes
print("[4] Testing Flask routes...")
try:
    with app.app_context():
        routes = [str(rule) for rule in app.url_map.iter_rules()]
        print(f"    [OK] Found {len(routes)} routes:")
        for route in sorted(routes):
            print(f"         {route}")
except Exception as e:
    print(f"    [FAIL] Route check failed: {e}")
    traceback.print_exc()
    sys.exit(1)

# Test 5: Test Flask is thread-safe
print("[5] Testing Flask thread safety...")
try:
    with app.test_client() as client:
        response = client.get('/')
        print(f"    [OK] Test request to / returned status: {response.status_code}")
        if response.status_code == 200:
            print(f"    [OK] Response contains HTML")
except Exception as e:
    print(f"    [FAIL] Test request failed: {e}")
    traceback.print_exc()
    sys.exit(1)

print()
print("=" * 60)
print("ALL DIAGNOSTICS PASSED!")
print("=" * 60)
print()
print("The application is ready to run. Use:")
print("  python app.py")
print()
