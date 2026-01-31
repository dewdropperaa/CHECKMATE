import requests
import sys

try:
    r = requests.get('http://localhost:5000/', timeout=5)
    
    headers_to_check = [
        'Content-Security-Policy',
        'X-Frame-Options',
        'X-Content-Type-Options',
        'Strict-Transport-Security',
        'X-XSS-Protection',
        'Referrer-Policy',
        'Permissions-Policy'
    ]
    
    print("\nSecurity Headers Check:")
    print("-" * 50)
    
    all_present = True
    for header in headers_to_check:
        is_present = header in r.headers
        status = "✓" if is_present else "✗"
        print(f"{status} {header}: {'PRESENT' if is_present else 'MISSING'}")
        if not is_present:
            all_present = False
    
    print("-" * 50)
    sys.exit(0 if all_present else 1)
    
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
