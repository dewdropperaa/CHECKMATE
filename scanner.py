"""
Vulnerability Scanner Module
Contains the core scanning logic for security vulnerabilities
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
from typing import Dict, List, Any
import re
import argparse
import sys
from datetime import datetime
import json

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Configuration
TIMEOUT = 5  # Timeout for individual requests
MAX_SCAN_TIME = 30  # Maximum time for entire scan
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'

class VulnerabilityScanner:
    """Main scanner class that performs various security checks"""
    
    def __init__(self, url: str):
        self.url = self._normalize_url(url)
        self.vulnerabilities = []
        self.start_time = time.time()
        
    def _normalize_url(self, url: str) -> str:
        """Normalize and validate URL"""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url
    
    def _is_timeout_exceeded(self) -> bool:
        """Check if maximum scan time has been exceeded"""
        return (time.time() - self.start_time) > MAX_SCAN_TIME
    
    def _make_request(self, url: str, method: str = 'GET', **kwargs) -> requests.Response:
        """Make HTTP request with proper headers and timeout"""
        headers = kwargs.pop('headers', {})
        headers['User-Agent'] = USER_AGENT
        
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                timeout=TIMEOUT,
                allow_redirects=True,
                verify=True,
                **kwargs
            )
            return response
        except requests.exceptions.SSLError:
            # Retry without SSL verification if certificate fails
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                timeout=TIMEOUT,
                allow_redirects=True,
                verify=False,
                **kwargs
            )
            return response
    
    def _add_vulnerability(self, vuln_type: str, severity: str, 
                          description: str, recommendation: str, details: Dict = None):
        """Add a vulnerability to the results list"""
        vulnerability = {
            'type': vuln_type,
            'severity': severity,
            'description': description,
            'recommendation': recommendation,
            'details': details or {}
        }
        self.vulnerabilities.append(vulnerability)
    
    def check_https(self):
        """Check if the website uses HTTPS"""
        if self._is_timeout_exceeded():
            return
            
        try:
            parsed = urlparse(self.url)
            if parsed.scheme == 'http':
                # Try to access HTTPS version
                https_url = self.url.replace('http://', 'https://', 1)
                try:
                    response = self._make_request(https_url)
                    if response.status_code < 400:
                        self._add_vulnerability(
                            vuln_type='HTTPS Not Enforced',
                            severity='warning',
                            description='Website is accessible via HTTP but HTTPS is available',
                            recommendation='Implement HTTPS redirect and enable HSTS header',
                            details={'http_url': self.url, 'https_url': https_url}
                        )
                    else:
                        self._add_vulnerability(
                            vuln_type='No HTTPS',
                            severity='critical',
                            description='Website does not support HTTPS encryption',
                            recommendation='Install SSL/TLS certificate and enable HTTPS',
                            details={'url': self.url}
                        )
                except:
                    self._add_vulnerability(
                        vuln_type='No HTTPS',
                        severity='critical',
                        description='Website does not support HTTPS encryption',
                        recommendation='Install SSL/TLS certificate and enable HTTPS',
                        details={'url': self.url}
                    )
        except Exception as e:
            print(f"Error checking HTTPS: {str(e)}")
    
    def check_security_headers(self):
        """Check for missing security headers"""
        if self._is_timeout_exceeded():
            return
            
        try:
            response = self._make_request(self.url)
            headers = response.headers
            
            # Define required security headers
            security_headers = {
                'Content-Security-Policy': {
                    'description': 'Content Security Policy header is missing',
                    'recommendation': 'Implement CSP header to prevent XSS and data injection attacks',
                    'severity': 'warning'
                },
                'X-Frame-Options': {
                    'description': 'X-Frame-Options header is missing',
                    'recommendation': 'Add X-Frame-Options header to prevent clickjacking attacks',
                    'severity': 'warning'
                },
                'X-Content-Type-Options': {
                    'description': 'X-Content-Type-Options header is missing',
                    'recommendation': 'Add X-Content-Type-Options: nosniff to prevent MIME-sniffing',
                    'severity': 'warning'
                },
                'Strict-Transport-Security': {
                    'description': 'HTTP Strict Transport Security (HSTS) header is missing',
                    'recommendation': 'Implement HSTS to force HTTPS connections',
                    'severity': 'warning'
                }
            }
            
            # Check each security header
            missing_headers = []
            for header, config in security_headers.items():
                if header not in headers:
                    missing_headers.append(header)
                    self._add_vulnerability(
                        vuln_type=f'Missing {header}',
                        severity=config['severity'],
                        description=config['description'],
                        recommendation=config['recommendation'],
                        details={'header': header}
                    )
            
        except Exception as e:
            print(f"Error checking security headers: {str(e)}")
    
    def check_sensitive_files(self):
        """Check for exposure of sensitive files"""
        if self._is_timeout_exceeded():
            return
            
        sensitive_paths = [
            '/.env',
            '/robots.txt',
            '/admin',
            '/.git/config',
            '/config.php'
        ]
        
        for path in sensitive_paths:
            if self._is_timeout_exceeded():
                break
                
            try:
                test_url = urljoin(self.url, path)
                response = self._make_request(test_url)
                
                # Check if file is accessible
                if response.status_code == 200:
                    severity = 'critical' if path in ['/.env', '/.git/config', '/config.php'] else 'warning'
                    
                    self._add_vulnerability(
                        vuln_type='Sensitive File Exposure',
                        severity=severity,
                        description=f'Sensitive file {path} is publicly accessible',
                        recommendation=f'Restrict access to {path} or remove it from the web root',
                        details={
                            'path': path,
                            'url': test_url,
                            'status_code': response.status_code,
                            'content_length': len(response.content)
                        }
                    )
            except Exception as e:
                # File not accessible or error occurred - this is actually good
                pass
    
    def check_directory_listing(self):
        """Check if directory listing is enabled"""
        if self._is_timeout_exceeded():
            return
            
        test_paths = ['/', '/images/', '/js/', '/css/', '/assets/']
        
        for path in test_paths:
            if self._is_timeout_exceeded():
                break
                
            try:
                test_url = urljoin(self.url, path)
                response = self._make_request(test_url)
                
                if response.status_code == 200:
                    # Check for common directory listing indicators
                    content = response.text.lower()
                    indicators = [
                        'index of /',
                        'directory listing',
                        'parent directory',
                        '<title>index of',
                        'apache.*server at'
                    ]
                    
                    for indicator in indicators:
                        if re.search(indicator, content, re.IGNORECASE):
                            self._add_vulnerability(
                                vuln_type='Directory Listing Enabled',
                                severity='warning',
                                description=f'Directory listing is enabled at {path}',
                                recommendation='Disable directory listing in web server configuration',
                                details={'path': path, 'url': test_url}
                            )
                            break
            except Exception as e:
                pass
    
    def check_xss_basic(self):
        """Perform basic XSS test on forms"""
        if self._is_timeout_exceeded():
            return
            
        try:
            response = self._make_request(self.url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all forms
            forms = soup.find_all('form')
            
            if not forms:
                return
            
            # Test the first form found
            form = forms[0]
            form_action = form.get('action', '')
            form_method = form.get('method', 'get').lower()
            
            # Build absolute URL for form action
            if form_action:
                form_url = urljoin(self.url, form_action)
            else:
                form_url = self.url
            
            # Find input fields
            inputs = form.find_all(['input', 'textarea'])
            
            if not inputs:
                return
            
            # Create test payload
            test_payload = "<script>alert('test')</script>"
            form_data = {}
            
            for input_field in inputs:
                field_name = input_field.get('name')
                field_type = input_field.get('type', 'text')
                
                if field_name and field_type not in ['submit', 'button', 'image', 'file']:
                    form_data[field_name] = test_payload
            
            if not form_data:
                return
            
            # Submit form with test payload
            try:
                if form_method == 'post':
                    test_response = self._make_request(form_url, method='POST', data=form_data)
                else:
                    test_response = self._make_request(form_url, method='GET', params=form_data)
                
                # Check if payload appears unescaped in response
                if test_payload in test_response.text:
                    self._add_vulnerability(
                        vuln_type='Potential XSS Vulnerability',
                        severity='critical',
                        description='Form may be vulnerable to Cross-Site Scripting (XSS)',
                        recommendation='Implement proper input validation and output encoding',
                        details={
                            'form_url': form_url,
                            'method': form_method,
                            'tested_fields': list(form_data.keys())
                        }
                    )
            except Exception as e:
                pass
                
        except Exception as e:
            print(f"Error checking XSS: {str(e)}")
    
    def scan(self) -> Dict[str, Any]:
        """Run all security checks and return results"""
        try:
            # Verify the URL is accessible
            response = self._make_request(self.url)
            
            # Run all checks
            self.check_https()
            self.check_security_headers()
            self.check_sensitive_files()
            self.check_directory_listing()
            self.check_xss_basic()
            
            # Generate summary
            critical_count = sum(1 for v in self.vulnerabilities if v['severity'] == 'critical')
            warning_count = sum(1 for v in self.vulnerabilities if v['severity'] == 'warning')
            
            return {
                'success': True,
                'url': self.url,
                'vulnerabilities': self.vulnerabilities,
                'summary': {
                    'total': len(self.vulnerabilities),
                    'critical': critical_count,
                    'warning': warning_count
                },
                'scan_time': round(time.time() - self.start_time, 2)
            }
            
        except requests.exceptions.Timeout:
            return {
                'success': False,
                'error': 'Request timeout - website took too long to respond',
                'vulnerabilities': [],
                'summary': {'total': 0, 'critical': 0, 'warning': 0}
            }
        except requests.exceptions.ConnectionError:
            return {
                'success': False,
                'error': 'Connection error - unable to reach the website',
                'vulnerabilities': [],
                'summary': {'total': 0, 'critical': 0, 'warning': 0}
            }
        except requests.exceptions.InvalidURL:
            return {
                'success': False,
                'error': 'Invalid URL format',
                'vulnerabilities': [],
                'summary': {'total': 0, 'critical': 0, 'warning': 0}
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Scan error: {str(e)}',
                'vulnerabilities': [],
                'summary': {'total': 0, 'critical': 0, 'warning': 0}
            }


def print_scan_results(results: Dict, use_rich: bool = True):
    """Print scan results in a user-friendly format"""
    if use_rich and RICH_AVAILABLE:
        console = Console()
        
        # Header
        console.print(Panel.fit(
            f"[bold blue]🔍 Vulnerability Scan Results[/bold blue]\n"
            f"[dim]Target: {results.get('url', 'Unknown')}[/dim]\n"
            f"[dim]Scanned at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]",
            title="Security Scanner"
        ))
        
        if not results.get('success', False):
            console.print(f"[red]❌ Scan failed: {results.get('error', 'Unknown error')}[/red]")
            return
        
        vulnerabilities = results.get('vulnerabilities', [])
        summary = results.get('summary', {})
        
        # Summary table
        summary_table = Table(title="📊 Scan Summary")
        summary_table.add_column("Total Vulnerabilities", style="cyan", justify="center")
        summary_table.add_column("Critical", style="red", justify="center")
        summary_table.add_column("Warning", style="yellow", justify="center")
        
        summary_table.add_row(
            str(summary.get('total', 0)),
            str(summary.get('critical', 0)),
            str(summary.get('warning', 0))
        )
        console.print(summary_table)
        
        if vulnerabilities:
            # Vulnerabilities table
            vuln_table = Table(title="🚨 Detected Vulnerabilities")
            vuln_table.add_column("Type", style="red")
            vuln_table.add_column("Severity", style="yellow")
            vuln_table.add_column("Description", style="white")
            vuln_table.add_column("Recommendation", style="green")
            
            for vuln in vulnerabilities:
                vuln_table.add_row(
                    vuln.get('type', 'Unknown'),
                    vuln.get('severity', 'Unknown'),
                    vuln.get('description', 'No description'),
                    vuln.get('recommendation', 'No recommendation')
                )
            console.print(vuln_table)
        else:
            console.print("[green]✅ No vulnerabilities detected![/green]")
            
    else:
        # Fallback to plain text
        print("🔍 Vulnerability Scan Results")
        print(f"Target: {results.get('url', 'Unknown')}")
        print(f"Scanned at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        if not results.get('success', False):
            print(f"❌ Scan failed: {results.get('error', 'Unknown error')}")
            return
        
        vulnerabilities = results.get('vulnerabilities', [])
        summary = results.get('summary', {})
        
        print("📊 Scan Summary:")
        print(f"  Total Vulnerabilities: {summary.get('total', 0)}")
        print(f"  Critical: {summary.get('critical', 0)}")
        print(f"  Warning: {summary.get('warning', 0)}")
        print()
        
        if vulnerabilities:
            print("🚨 Detected Vulnerabilities:")
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"{i}. [{vuln.get('severity', 'Unknown')}] {vuln.get('type', 'Unknown')}")
                print(f"   Description: {vuln.get('description', 'No description')}")
                print(f"   Recommendation: {vuln.get('recommendation', 'No recommendation')}")
                print()
        else:
            print("✅ No vulnerabilities detected!")


def main():
    """Command-line interface for the vulnerability scanner"""
    parser = argparse.ArgumentParser(
        description="🔍 Web Vulnerability Scanner - Scan websites for common security issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py https://example.com
  python scanner.py --json https://example.com
  python scanner.py --output results.json https://example.com
        """
    )
    
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--json', action='store_true', 
                       help='Output results in JSON format')
    parser.add_argument('--output', '-o', type=str,
                       help='Save results to file (JSON format)')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Suppress progress output')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url
    
    print("🚀 Starting vulnerability scan..." if not args.quiet else "", end='')
    
    # Perform scan
    scanner = VulnerabilityScanner(args.url)
    results = scanner.scan()
    
    if args.quiet:
        print(" Done!")
    
    # Output results
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_scan_results(results, use_rich=not args.quiet)
    
    # Save to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n💾 Results saved to {args.output}")
    
    # Exit with appropriate code
    if results.get('success', False):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()