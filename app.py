"""
Checkmate Vulnerability Scanner API
A web application security scanner that checks for common vulnerabilities
"""

from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import validators
import re
from scanner import VulnerabilityScanner
from io import BytesIO
import json
from datetime import datetime

import html

# Try to import reportlab for PDF generation
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib import colors
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    print("Warning: reportlab not installed. PDF generation will be unavailable.")
    print("Install with: pip install reportlab")

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Add security headers to all responses
@app.after_request
def set_security_headers(response):
    """Add security headers to prevent common web vulnerabilities"""
    # Content Security Policy - prevents XSS and data injection attacks
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'"
    
    # X-Frame-Options - prevents clickjacking attacks
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    
    # X-Content-Type-Options - prevents MIME-sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Strict-Transport-Security - forces HTTPS connections
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # X-XSS-Protection - additional XSS protection for older browsers
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Referrer-Policy - controls referrer information
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Permissions-Policy - controls browser features
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    return response

# Rate limiting: 10 scans per IP per hour
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["10 per hour"]
)

def sanitize_url(url: str) -> str:
    """Sanitize and validate URL input"""
    if not url:
        raise ValueError("URL cannot be empty")
    
    url = url.strip()
    
    # Remove any dangerous characters
    url = re.sub(r'[<>]', '', url)
    
    # Basic length check
    if len(url) > 2048:
        raise ValueError("URL is too long")
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Validate URL format
    if not validators.url(url):
        raise ValueError("Invalid URL format")
    
    return url

@app.route('/')
def index():
    """Serve the main web interface"""
    return render_template('index.html')

@app.route('/test')
def test():
    """Serve the test page"""
    return render_template('test.html')

@app.route('/scan', methods=['POST'])
@limiter.limit("10 per hour")
def scan():
    """API endpoint to scan a URL for vulnerabilities"""
    try:
        # Get and validate request data
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No JSON data provided. Please send a POST request with {"url": "example.com"}'
            }), 400
        
        url = data.get('url')
        
        if not url:
            return jsonify({
                'success': False,
                'error': 'URL parameter is required. Example: {"url": "example.com"}'
            }), 400
        
        # Sanitize and validate URL
        try:
            sanitized_url = sanitize_url(url)
        except ValueError as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 400
        
        # Perform scan
        scanner = VulnerabilityScanner(sanitized_url)
        results = scanner.scan()
        
        return jsonify(results), 200 if results['success'] else 400
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Server error: {str(e)}. Please try again later.'
        }), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'vulnerability-scanner',
        'version': '1.0.0'
    }), 200

@app.route('/api', methods=['GET'])
def api_info():
    """API information endpoint"""
    return jsonify({
        'service': 'Checkmate Vulnerability Scanner API',
        'version': '1.0.0',
        'rate_limit': '10 scans per IP per hour',
        'endpoints': {
            '/': {
                'method': 'GET',
                'description': 'Web interface'
            },
            '/scan': {
                'method': 'POST',
                'description': 'Scan a URL for security vulnerabilities',
                'body': {
                    'url': 'example.com'
                },
                'response': {
                    'success': True,
                    'url': 'http://example.com',
                    'vulnerabilities': [],
                    'summary': {'total': 0, 'critical': 0, 'warning': 0},
                    'scan_time': 2.34
                }
            },
            '/demo': {
                'method': 'GET',
                'description': 'Get demo scan results for example.com'
            },
            '/health': {
                'method': 'GET',
                'description': 'Health check endpoint'
            }
        }
    }), 200

@app.route('/demo', methods=['GET'])
def demo():
    """Demo endpoint with pre-computed results for example.com"""
    demo_results = {
        'success': True,
        'url': 'http://example.com',
        'vulnerabilities': [
            {
                'type': 'Missing Content-Security-Policy',
                'severity': 'warning',
                'description': 'Content Security Policy header is missing',
                'recommendation': 'Implement CSP header to prevent XSS and data injection attacks',
                'details': {'header': 'Content-Security-Policy'}
            },
            {
                'type': 'Missing X-Frame-Options',
                'severity': 'warning',
                'description': 'X-Frame-Options header is missing',
                'recommendation': 'Add X-Frame-Options header to prevent clickjacking attacks',
                'details': {'header': 'X-Frame-Options'}
            },
            {
                'type': 'Missing X-Content-Type-Options',
                'severity': 'warning',
                'description': 'X-Content-Type-Options header is missing',
                'recommendation': 'Add X-Content-Type-Options: nosniff to prevent MIME-sniffing',
                'details': {'header': 'X-Content-Type-Options'}
            },
            {
                'type': 'Missing Strict-Transport-Security',
                'severity': 'warning',
                'description': 'HTTP Strict Transport Security (HSTS) header is missing',
                'recommendation': 'Implement HSTS to force HTTPS connections',
                'details': {'header': 'Strict-Transport-Security'}
            },
            {
                'type': 'Directory Listing Enabled',
                'severity': 'warning',
                'description': 'Directory listing is enabled at /images/',
                'recommendation': 'Disable directory listing in web server configuration',
                'details': {'path': '/images/', 'url': 'http://example.com/images/'}
            }
        ],
        'summary': {
            'total': 5,
            'critical': 0,
            'warning': 5
        },
        'scan_time': 1.23,
        'note': 'This is demo data for demonstration purposes. Real scans may produce different results.'
    }

    return jsonify(demo_results), 200

@app.route('/generate-report', methods=['POST'])
def generate_report():
    """Generate PDF report from scan results"""
    try:
        if not PDF_AVAILABLE:
            return jsonify({
                'success': False,
                'error': 'PDF generation not available. Please install reportlab: pip install reportlab'
            }), 400
        
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No scan data provided'
            }), 400
        
        # Generate PDF
        pdf_buffer = generate_pdf_report(data)
        
        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"vulnerability-report-{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'PDF generation failed: {str(e)}'
        }), 500

def generate_pdf_report(scan_data):
    """Generate a PDF report from scan data"""
    buffer = BytesIO()
    
    try:
        # Create PDF document
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=30,
            alignment=1
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#34495e'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        # Title
        elements.append(Paragraph("Security Vulnerability Report", title_style))
        elements.append(Spacer(1, 0.3*inch))
        
        # Metadata
        url = scan_data.get('url', 'Unknown')
        scan_time = scan_data.get('scan_time', 'N/A')
        generated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        metadata_data = [
            ['Target URL:', url],
            ['Scan Time:', f"{scan_time} seconds"],
            ['Generated:', generated_at],
            ['Scanner:', 'Checkmate Vulnerability Scanner v1.0.0']
        ]
        
        metadata_table = Table(metadata_data, colWidths=[2*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(metadata_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Summary
        elements.append(Paragraph("Vulnerability Summary", heading_style))
        
        summary = scan_data.get('summary', {})
        summary_data = [
            ['Metric', 'Count'],
            ['Total Issues', str(summary.get('total', 0))],
            ['Critical', str(summary.get('critical', 0))],
            ['Warnings', str(summary.get('warning', 0))],
            ['Info', str(summary.get('info', 0))]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ecf0f1')),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(summary_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Vulnerabilities
        vulnerabilities = scan_data.get('vulnerabilities', [])
        if vulnerabilities:
            elements.append(Paragraph("Detailed Findings", heading_style))
            
            for idx, vuln in enumerate(vulnerabilities, 1):
                vuln_type = html.escape(vuln.get('type', 'Unknown'))
                severity = html.escape(vuln.get('severity', 'Unknown').upper())
                description = html.escape(vuln.get('description', 'N/A'))
                recommendation = html.escape(vuln.get('recommendation', 'N/A'))
                
                vuln_text = f"""
                <b>{idx}. {vuln_type}</b><br/>
                <b>Severity:</b> {severity}<br/>
                <b>Description:</b> {description}<br/>
                <b>Recommendation:</b> {recommendation}<br/>
                """
                
                elements.append(Paragraph(vuln_text, styles['Normal']))
                elements.append(Spacer(1, 0.2*inch))
        else:
            elements.append(Paragraph("No vulnerabilities found.", styles['Normal']))
        
        elements.append(Spacer(1, 0.3*inch))
        
        # Footer
        footer_text = "This report was automatically generated by Checkmate Vulnerability Scanner | nourkabbouri022@gmail.com"
        elements.append(Paragraph(footer_text, styles['Normal']))
        
        # Build PDF
        doc.build(elements)
        buffer.seek(0)
        return buffer
        
    except Exception as e:
        raise Exception(f"Error generating PDF: {str(e)}")

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)