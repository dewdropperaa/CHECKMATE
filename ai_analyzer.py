"""
FREE AI Integration for Vulnerability Scanner
Uses: Gemini (FREE) -> Groq (FREE) -> Templates (FREE)
Cost: $0/month for ~10,000 scans
"""

import json
import hashlib
import logging
from typing import Dict, List, Any, Optional
import google.generativeai as genai
from groq import Groq
import redis
from config import Config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Redis cache (optional - can work without it)
try:
    cache = redis.from_url(Config.REDIS_URL, decode_responses=True)
    CACHE_ENABLED = True
    logger.info("✅ Redis cache enabled")
except:
    CACHE_ENABLED = False
    logger.warning("⚠️ Redis not available - running without cache")

# Initialize AI clients
try:
    genai.configure(api_key=Config.GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel('gemini-2.0-flash-exp')
    GEMINI_ENABLED = True
    logger.info("✅ Gemini AI enabled")
except Exception as e:
    GEMINI_ENABLED = False
    logger.warning(f"⚠️ Gemini not configured: {e}")

try:
    groq_client = Groq(api_key=Config.GROQ_API_KEY)
    GROQ_ENABLED = True
    logger.info("✅ Groq AI enabled")
except Exception as e:
    GROQ_ENABLED = False
    logger.warning(f"⚠️ Groq not configured: {e}")


class AISecurityAnalyzer:
    """
    Smart AI analyzer with multiple fallback layers
    """
    
    # Pre-written templates for common vulnerabilities (FREE!)
    VULNERABILITY_TEMPLATES = {
        'missing_csp': {
            'severity_score': 8,
            'exploitation_difficulty': 'Easy',
            'business_impact': 'High - Allows XSS attacks that can steal user data, session tokens, or inject malicious scripts.',
            'remediation': [
                'Add Content-Security-Policy header to all responses',
                "Example: Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'",
                'Use nonce or hash-based CSP for inline scripts',
                'Monitor CSP violations using report-uri directive',
                'Test thoroughly as CSP can break existing functionality'
            ],
            'tools': ['CSP Evaluator (Google)', 'Report URI', 'Observatory by Mozilla'],
            'references': [
                'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
                'https://content-security-policy.com/'
            ]
        },
        
        'missing_x_frame_options': {
            'severity_score': 6,
            'exploitation_difficulty': 'Easy',
            'business_impact': 'Medium - Enables clickjacking attacks where attackers can trick users into clicking hidden elements.',
            'remediation': [
                'Add X-Frame-Options header with value DENY or SAMEORIGIN',
                'Example: X-Frame-Options: SAMEORIGIN',
                'Alternatively, use CSP frame-ancestors directive',
                'Test with your embedding requirements (if any)',
                'Consider using both X-Frame-Options and CSP for defense in depth'
            ],
            'tools': ['Burp Suite', 'OWASP ZAP'],
            'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options']
        },
        
        'no_https': {
            'severity_score': 9,
            'exploitation_difficulty': 'Easy',
            'business_impact': 'Critical - Data transmitted in plain text can be intercepted. Damages user trust and SEO rankings.',
            'remediation': [
                'Obtain SSL/TLS certificate (free from Let\'s Encrypt)',
                'Configure web server to redirect all HTTP to HTTPS',
                'Enable HSTS header: Strict-Transport-Security: max-age=31536000',
                'Update all internal links to use HTTPS',
                'Check for mixed content warnings',
                'Consider HSTS preloading for additional security'
            ],
            'tools': ['Let\'s Encrypt', 'Certbot', 'Cloudflare (free SSL)'],
            'references': [
                'https://letsencrypt.org/',
                'https://www.ssllabs.com/ssltest/'
            ]
        },
        
        'exposed_env_file': {
            'severity_score': 10,
            'exploitation_difficulty': 'Easy',
            'business_impact': 'Critical - Database credentials, API keys, and secrets exposed. Immediate breach risk.',
            'remediation': [
                'IMMEDIATELY move .env file outside web root',
                'Add .env to .gitignore (if not already)',
                'Rotate ALL exposed credentials immediately',
                'Configure web server to deny access to .env files',
                'Use environment variables or secure secret management',
                'Audit git history for committed secrets'
            ],
            'tools': ['git-secrets', 'TruffleHog', 'AWS Secrets Manager', 'HashiCorp Vault'],
            'references': ['https://12factor.net/config']
        },
        
        'directory_listing': {
            'severity_score': 5,
            'exploitation_difficulty': 'Easy',
            'business_impact': 'Medium - Exposes file structure and potentially sensitive files to attackers.',
            'remediation': [
                'Disable directory indexing in web server configuration',
                'Apache: Add "Options -Indexes" to .htaccess',
                'Nginx: Remove "autoindex on" from configuration',
                'Add index.html files to directories',
                'Review exposed files for sensitive information'
            ],
            'tools': ['DirBuster', 'Gobuster'],
            'references': ['https://httpd.apache.org/docs/current/mod/core.html#options']
        },
        
        'xss_vulnerability': {
            'severity_score': 8,
            'exploitation_difficulty': 'Medium',
            'business_impact': 'High - Attackers can execute malicious scripts, steal cookies, hijack sessions, or deface website.',
            'remediation': [
                'Implement proper input validation and output encoding',
                'Use security libraries: DOMPurify (JS), bleach (Python)',
                'Set Content-Security-Policy header',
                'Use HTTP-only and Secure flags on cookies',
                'Implement proper session management',
                'Regular security testing and code review'
            ],
            'tools': ['OWASP ZAP', 'Burp Suite', 'XSStrike'],
            'references': [
                'https://owasp.org/www-community/attacks/xss/',
                'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
            ]
        }
    }
    
    def __init__(self):
        self.gemini_available = GEMINI_ENABLED
        self.groq_available = GROQ_ENABLED
        self.cache_enabled = CACHE_ENABLED
        
    def _get_cache_key(self, data: str) -> str:
        """Generate cache key from vulnerability data"""
        return f"ai_analysis:{hashlib.md5(data.encode()).hexdigest()}"
    
    def _get_cached_analysis(self, cache_key: str) -> Optional[Dict]:
        """Get cached analysis if available"""
        if not self.cache_enabled:
            return None
            
        try:
            cached = cache.get(cache_key)
            if cached:
                logger.info(f"✅ Cache HIT for {cache_key[:20]}...")
                return json.loads(cached)
        except Exception as e:
            logger.warning(f"Cache read error: {e}")
        
        return None
    
    def _cache_analysis(self, cache_key: str, analysis: Dict):
        """Cache analysis result"""
        if not self.cache_enabled:
            return
            
        try:
            cache.setex(
                cache_key,
                Config.AI_CACHE_TTL,
                json.dumps(analysis)
            )
            logger.info(f"✅ Cached analysis for {cache_key[:20]}...")
        except Exception as e:
            logger.warning(f"Cache write error: {e}")
    
    def _analyze_with_gemini(self, vulnerability: Dict) -> Optional[Dict]:
        """Analyze vulnerability using Gemini (FREE tier: 1500 req/day)"""
        if not self.gemini_available:
            return None
            
        try:
            prompt = f"""
You are an expert penetration tester and security researcher. Analyze this web security vulnerability:

**Vulnerability Type**: {vulnerability.get('type', 'Unknown')}
**Description**: {vulnerability.get('description', 'No description')}
**Details**: {vulnerability.get('details', 'No additional details')}

Provide a comprehensive security analysis in JSON format:
{{
    "severity_score": <number 0-10>,
    "exploitation_difficulty": "<Easy|Medium|Hard>",
    "business_impact": "<brief explanation of business consequences>",
    "remediation": ["step 1", "step 2", "step 3"],
    "tools": ["recommended security tool 1", "tool 2"],
    "references": ["url1", "url2"]
}}

Be specific, actionable, and technical. Focus on practical remediation steps.
"""
            
            response = gemini_model.generate_content(prompt)
            
            # Extract JSON from response
            text = response.text.strip()
            if '```json' in text:
                text = text.split('```json')[1].split('```')[0].strip()
            elif '```' in text:
                text = text.split('```')[1].split('```')[0].strip()
            
            analysis = json.loads(text)
            logger.info(f"✅ Gemini analysis successful for {vulnerability.get('type')}")
            return analysis
            
        except Exception as e:
            logger.error(f"❌ Gemini analysis failed: {e}")
            return None
    
    def _analyze_with_groq(self, vulnerability: Dict) -> Optional[Dict]:
        """Analyze vulnerability using Groq (FREE tier: 14,400 req/day)"""
        if not self.groq_available:
            return None
            
        try:
            chat_completion = groq_client.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert penetration tester. Provide security analysis in JSON format only."
                    },
                    {
                        "role": "user",
                        "content": f"""
Analyze this vulnerability and respond ONLY with valid JSON:

Type: {vulnerability.get('type')}
Description: {vulnerability.get('description')}
Details: {vulnerability.get('details')}

Required JSON format:
{{
    "severity_score": <0-10>,
    "exploitation_difficulty": "<Easy|Medium|Hard>",
    "business_impact": "<explanation>",
    "remediation": ["step1", "step2"],
    "tools": ["tool1", "tool2"],
    "references": ["url1", "url2"]
}}
"""
                    }
                ],
                model="llama-3.1-70b-versatile",
                temperature=0.3,
                max_tokens=1000
            )
            
            content = chat_completion.choices[0].message.content.strip()
            
            # Clean JSON
            if '```json' in content:
                content = content.split('```json')[1].split('```')[0].strip()
            elif '```' in content:
                content = content.split('```')[1].split('```')[0].strip()
            
            analysis = json.loads(content)
            logger.info(f"✅ Groq analysis successful for {vulnerability.get('type')}")
            return analysis
            
        except Exception as e:
            logger.error(f"❌ Groq analysis failed: {e}")
            return None
    
    def _get_template_analysis(self, vuln_type: str) -> Optional[Dict]:
        """Get pre-written template analysis (always FREE!)"""
        template_key = vuln_type.lower().replace(' ', '_').replace('-', '_')
        
        if template_key in self.VULNERABILITY_TEMPLATES:
            logger.info(f"✅ Using template for {vuln_type}")
            return self.VULNERABILITY_TEMPLATES[template_key].copy()
        
        return None
    
    def analyze_vulnerability(self, vulnerability: Dict) -> Dict:
        """
        Multi-tier analysis with intelligent fallback
        
        Tier 1: Check cache (FREE, instant)
        Tier 2: Try templates (FREE, instant)
        Tier 3: Try Gemini (FREE, 1500/day)
        Tier 4: Try Groq (FREE, 14,400/day)
        Tier 5: Generic fallback (FREE)
        """
        
        vuln_type = vulnerability.get('type', 'unknown')
        cache_key = self._get_cache_key(json.dumps(vulnerability))
        
        # Tier 1: Check cache
        cached = self._get_cached_analysis(cache_key)
        if cached:
            return cached
        
        # Tier 2: Try template (for common vulnerabilities)
        template_analysis = self._get_template_analysis(vuln_type)
        if template_analysis:
            self._cache_analysis(cache_key, template_analysis)
            return template_analysis
        
        # Tier 3: Try Gemini AI
        gemini_analysis = self._analyze_with_gemini(vulnerability)
        if gemini_analysis:
            self._cache_analysis(cache_key, gemini_analysis)
            return gemini_analysis
        
        # Tier 4: Try Groq AI
        groq_analysis = self._analyze_with_groq(vulnerability)
        if groq_analysis:
            self._cache_analysis(cache_key, groq_analysis)
            return groq_analysis
        
        # Tier 5: Generic fallback
        logger.warning(f"⚠️ All AI methods failed, using generic analysis for {vuln_type}")
        generic_analysis = {
            'severity_score': 5,
            'exploitation_difficulty': 'Medium',
            'business_impact': 'This vulnerability could potentially be exploited by attackers. Review and remediate as soon as possible.',
            'remediation': [
                'Review the vulnerability details carefully',
                'Research best practices for this type of issue',
                'Implement proper security controls',
                'Test thoroughly after fixes',
                'Consider professional security audit'
            ],
            'tools': ['OWASP ZAP', 'Burp Suite', 'Nmap'],
            'references': [
                'https://owasp.org/',
                'https://cwe.mitre.org/'
            ]
        }
        
        self._cache_analysis(cache_key, generic_analysis)
        return generic_analysis
    
    def batch_analyze(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Analyze multiple vulnerabilities efficiently
        Uses batching to reduce API calls
        """
        
        enhanced_vulns = []
        
        for vuln in vulnerabilities:
            try:
                ai_analysis = self.analyze_vulnerability(vuln)
                
                # Merge AI analysis into vulnerability
                vuln['ai_analysis'] = ai_analysis
                vuln['severity_score'] = ai_analysis.get('severity_score', 5)
                vuln['exploitation_difficulty'] = ai_analysis.get('exploitation_difficulty', 'Medium')
                vuln['business_impact'] = ai_analysis.get('business_impact', 'Unknown impact')
                vuln['remediation_steps'] = ai_analysis.get('remediation', [])
                vuln['recommended_tools'] = ai_analysis.get('tools', [])
                vuln['references'] = ai_analysis.get('references', [])
                
                enhanced_vulns.append(vuln)
                
            except Exception as e:
                logger.error(f"Error analyzing vulnerability: {e}")
                # Add basic info even if analysis fails
                vuln['ai_analysis'] = {'error': str(e)}
                enhanced_vulns.append(vuln)
        
        return enhanced_vulns


# Global analyzer instance
analyzer = AISecurityAnalyzer()


def enhance_scan_results(scan_results: Dict) -> Dict:
    """
    Main function to enhance scan results with AI
    Called from Flask app
    """
    
    if not Config.USE_AI_ENHANCEMENT:
        logger.info("AI enhancement disabled in config")
        return scan_results
    
    vulnerabilities = scan_results.get('vulnerabilities', [])
    
    if not vulnerabilities:
        logger.info("No vulnerabilities to analyze")
        return scan_results
    
    logger.info(f"🤖 Analyzing {len(vulnerabilities)} vulnerabilities with AI...")
    
    # Enhance each vulnerability with AI analysis
    enhanced_vulns = analyzer.batch_analyze(vulnerabilities)
    
    scan_results['vulnerabilities'] = enhanced_vulns
    scan_results['ai_enhanced'] = True
    scan_results['total_severity_score'] = sum(
        v.get('severity_score', 0) for v in enhanced_vulns
    )
    
    logger.info(f"✅ AI analysis complete! Total severity: {scan_results['total_severity_score']}")
    
    return scan_results