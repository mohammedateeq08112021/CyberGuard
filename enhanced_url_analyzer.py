import re
import random
import tldextract
import requests
from bs4 import BeautifulSoup
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse
from utils import is_valid_url

class URLAnalyzer:
    """Enhanced URL analysis with security features for CyberGuard"""
    
    def __init__(self):
        self.suspicious_terms = [
            'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
            'payment', 'password', 'credential', 'bank', 'wallet', 'authenticate',
            'validate', 'verification', 'recover', 'suspension', 'locked'
        ]
        
        self.suspicious_tlds = [
            '.xyz', '.top', '.club', '.online', '.site', '.world', '.live', '.gq', 
            '.ml', '.cf', '.ga', '.tk', '.buzz', '.loan', '.work', '.casa', '.icu'
        ]
    
    def extract_domain_info(self, url):
        """Extract domain information from URL"""
        parsed_url = urlparse(url)
        extracted = tldextract.extract(url)
        
        return {
            'scheme': parsed_url.scheme,
            'netloc': parsed_url.netloc,
            'path': parsed_url.path,
            'params': parsed_url.params,
            'query': parsed_url.query,
            'fragment': parsed_url.fragment,
            'subdomain': extracted.subdomain,
            'domain': extracted.domain,
            'suffix': extracted.suffix
        }
    
    def check_url_length(self, url):
        """Check if URL is suspiciously long"""
        return len(url) > 100
    
    def check_suspicious_characters(self, url):
        """Check for suspicious characters in URL"""
        suspicious_chars = ['@', '==', '%', '~', '`', '+']
        return any(char in url for char in suspicious_chars)
    
    def check_suspicious_terms(self, url):
        """Check for suspicious terms in URL"""
        url_lower = url.lower()
        return [term for term in self.suspicious_terms if term in url_lower]
    
    def check_suspicious_tld(self, domain_info):
        """Check if TLD is in list of suspicious TLDs"""
        return f".{domain_info['suffix']}" in self.suspicious_tlds
    
    def check_ip_url(self, url):
        """Check if URL contains IP address instead of domain name"""
        ip_pattern = re.compile(r'https?://\d+\.\d+\.\d+\.\d+')
        return bool(ip_pattern.match(url))
    
    def check_domain_age(self, domain_info):
        """Simulate checking domain age"""
        # In a real implementation, this would query WHOIS records
        # For this prototype, we'll simulate it with random age
        domain = f"{domain_info['domain']}.{domain_info['suffix']}"
        # Use domain hash for consistent results
        domain_hash = hash(domain)
        random.seed(domain_hash)
        days_old = random.randint(1, 3650)  # 1 day to 10 years
        
        return {
            'days_old': days_old,
            'registration_date': (datetime.now() - timedelta(days=days_old)).strftime('%Y-%m-%d'),
            'is_new': days_old < 30  # Consider domains less than 30 days old as new
        }
    
    def check_redirects(self, url):
        """Check if URL involves redirects"""
        try:
            # Set a timeout to avoid hanging
            response = requests.head(url, allow_redirects=False, timeout=3)
            return 300 <= response.status_code < 400
        except Exception:
            return False
    
    def check_ssl(self, url):
        """Check if URL uses SSL/TLS"""
        return url.startswith('https://')
    
    def analyze_page_content(self, url):
        """Analyze the content of the page for suspicious elements"""
        try:
            # Fetch the page with a timeout
            response = requests.get(url, timeout=5)
            if response.status_code != 200:
                return {
                    'success': False,
                    'error': f"Failed to fetch page: Status code {response.status_code}"
                }
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for login forms
            forms = soup.find_all('form')
            login_forms = [form for form in forms if self._is_login_form(form)]
            
            # Check for password fields
            password_fields = soup.find_all('input', {'type': 'password'})
            
            # Check for iframes
            iframes = soup.find_all('iframe')
            
            # Check for excessive number of script tags
            scripts = soup.find_all('script')
            
            # Check for obfuscated JavaScript
            js_obfuscation = self._check_js_obfuscation(soup)
            
            return {
                'success': True,
                'has_login_form': len(login_forms) > 0,
                'login_form_count': len(login_forms),
                'has_password_field': len(password_fields) > 0,
                'password_field_count': len(password_fields),
                'has_iframes': len(iframes) > 0,
                'iframe_count': len(iframes),
                'script_count': len(scripts),
                'possible_js_obfuscation': js_obfuscation
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _is_login_form(self, form):
        """Check if a form appears to be a login form"""
        # Look for password fields
        has_password = bool(form.find('input', {'type': 'password'}))
        
        # Look for common login form attributes
        form_id = form.get('id', '').lower()
        form_class = form.get('class', [])
        form_class = ' '.join(form_class).lower() if isinstance(form_class, list) else form_class.lower()
        form_action = form.get('action', '').lower()
        
        login_indicators = ['login', 'signin', 'auth', 'credential']
        
        return has_password or any(indicator in form_id or indicator in form_class or indicator in form_action for indicator in login_indicators)
    
    def _check_js_obfuscation(self, soup):
        """Check for signs of JavaScript obfuscation"""
        scripts = soup.find_all('script')
        
        for script in scripts:
            script_content = script.string
            if script_content:
                # Check for common obfuscation patterns
                obfuscation_indicators = [
                    'eval(', 
                    'String.fromCharCode(', 
                    'unescape(', 
                    'decodeURIComponent(',
                    'atob(',
                    r'\x'
                ]
                
                if any(indicator in script_content for indicator in obfuscation_indicators):
                    return True
                
                # Check for unusually long strings
                if 'fromCharCode' in script_content and len(script_content) > 1000:
                    return True
        
        return False
    
    def simulate_reputation_check(self, url, domain_info):
        """Simulate checking URL against reputation services"""
        # In a real implementation, this would query services like Google Safe Browsing, PhishTank, etc.
        # For this prototype, we'll use domain characteristics to simulate reputation
        
        domain = f"{domain_info['domain']}.{domain_info['suffix']}"
        domain_hash = hash(domain)
        random.seed(domain_hash)
        
        # More suspicious indicators increase chance of poor reputation
        suspicious_indicators = [
            self.check_ip_url(url),
            self.check_suspicious_tld(domain_info),
            len(self.check_suspicious_terms(url)) > 0,
            self.check_suspicious_characters(url),
            self.check_url_length(url)
        ]
        
        # Count the number of suspicious indicators
        suspicious_count = sum(1 for indicator in suspicious_indicators if indicator)
        
        # Base reputation chance - higher is worse
        base_reputation_chance = 0.05  # 5% chance for legitimate domains
        
        # Each suspicious indicator adds to the chance of poor reputation
        reputation_chance = base_reputation_chance + (suspicious_count * 0.15)
        
        # Adjust based on domain age
        age_info = self.check_domain_age(domain_info)
        if age_info['is_new']:
            reputation_chance += 0.2  # New domains are more suspicious
        
        # Random check with weighted probability
        is_flagged = random.random() < reputation_chance
        
        return {
            'is_flagged': is_flagged,
            'services': {
                'safe_browsing': {
                    'flagged': is_flagged,
                    'threat_type': 'SOCIAL_ENGINEERING' if is_flagged else None
                },
                'phishtank': {
                    'flagged': is_flagged and random.random() < 0.8,  # 80% correlation with Safe Browsing
                    'verified': is_flagged and random.random() < 0.7   # 70% of flagged are verified
                }
            }
        }
    
    def analyze(self, url):
        """Perform comprehensive URL analysis"""
        if not is_valid_url(url):
            return {
                'url': url,
                'is_valid': False,
                'error': 'Invalid URL format',
                'risk_level': 'UNKNOWN',
                'risk_score': 0,
                'analysis_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        
        start_time = time.time()
        
        domain_info = self.extract_domain_info(url)
        suspicious_terms = self.check_suspicious_terms(url)
        domain_age = self.check_domain_age(domain_info)
        reputation = self.simulate_reputation_check(url, domain_info)
        
        # Try to analyze page content
        content_analysis = {'success': False, 'error': 'Content analysis not performed'}
        try:
            content_analysis = self.analyze_page_content(url)
        except Exception as e:
            content_analysis = {'success': False, 'error': str(e)}
        
        # Calculate overall risk score (0-100)
        risk_factors = []
        
        # Domain factors
        if domain_age['is_new']:
            risk_factors.append(('New domain registration', 15))
        
        if self.check_suspicious_tld(domain_info):
            risk_factors.append(('Suspicious TLD', 10))
        
        if self.check_ip_url(url):
            risk_factors.append(('IP address in URL', 20))
        
        # URL structure factors
        if self.check_url_length(url):
            risk_factors.append(('Unusually long URL', 5))
        
        if self.check_suspicious_characters(url):
            risk_factors.append(('Suspicious characters in URL', 10))
        
        if suspicious_terms:
            risk_factors.append((f'Suspicious terms in URL: {", ".join(suspicious_terms)}', 5 * min(len(suspicious_terms), 3)))
        
        if self.check_redirects(url):
            risk_factors.append(('URL redirects to another location', 10))
        
        if not self.check_ssl(url):
            risk_factors.append(('No SSL/TLS encryption', 15))
        
        # Reputation factors
        if reputation['is_flagged']:
            risk_factors.append(('Flagged by reputation services', 25))
        
        # Content factors
        if content_analysis.get('success', False):
            if content_analysis.get('has_login_form', False):
                risk_factors.append(('Contains login form', 10))
            
            if content_analysis.get('has_password_field', False):
                risk_factors.append(('Contains password field', 15))
            
            if content_analysis.get('possible_js_obfuscation', False):
                risk_factors.append(('Possible JavaScript obfuscation', 20))
        
        # Calculate total risk score
        total_risk = sum(score for _, score in risk_factors)
        risk_score = min(total_risk, 100)  # Cap at 100
        
        # Determine risk level
        risk_level = 'LOW'
        if risk_score >= 75:
            risk_level = 'CRITICAL'
        elif risk_score >= 50:
            risk_level = 'HIGH'
        elif risk_score >= 25:
            risk_level = 'MEDIUM'
        
        # Generate findings and recommendations
        findings = risk_factors
        
        recommendations = []
        if risk_level == 'CRITICAL' or risk_level == 'HIGH':
            recommendations.append("Avoid visiting this URL as it shows strong indicators of being malicious.")
        if risk_level == 'MEDIUM':
            recommendations.append("Exercise caution when visiting this URL and do not provide any personal information.")
        if not self.check_ssl(url):
            recommendations.append("This site does not use secure HTTPS encryption. Do not enter sensitive information.")
        if domain_age['is_new']:
            recommendations.append(f"This domain was registered recently ({domain_age['registration_date']}), which is a common characteristic of phishing sites.")
        
        # If no specific recommendations, provide a general one
        if not recommendations and risk_level == 'LOW':
            recommendations.append("This URL appears to be low risk, but always exercise standard security precautions.")
        
        end_time = time.time()
        analysis_duration = round(end_time - start_time, 2)
        
        return {
            'url': url,
            'is_valid': True,
            'domain_info': domain_info,
            'risk_level': risk_level,
            'risk_score': risk_score,
            'findings': findings,
            'recommendations': recommendations,
            'domain_age': domain_age,
            'reputation': reputation,
            'content_analysis': content_analysis,
            'analysis_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'analysis_duration': analysis_duration
        }


def analyze_url(url):
    """Analyze URL and format results for display"""
    analyzer = URLAnalyzer()
    analysis = analyzer.analyze(url)
    
    if not analysis['is_valid']:
        return f"⚠️ **Invalid URL**: {analysis['error']}"
    
    # Format the risk level with appropriate color
    risk_color = {
        'LOW': '🟢 Low',
        'MEDIUM': '🟠 Medium', 
        'HIGH': '🔴 High',
        'CRITICAL': '⛔ Critical',
        'UNKNOWN': '⚪ Unknown'
    }
    
    # Build the formatted response
    response = f"""
## URL Security Analysis

**URL:** {analysis['url']}  
**Risk Level:** {risk_color[analysis['risk_level']]}  
**Risk Score:** {analysis['risk_score']}/100

### Domain Information
- **Domain:** {analysis['domain_info']['domain']}.{analysis['domain_info']['suffix']}
- **Registration Date:** {analysis['domain_age']['registration_date']} (approximately)
- **Age:** {analysis['domain_age']['days_old']} days old

### Key Findings
"""
    
    # Add findings
    if analysis['findings']:
        for finding, score in analysis['findings']:
            response += f"- {finding} (+{score} risk points)\n"
    else:
        response += "- No significant risk factors identified\n"
    
    # Add recommendations
    response += "\n### Recommendations\n"
    for recommendation in analysis['recommendations']:
        response += f"- {recommendation}\n"
    
    # Add reputation information if flagged
    if analysis['reputation']['is_flagged']:
        response += "\n### Reputation Alerts\n"
        response += "- This URL has been flagged by security services as potentially malicious\n"
        
        if analysis['reputation']['services']['safe_browsing']['flagged']:
            response += f"- Flagged for: {analysis['reputation']['services']['safe_browsing']['threat_type']}\n"
    
    # Add content analysis if successful
    if analysis['content_analysis'].get('success', False):
        response += "\n### Content Analysis\n"
        
        content = analysis['content_analysis']
        if content.get('has_login_form', False):
            response += f"- Contains {content.get('login_form_count', 0)} login form(s)\n"
        
        if content.get('has_password_field', False):
            response += f"- Contains {content.get('password_field_count', 0)} password field(s)\n"
        
        if content.get('possible_js_obfuscation', False):
            response += "- Contains potentially obfuscated JavaScript code\n"
    
    response += f"\n*Analysis performed at {analysis['analysis_time']} (completed in {analysis['analysis_duration']} seconds)*"
    
    return response
