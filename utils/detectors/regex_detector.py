"""
Regex Pattern Detection Module
Identifies phishing indicators using regular expressions and pattern matching.
This is the rule-based detection system that works without AI.
"""

import re


class RegexDetector:
    """
    Detects phishing indicators using predefined regex patterns and rules.
    This provides the foundation for phishing detection.
    """
    
    def __init__(self):
        """Initialize regex patterns for phishing detection."""
        self.patterns = self._init_patterns()
    
    def _init_patterns(self):
        """
        Initialize all regex patterns for detection.
        
        Returns:
            dict: Dictionary of pattern categories and their regex patterns
        """
        return {
            'urgent_keywords': [
                r'\burge',  # Starts with 'urge'
                r'\bact\s*now',
                r'\bimmediately',
                r'\bwithin\s*\d+\s*hours?',
                r'\bwithin\s*\d+\s*days?',
                r'\bverify\s*(now|immediately)',
                r'\bconfirm\s*(now|immediately)',
                r'\bclick\s*here',
                r'\bclick\s*now',
                r'\byour\s*account\s*(will\s*)?be\s*(closed|suspended|locked)',
                r'\byour\s*account\s*has\s*been\s*(suspended|locked|compromised)',
                r'\blimited\s*time',
                r'\bdon\'?t\s*miss',
                r'\bfree\s*(money|cash|gift|prize)',
            ],
            'credential_requests': [
                r'\bpassword',
                r'\bconfirm\s*(password|details)',
                r'\blog\s*in',
                r'\bverify\s*(account|identity|credentials|details)',
                r'\bconfirm\s*(account|identity)',
                r'\b(otp|one.time.password)',
                r'\bsocial\s*security',
                r'\bcredit\s*card',
                r'\bbank\s*account',
                r'\bpincode',
                r'\bpins?',
                r'\b(atm|bank)\s*(pin|password)',
                r'\bsecret\s*(question|answer)',
            ],
            'suspicious_domains': [
                r'(0|o){2,}',  # Multiple 0s or Os (e.g., amazon => am@z0n)
                r'[\-_](service|support|security|verify|confirm)',
                r'(paypa1|amazo|gmai1)',  # Common typosquatting
                r'bit\.ly',  # URL shortener
                r'tinyurl',  # URL shortener
                r'short\.link',  # URL shortener
                r'\d+\.\d+\.\d+\.\d+',  # IP address instead of domain
            ],
            'suspicious_sender': [
                r'noreply',
                r'no-reply',
                r'no_reply',
                r'admin',
                r'support@',
                r'notification',
                r'donotreply',
                r'automated',
            ],
            'attachment_warnings': [
                r'\.exe',
                r'\.scr',
                r'\.bat',
                r'\.cmd',
                r'\.com',
                r'\.pif',
                r'\.vbs',
                r'\.zip',
                r'\.rar',
                r'\.dll',
                r'\.msi',
                r'\.pdf\.exe',  # Double extension
                r'\.doc\.exe',
                r'\.xls\.exe',
            ],
            'html_forms': [
                r'<form',
                r'<input[^>]*type=["\']?password',
                r'<input[^>]*type=["\']?text[^>]*name=["\']?(password|pin|otp)',
            ],
            'suspicious_grammar': [
                r'(thier|teh|recieve|occured|definately)',
                r'(alterate|occassion|addresss)',
                r'(becuase|adn|taht)',
            ],
        }
    
    def detect_indicators(self, email_content):
        """
        Scan email for suspicious indicators.
        
        Args:
            email_content (str): Email text to analyze
        
        Returns:
            dict: Dictionary with detected indicators and their matches
        """
        indicators = {}
        
        # Convert to lowercase for case-insensitive matching
        content_lower = email_content.lower()
        
        for category, patterns in self.patterns.items():
            indicators[category] = []
            
            for pattern in patterns:
                matches = re.findall(pattern, content_lower, re.IGNORECASE)
                if matches:
                    # Store the pattern that matched
                    indicators[category].append({
                        'pattern': pattern,
                        'matches': matches
                    })
        
        return indicators
    
    def get_suspicious_phrases(self, email_content):
        """
        Extract and categorize suspicious phrases from email.
        
        Args:
            email_content (str): Email text to analyze
        
        Returns:
            list: List of detected suspicious phrases
        """
        detected_phrases = []
        
        # Urgent language phrases
        urgent_phrases = ['urgent', 'act now', 'immediately', 'verify now', 
                         'confirm now', 'suspended', 'locked', 'closed',
                         'within 24 hours', 'within 48 hours', 'limited time',
                         'click here', 'click now', 'don\'t miss']
        
        for phrase in urgent_phrases:
            if phrase in email_content.lower():
                detected_phrases.append(f"Urgent language: '{phrase}'")
        
        return detected_phrases
    
    def check_url_reputation_flags(self, urls):
        """
        Check URLs for suspicious characteristics.
        
        Args:
            urls (list): List of URLs to check
        
        Returns:
            list: List of suspicious URLs with reasons
        """
        suspicious_urls = []
        
        for url in urls:
            reasons = []
            
            # Check for shortened URL services
            if any(x in url.lower() for x in ['bit.ly', 'tinyurl', 'short', 'shorten']):
                reasons.append('Shortened URL (hides real destination)')
            
            # Check for IP address instead of domain
            if re.search(r'\d+\.\d+\.\d+\.\d+', url):
                reasons.append('Uses IP address instead of domain')
            
            # Check for suspicious subdomains
            if 'verify' in url.lower() or 'confirm' in url.lower() or 'secure' in url.lower():
                if 'official-domain' not in url.lower():  # This is a simplified check
                    reasons.append('Contains verification/security keywords')
            
            # Check for mismatched domain
            if '-' in url and '.' in url:
                parts = url.split('/')
                if parts[0]:
                    reasons.append('Domain uses hyphens (potential typosquatting)')
            
            if reasons:
                suspicious_urls.append({
                    'url': url,
                    'reasons': reasons
                })
        
        return suspicious_urls
    
    def calculate_risk_score_from_indicators(self, indicators):
        """
        Calculate preliminary risk score based on detected indicators.
        This is a rule-based score before AI analysis.
        
        Args:
            indicators (dict): Dictionary of detected indicators
        
        Returns:
            float: Risk score between 0-100
        """
        score = 0
        indicator_count = 0
        
        # Weight different categories
        weights = {
            'urgent_keywords': 15,
            'credential_requests': 25,
            'suspicious_domains': 20,
            'suspicious_sender': 10,
            'attachment_warnings': 20,
            'html_forms': 20,
            'suspicious_grammar': 5,
        }
        
        for category, weight in weights.items():
            if indicators.get(category):
                indicator_count += len(indicators[category])
                # Add weight for each match in this category
                score += min(weight, weight * len(indicators[category]))
        
        # Cap score at 100
        score = min(score, 100)
        
        return score
    
    def get_indicator_summary(self, indicators):
        """
        Create a human-readable summary of detected indicators.
        
        Args:
            indicators (dict): Dictionary of detected indicators
        
        Returns:
            list: List of strings describing detected indicators
        """
        summary = []
        
        if indicators.get('urgent_keywords'):
            summary.append("🚨 Uses urgent/time-pressure language")
        
        if indicators.get('credential_requests'):
            summary.append("🔐 Requests sensitive information (password, OTP, etc.)")
        
        if indicators.get('suspicious_domains'):
            summary.append("🌐 Domain looks suspicious or misspelled")
        
        if indicators.get('suspicious_sender'):
            summary.append("📧 Sender email looks suspicious")
        
        if indicators.get('attachment_warnings'):
            summary.append("📎 Attachment with suspicious extension")
        
        if indicators.get('html_forms'):
            summary.append("📝 Contains embedded login/credential form")
        
        if indicators.get('suspicious_grammar'):
            summary.append("✏️ Contains grammatical errors")
        
        return summary
