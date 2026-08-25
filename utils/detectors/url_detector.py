"""
URL Detection Module
Analyzes URLs for phishing characteristics.
"""

import re


class URLDetector:
    """
    Detects suspicious URLs and domain characteristics.
    """
    
    def __init__(self):
        """Initialize URL detection patterns."""
        self.shortener_services = [
            'bit.ly', 'tinyurl', 'short.link', 'ow.ly', 
            'goo.gl', 'is.gd', 'buff.ly', 't.co', 'adf.ly'
        ]
        
        self.suspicious_keywords = [
            'verify', 'confirm', 'secure', 'update', 'login',
            'signin', 'account', 'password', 'reset', 'urgent'
        ]
    
    def extract_urls(self, text):
        """
        Extract all URLs from text.
        
        Args:
            text (str): Text to scan
        
        Returns:
            list: List of unique URLs found
        """
        url_pattern = r'https?://[^\s\n<>"\)\]]+|www\.[^\s\n<>"\)\]]+'
        urls = re.findall(url_pattern, text, re.IGNORECASE)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_urls = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        
        return unique_urls
    
    def is_url_shortened(self, url):
        """
        Check if URL uses a shortener service.
        
        Args:
            url (str): URL to check
        
        Returns:
            bool: True if URL is shortened
        """
        url_lower = url.lower()
        return any(service in url_lower for service in self.shortener_services)
    
    def is_ip_address(self, url):
        """
        Check if URL uses IP address instead of domain.
        
        Args:
            url (str): URL to check
        
        Returns:
            bool: True if URL contains IP address
        """
        ip_pattern = r'\d+\.\d+\.\d+\.\d+'
        return bool(re.search(ip_pattern, url))
    
    def has_suspicious_subdomain(self, url):
        """
        Check for suspicious subdomains.
        
        Args:
            url (str): URL to check
        
        Returns:
            bool: True if subdomain looks suspicious
        """
        url_lower = url.lower()
        
        for keyword in self.suspicious_keywords:
            if keyword in url_lower:
                return True
        
        return False
    
    def check_domain_typo(self, url, legitimate_domain='amazon.com'):
        """
        Check for common typosquatting patterns.
        
        Args:
            url (str): URL to check
            legitimate_domain (str): Domain to compare against
        
        Returns:
            bool: True if URL looks like a typo
        """
        url_lower = url.lower()
        
        # Look for common typosquatting tricks
        typo_patterns = [
            r'0',  # Zero instead of O
            r'l',  # lowercase L instead of I
            r'1',  # One instead of I or L
        ]
        
        # Check for extra characters (e.g., amaz0n instead of amazon)
        if '0' in url_lower and legitimate_domain.replace('o', '0') in url_lower:
            return True
        
        return False
    
    def analyze_urls(self, text):
        """
        Complete URL analysis.
        
        Args:
            text (str): Text to analyze
        
        Returns:
            dict: Dictionary with URL findings
        """
        urls = self.extract_urls(text)
        
        suspicious_urls = []
        for url in urls:
            reasons = []
            
            if self.is_url_shortened(url):
                reasons.append('Shortened URL (hides destination)')
            
            if self.is_ip_address(url):
                reasons.append('Uses IP address instead of domain')
            
            if self.has_suspicious_subdomain(url):
                reasons.append('Contains suspicious keywords')
            
            if reasons:
                suspicious_urls.append({
                    'url': url,
                    'reasons': reasons
                })
        
        return {
            'total_urls': len(urls),
            'all_urls': urls,
            'suspicious_urls': suspicious_urls,
            'suspicion_count': len(suspicious_urls)
        }
    
    def get_url_risk_score(self, url_analysis):
        """
        Calculate risk score from URL analysis.
        
        Args:
            url_analysis (dict): Result from analyze_urls()
        
        Returns:
            float: Risk score contribution (0-25)
        """
        score = 0
        
        # Each suspicious URL: +5 points (max 25)
        score += min(url_analysis['suspicion_count'] * 5, 25)
        
        return score

